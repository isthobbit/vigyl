package offline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// DefaultEcosystems are the OSV ecosystems synced when none are specified.
var DefaultEcosystems = []string{"Go", "npm", "PyPI", "Maven", "crates.io", "RubyGems", "Packagist", "NuGet"}

// DefaultSemgrepPacks are the Semgrep registry packs synced when none are
// specified. They are downloaded onto the user's machine at sync time and
// never shipped with jensec: the Semgrep Rules License does not allow
// redistributing them.
var DefaultSemgrepPacks = []string{"default", "secrets", "owasp-top-ten"}

// Sources that can be synced.
const (
	SourceTrivy   = "trivy"
	SourceOSV     = "osv"
	SourceSemgrep = "semgrep"
)

var (
	osvBaseURL     = "https://osv-vulnerabilities.storage.googleapis.com"
	semgrepBaseURL = "https://semgrep.dev/c/p"
	httpClient     = &http.Client{Timeout: 30 * time.Minute}
)

// SyncOptions selects what Sync downloads.
type SyncOptions struct {
	// Sources limits the sync to these sources; empty means all three.
	Sources []string
	// Ecosystems are the OSV ecosystems to download; empty means DefaultEcosystems.
	Ecosystems []string
	// SemgrepPacks are the registry packs to download; empty means DefaultSemgrepPacks.
	SemgrepPacks []string
	// JavaDB also downloads Trivy's Java index DB (several hundred MB),
	// needed to identify dependencies inside .jar files.
	JavaDB bool
}

// Manifest records what was synced and when.
type Manifest struct {
	Trivy   *SourceInfo `json:"trivy,omitempty"`
	OSV     *SourceInfo `json:"osv,omitempty"`
	Semgrep *SourceInfo `json:"semgrep,omitempty"`
}

// SourceInfo describes the last successful sync of one source.
type SourceInfo struct {
	SyncedAt time.Time `json:"synced_at"`
	Items    []string  `json:"items,omitempty"`
}

// ReadManifest loads manifest.json, returning an empty Manifest if absent.
func (p Paths) ReadManifest() (*Manifest, error) {
	data, err := os.ReadFile(p.Manifest())
	if errors.Is(err, os.ErrNotExist) {
		return &Manifest{}, nil
	}
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("could not parse %s: %w", p.Manifest(), err)
	}
	return &m, nil
}

func (p Paths) writeManifest(m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p.Manifest(), append(data, '\n'), 0o644)
}

// Sync downloads offline data for the selected sources, writing progress to
// log. A failure in one source does not stop the others; all failures are
// returned together. The manifest is updated for every source that succeeded.
func Sync(ctx context.Context, p Paths, opts SyncOptions, log io.Writer) error {
	if err := os.MkdirAll(p.Root, 0o755); err != nil {
		return fmt.Errorf("could not create %s: %w", p.Root, err)
	}
	m, err := p.ReadManifest()
	if err != nil {
		return err
	}

	want := func(src string) bool {
		if len(opts.Sources) == 0 {
			return true
		}
		for _, s := range opts.Sources {
			if s == src {
				return true
			}
		}
		return false
	}

	var errs []error
	if want(SourceTrivy) {
		if err := syncTrivy(ctx, p, opts.JavaDB, log); err != nil {
			errs = append(errs, fmt.Errorf("trivy: %w", err))
		} else {
			items := []string{"vulnerability-db"}
			if opts.JavaDB {
				items = append(items, "java-db")
			}
			m.Trivy = &SourceInfo{SyncedAt: time.Now().UTC(), Items: items}
		}
	}
	if want(SourceOSV) {
		ecos := opts.Ecosystems
		if len(ecos) == 0 {
			ecos = DefaultEcosystems
		}
		if done, err := syncOSV(ctx, p, ecos, log); err != nil {
			errs = append(errs, fmt.Errorf("osv: %w", err))
		} else {
			m.OSV = &SourceInfo{SyncedAt: time.Now().UTC(), Items: done}
		}
	}
	if want(SourceSemgrep) {
		packs := opts.SemgrepPacks
		if len(packs) == 0 {
			packs = DefaultSemgrepPacks
		}
		if done, err := syncSemgrep(ctx, p, packs, log); err != nil {
			errs = append(errs, fmt.Errorf("semgrep: %w", err))
		} else {
			m.Semgrep = &SourceInfo{SyncedAt: time.Now().UTC(), Items: done}
		}
	}

	if err := p.writeManifest(m); err != nil {
		errs = append(errs, fmt.Errorf("could not write manifest: %w", err))
	}
	return errors.Join(errs...)
}

// syncTrivy asks trivy itself to download its DB into the cache dir, so the
// on-disk format always matches the installed trivy version.
func syncTrivy(ctx context.Context, p Paths, javaDB bool, log io.Writer) error {
	trivyPath, err := exec.LookPath("trivy")
	if err != nil {
		return errors.New("trivy is not installed on this machine; install it here or sync on a machine that has it")
	}
	runs := [][]string{{"fs", "--download-db-only", "--cache-dir", p.TrivyCache(), "--quiet"}}
	if javaDB {
		runs = append(runs, []string{"fs", "--download-java-db-only", "--cache-dir", p.TrivyCache(), "--quiet"})
	}
	for _, args := range runs {
		fmt.Fprintf(log, "  trivy %s\n", strings.Join(args[:2], " "))
		cmd := exec.CommandContext(ctx, trivyPath, args...) //nolint // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%w\n%s", err, stderr.String())
		}
	}
	return p.TrivyReady()
}

// syncOSV downloads each ecosystem's all.zip from the public OSV bucket into
// the layout osv-scanner expects. It returns the ecosystems downloaded.
func syncOSV(ctx context.Context, p Paths, ecosystems []string, log io.Writer) ([]string, error) {
	var done []string
	var errs []error
	for _, eco := range ecosystems {
		if !safeName(eco) {
			errs = append(errs, fmt.Errorf("invalid ecosystem name %q", eco))
			continue
		}
		fmt.Fprintf(log, "  osv %s\n", eco)
		src := osvBaseURL + "/" + url.PathEscape(eco) + "/all.zip"
		if err := download(ctx, src, p.OSVEcosystemZip(eco), nil); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", eco, err))
			continue
		}
		done = append(done, eco)
	}
	if len(done) == 0 {
		errs = append(errs, errors.New("no ecosystem database could be downloaded"))
	}
	return done, errors.Join(errs...)
}

// syncSemgrep downloads registry packs as YAML rule files.
func syncSemgrep(ctx context.Context, p Paths, packs []string, log io.Writer) ([]string, error) {
	var done []string
	var errs []error
	for _, pack := range packs {
		pack = strings.TrimPrefix(pack, "p/")
		if !safeName(pack) {
			errs = append(errs, fmt.Errorf("invalid pack name %q", pack))
			continue
		}
		fmt.Fprintf(log, "  semgrep p/%s\n", pack)
		dest := filepath.Join(p.SemgrepRules(), pack+".yml")
		if err := download(ctx, semgrepBaseURL+"/"+url.PathEscape(pack), dest, isRuleFile); err != nil {
			errs = append(errs, fmt.Errorf("p/%s: %w", pack, err))
			continue
		}
		done = append(done, pack)
	}
	return done, errors.Join(errs...)
}

// ruleFileStart matches the opening of a Semgrep rules document. The registry
// serves YAML or, when the client accepts gzip (Go always does), JSON. JSON is
// valid YAML, so either is saved as .yml and semgrep loads it unchanged.
var ruleFileStart = regexp.MustCompile(`^(rules:|\{\s*"rules"\s*:)`)

// isRuleFile rejects responses that are not a Semgrep rules document, such as
// an HTML error page served with a 200 status.
func isRuleFile(head []byte) error {
	if !ruleFileStart.Match(bytes.TrimSpace(head)) {
		return errors.New("response is not a Semgrep rules file")
	}
	return nil
}

// download fetches src into dest via a temporary file, so an interrupted
// download never replaces good data. check, when set, inspects the first
// bytes of the body before it is accepted.
func download(ctx context.Context, src, dest string, check func(head []byte) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", src, resp.Status)
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	body := io.Reader(resp.Body)
	if check != nil {
		head := make([]byte, 512)
		n, _ := io.ReadFull(resp.Body, head)
		if err := check(head[:n]); err != nil {
			tmp.Close()
			return err
		}
		body = io.MultiReader(bytes.NewReader(head[:n]), resp.Body)
	}

	if _, err := io.Copy(tmp, body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dest)
}

// safeName accepts ecosystem and pack names that are safe to use as a single
// path element and URL segment.
func safeName(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	return !strings.ContainsAny(s, `/\:`)
}
