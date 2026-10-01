package offline_test

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/isthobbit/vigyl/internal/offline"
)

func populated(t *testing.T) offline.Paths {
	t.Helper()
	p := offline.Paths{Root: filepath.Join(t.TempDir(), "offline")}
	touch(t, filepath.Join(p.TrivyCache(), "db", "trivy.db"))
	touch(t, filepath.Join(p.TrivyCache(), "fanal", "fanal.db")) // local cache, not exported
	touch(t, p.OSVEcosystemZip("npm"))
	touch(t, filepath.Join(p.SemgrepRules(), "default.yml"))
	return p
}

func TestExportImport_RoundTrip(t *testing.T) {
	src := populated(t)
	archive := filepath.Join(t.TempDir(), "bundle.tar.gz")

	sum, err := offline.Export(src, archive)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	line, err := os.ReadFile(archive + ".sha256")
	if err != nil || !strings.HasPrefix(string(line), sum+"  bundle.tar.gz") {
		t.Fatalf("checksum file not in sha256sum format: %q (%v)", line, err)
	}

	dst := offline.Paths{Root: filepath.Join(t.TempDir(), "offline")}
	if err := offline.Import(dst, archive, false); err != nil {
		t.Fatalf("import: %v", err)
	}
	for _, check := range []func() error{dst.TrivyReady, dst.OSVReady, dst.SemgrepReady} {
		if err := check(); err != nil {
			t.Error(err)
		}
	}
	if _, err := os.Stat(filepath.Join(dst.TrivyCache(), "fanal")); !os.IsNotExist(err) {
		t.Errorf("trivy fanal cache should not be exported")
	}
}

func TestImport_RejectsTamperedArchive(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if _, err := offline.Export(populated(t), archive); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(archive, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("tampered"))
	f.Close()

	dst := offline.Paths{Root: filepath.Join(t.TempDir(), "offline")}
	err = offline.Import(dst, archive, false)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch, got %v", err)
	}
}

func TestImport_RequiresChecksumUnlessSkipped(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if _, err := offline.Export(populated(t), archive); err != nil {
		t.Fatal(err)
	}
	os.Remove(archive + ".sha256")

	dst := offline.Paths{Root: filepath.Join(t.TempDir(), "offline")}
	if err := offline.Import(dst, archive, false); !errors.Is(err, offline.ErrNoChecksum) {
		t.Fatalf("expected ErrNoChecksum, got %v", err)
	}
	if err := offline.Import(dst, archive, true); err != nil {
		t.Fatalf("--no-verify import: %v", err)
	}
}

// writeTar builds a .tar.gz with the given entries and no checksum file.
func writeTar(t *testing.T, entries ...*tar.Header) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "evil.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, h := range entries {
		if h.Typeflag == tar.TypeReg {
			h.Size = 1
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write([]byte("x"))
		}
	}
	tw.Close()
	gz.Close()
	f.Close()
	return path
}

func TestImport_RejectsEntriesEscapingTheDirectory(t *testing.T) {
	cases := map[string]*tar.Header{
		"parent traversal": {Name: "../escaped.txt", Typeflag: tar.TypeReg, Mode: 0o644},
		"nested traversal": {Name: "osv/../../escaped.txt", Typeflag: tar.TypeReg, Mode: 0o644},
		"absolute path":    {Name: "/tmp/escaped.txt", Typeflag: tar.TypeReg, Mode: 0o644},
		"symlink":          {Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
	}
	for name, hdr := range cases {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			dst := offline.Paths{Root: filepath.Join(base, "offline")}
			err := offline.Import(dst, writeTar(t, hdr), true)
			if err == nil {
				t.Fatal("expected import to fail")
			}
			if _, statErr := os.Stat(filepath.Join(base, "escaped.txt")); statErr == nil {
				t.Fatal("file was written outside the offline directory")
			}
		})
	}
}

func TestImport_FailureLeavesExistingDataIntact(t *testing.T) {
	dst := populated(t)
	bad := writeTar(t,
		&tar.Header{Name: "semgrep-rules/new.yml", Typeflag: tar.TypeReg, Mode: 0o644},
		&tar.Header{Name: "../escaped.txt", Typeflag: tar.TypeReg, Mode: 0o644},
	)
	if err := offline.Import(dst, bad, true); err == nil {
		t.Fatal("expected import to fail")
	}
	if got := dst.SemgrepPacks(); len(got) != 1 || got[0] != "default" {
		t.Errorf("existing rules changed by a failed import: %v", got)
	}
}
