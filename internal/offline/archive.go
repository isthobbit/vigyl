package offline

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// excludeFromExport lists paths (relative to the offline root, slash form)
// that are machine-local caches rather than offline data.
var excludeFromExport = []string{"trivy/fanal"}

// Export writes the offline directory to a .tar.gz at dest and a matching
// dest+".sha256" in `sha256sum` format, so the archive can be checked with
// either `jensec offline import` or `sha256sum -c`.
func Export(p Paths, dest string) (checksum string, err error) {
	if _, err := os.Stat(p.Root); err != nil {
		return "", fmt.Errorf("nothing to export: %w", err)
	}

	f, err := os.Create(dest)
	if err != nil {
		return "", err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(dest)
		}
	}()

	h := sha256.New()
	gz := gzip.NewWriter(io.MultiWriter(f, h))
	tw := tar.NewWriter(gz)

	walkErr := filepath.WalkDir(p.Root, func(full string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(p.Root, full)
		if err != nil || rel == "." {
			return err
		}
		rel = filepath.ToSlash(rel)
		for _, ex := range excludeFromExport {
			if rel == ex || strings.HasPrefix(rel, ex+"/") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		// Only regular files and directories belong in an offline bundle.
		if !d.IsDir() && !d.Type().IsRegular() {
			return nil
		}
		if strings.HasPrefix(path.Base(rel), ".download-") {
			return nil // half-finished download
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if d.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		src, err := os.Open(full)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(tw, src)
		return err
	})
	if walkErr != nil {
		return "", walkErr
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}

	checksum = hex.EncodeToString(h.Sum(nil))
	line := fmt.Sprintf("%s  %s\n", checksum, filepath.Base(dest))
	if err := os.WriteFile(dest+".sha256", []byte(line), 0o644); err != nil {
		return "", err
	}
	return checksum, nil
}

// ErrNoChecksum is returned by Import when src has no .sha256 file beside it.
var ErrNoChecksum = errors.New("no checksum file found")

// Import verifies src against src+".sha256" (unless skipVerify) and unpacks
// it into the offline directory, replacing the data it contains.
//
// The archive is treated as untrusted: absolute paths, ".." components,
// links and other special entries are rejected. It is first unpacked into a
// staging directory, so a bad archive leaves existing data untouched.
func Import(p Paths, src string, skipVerify bool) error {
	if !skipVerify {
		if err := verifyChecksum(src); err != nil {
			return err
		}
	}

	if err := os.MkdirAll(filepath.Dir(p.Root), 0o755); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(filepath.Dir(p.Root), ".offline-import-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)

	if err := extract(src, staging); err != nil {
		return err
	}

	if err := os.MkdirAll(p.Root, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(staging)
	if err != nil {
		return err
	}
	for _, e := range entries {
		target := filepath.Join(p.Root, e.Name())
		if err := os.RemoveAll(target); err != nil {
			return err
		}
		if err := os.Rename(filepath.Join(staging, e.Name()), target); err != nil {
			return err
		}
	}
	return nil
}

func verifyChecksum(src string) error {
	data, err := os.ReadFile(src + ".sha256")
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w at %s.sha256 — copy it alongside the archive, or pass --no-verify", ErrNoChecksum, src)
	}
	if err != nil {
		return err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return fmt.Errorf("empty checksum file %s.sha256", src)
	}
	want := strings.ToLower(fields[0])

	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("checksum mismatch for %s: archive is %s, .sha256 says %s — the file is corrupt or was modified", src, got, want)
	}
	return nil
}

func extract(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("not a gzip archive: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("corrupt archive: %w", err)
		}

		target, err := safeJoin(dest, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil { //nolint:gosec // size bounded by the verified archive
				out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("archive entry %q has unsupported type %q; only files and directories are allowed", hdr.Name, string(hdr.Typeflag))
		}
	}
}

// safeJoin resolves an archive entry name inside dest, rejecting anything
// that would escape it.
func safeJoin(dest, name string) (string, error) {
	clean := path.Clean(strings.ReplaceAll(name, `\`, "/"))
	if path.IsAbs(clean) || filepath.IsAbs(name) || clean == ".." || strings.HasPrefix(clean, "../") || filepath.VolumeName(name) != "" {
		return "", fmt.Errorf("archive entry %q points outside the offline directory", name)
	}
	return filepath.Join(dest, filepath.FromSlash(clean)), nil
}
