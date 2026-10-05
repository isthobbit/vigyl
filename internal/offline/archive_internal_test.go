package offline

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestImport_RejectsOversizedArchive checks the decompression-bomb cap: an
// archive whose entries add up to more than maxImportBytes is refused before
// the oversized entry is written.
func TestImport_RejectsOversizedArchive(t *testing.T) {
	old := maxImportBytes
	maxImportBytes = 1024
	t.Cleanup(func() { maxImportBytes = old })

	src := filepath.Join(t.TempDir(), "big.tar.gz")
	f, err := os.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, name := range []string{"osv/a.bin", "osv/b.bin"} {
		data := make([]byte, 800) // zeros compress to almost nothing
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		tw.Write(data)
	}
	tw.Close()
	gz.Close()
	f.Close()

	dst := Paths{Root: filepath.Join(t.TempDir(), "offline")}
	err = Import(dst, src, true)
	if err == nil || !strings.Contains(err.Error(), "refusing to import") {
		t.Fatalf("expected size-cap error, got %v", err)
	}
	if _, statErr := os.Stat(dst.Root); statErr == nil {
		if entries, _ := os.ReadDir(dst.Root); len(entries) > 0 {
			t.Errorf("a refused import must not change the offline directory: %v", entries)
		}
	}
}
