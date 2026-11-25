package fn

import (
	"os"
	"path/filepath"
	"testing"
)

// syncTree flushes regular files and directories and passes over links, as
// a version directory holds them (#247).
func TestSyncTreeFlushesAVersionDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "snap"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "snap", "mem"), []byte("m"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/nonexistent", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := syncTree(dir); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(dir, "function.json"), []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "function.json")); string(got) != "{}\n" {
		t.Fatal(string(got))
	}
}
