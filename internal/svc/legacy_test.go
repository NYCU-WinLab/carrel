package svc

import (
	"os"
	"path/filepath"
	"testing"
)

// A host upgraded from carrel-fnd keeps its live and built versions: their
// function.json manifests become service.json, links are not followed, and
// a manifest already under the new name wins.
func TestAdoptLegacyManifests(t *testing.T) {
	root := t.TempDir()
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "t1-demo", "function.json"), "live")
	write(filepath.Join(root, "t1-demo", "v", "v5", "function.json"), "v5")
	write(filepath.Join(root, "t1-demo", "v", "v4", "function.json"), "v4")
	write(filepath.Join(root, "t1-new", "service.json"), "new")
	write(filepath.Join(root, "t1-new", "function.json"), "stale")
	outside := t.TempDir()
	write(filepath.Join(outside, "function.json"), "outside")
	if err := os.Symlink(outside, filepath.Join(root, "t1-link")); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(root, ".jail", "function.json"), "jail")

	n, err := AdoptLegacyManifests(root)
	if err != nil || n != 3 {
		t.Fatalf("renamed %d, %v; want 3", n, err)
	}
	for path, want := range map[string]string{
		filepath.Join(root, "t1-demo", "service.json"):            "live",
		filepath.Join(root, "t1-demo", "v", "v5", "service.json"): "v5",
		filepath.Join(root, "t1-demo", "v", "v4", "service.json"): "v4",
		filepath.Join(root, "t1-new", "service.json"):             "new",
		filepath.Join(root, "t1-new", "function.json"):            "stale",
		filepath.Join(outside, "function.json"):                   "outside",
		filepath.Join(root, ".jail", "function.json"):             "jail",
	} {
		if got, err := os.ReadFile(path); err != nil || string(got) != want {
			t.Errorf("%s = %q, %v; want %q", path, got, err, want)
		}
	}
	if n, err := AdoptLegacyManifests(filepath.Join(root, "missing")); n != 0 || err != nil {
		t.Fatalf("a missing root: %d, %v", n, err)
	}
}
