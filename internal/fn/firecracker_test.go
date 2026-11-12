//go:build linux

package fn

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// jailWith builds what a build leaves behind: a jail root with /fn, both
// owned by the user the instance ran as. Here that user is the test's own.
func jailWith(t *testing.T) (*Firecracker, *vm, string, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(filepath.Join(root, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(base, "out")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	fc := &Firecracker{cfg: Config{GID: os.Getgid()}}
	return fc, &vm{fc: fc, root: root, slot: &slot{name: "test", uid: os.Getuid()}}, root, out
}

// A compromised Firecracker owns its jail during a build. Whatever it puts
// in place of the snapshot, the root daemon must not follow it.
func TestCollectRefusesWhatTheJailedUserCanPlant(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "host-secret")
	if err := os.WriteFile(secret, []byte("another tenant's memory"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(t *testing.T, root string){
		"the file is a symbolic link to a host file": func(t *testing.T, root string) {
			if err := os.Symlink(secret, filepath.Join(root, "out", "snap.mem")); err != nil {
				t.Fatal(err)
			}
		},
		"/out is a symbolic link to another directory": func(t *testing.T, root string) {
			other := filepath.Dir(secret)
			if err := os.Rename(secret, filepath.Join(other, "snap.mem")); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Rename(filepath.Join(other, "snap.mem"), secret) })
			if err := os.Remove(filepath.Join(root, "out")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, filepath.Join(root, "out")); err != nil {
				t.Fatal(err)
			}
		},
		"the file is a hard link to a host file": func(t *testing.T, root string) {
			if err := os.Link(secret, filepath.Join(root, "out", "snap.mem")); err != nil {
				t.Skip("hard link not possible here:", err)
			}
		},
		"the file is a FIFO": func(t *testing.T, root string) {
			if err := syscall.Mkfifo(filepath.Join(root, "out", "snap.mem"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"the file is a directory": func(t *testing.T, root string) {
			if err := os.Mkdir(filepath.Join(root, "out", "snap.mem"), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"the file is larger than the function's memory": func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "out", "snap.mem"), make([]byte, 4096), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"the file is missing": func(*testing.T, string) {},
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			fc, v, root, out := jailWith(t)
			plant(t, root)
			target := filepath.Join(out, "snap.mem")
			if err := fc.collect(v, "snap.mem", target, 1024); err == nil {
				t.Fatal("collect accepted it")
			}
			if _, err := os.Lstat(target); err == nil {
				t.Fatal("collect left a file behind")
			}
			if info, err := os.Stat(secret); err == nil && info.Mode().Perm() != 0o600 {
				t.Fatalf("the host file's mode changed to %o", info.Mode().Perm())
			}
		})
	}
}

func TestCollectRefusesAFileOfAnotherUser(t *testing.T) {
	fc, v, root, out := jailWith(t)
	if err := os.WriteFile(filepath.Join(root, "out", "snap.mem"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	v.slot.uid++ // the instance ran as someone else
	if err := fc.collect(v, "snap.mem", filepath.Join(out, "snap.mem"), 1024); err == nil {
		t.Fatal("collect accepted a file the instance's user does not own")
	}
}

func TestCollectCopiesARegularFile(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the copy is given to root, which needs root")
	}
	fc, v, root, out := jailWith(t)
	if err := os.WriteFile(filepath.Join(root, "out", "snap.mem"), []byte("memory"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(out, "snap.mem")
	if err := fc.collect(v, "snap.mem", target, 1024); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(target)
	if err != nil || string(content) != "memory" {
		t.Fatalf("content %q, %v", content, err)
	}
	if info, _ := os.Stat(target); info.Mode().Perm() != 0o440 {
		t.Fatalf("mode %o, want 440", info.Mode().Perm())
	}
}

// A function's serial log keeps its newest output and never grows past two halves.
func TestCapLogKeepsTheEndAndStaysSmall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	fc := &Firecracker{}
	line := bytes.Repeat([]byte("x"), 1<<20)
	for range 23 {
		if _, err := fc.logFor(path).Write(line); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fc.logFor(path).Write([]byte("last")); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, name := range []string{path, path + ".1"} {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
	}
	if total > 2*logHalf {
		t.Fatalf("the log holds %d bytes, more than %d", total, 2*logHalf)
	}
	content, _ := os.ReadFile(path)
	if !bytes.HasSuffix(content, []byte("last")) {
		t.Fatal("the newest output is not at the end of the log")
	}
	// One write larger than the limit keeps only its end.
	big := append(bytes.Repeat([]byte("y"), 2*logHalf), []byte("tail")...)
	if _, err := fc.logFor(path).Write(big); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Size() > logHalf {
		t.Fatalf("one large write made the log %d bytes", info.Size())
	}
}

// After lock the jailed user can create nothing in its jail but /out.
func TestLockGivesEveryDirectoryButOutToRoot(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("giving directories to root needs root")
	}
	root := t.TempDir()
	for _, dir := range []string{"dev/net", "run", "in", "out"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o777); err != nil {
			t.Fatal(err)
		}
	}
	const user = 300099
	for _, dir := range []string{"", "dev", "dev/net", "run", "in", "out"} {
		os.Chown(filepath.Join(root, dir), user, user)
	}
	if err := os.Symlink("/etc", filepath.Join(root, "run", "etc")); err != nil {
		t.Fatal(err)
	}
	if err := lock(root); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"", "dev", "dev/net", "run", "in"} {
		info, _ := os.Stat(filepath.Join(root, dir))
		stat := info.Sys().(*syscall.Stat_t)
		if stat.Uid != 0 || info.Mode().Perm() != 0o750 {
			t.Errorf("%s/ is owned by %d with mode %o after lock", dir, stat.Uid, info.Mode().Perm())
		}
	}
	if info, _ := os.Stat(filepath.Join(root, "out")); info.Sys().(*syscall.Stat_t).Uid != user {
		t.Error("lock took /out from the build")
	}
	if info, _ := os.Stat("/etc"); info.Sys().(*syscall.Stat_t).Uid != 0 || info.Mode().Perm() != 0o755 {
		t.Error("lock followed a symbolic link out of the jail")
	}
}
