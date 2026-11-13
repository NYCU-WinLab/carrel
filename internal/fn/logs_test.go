package fn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStampMarksEachLine(t *testing.T) {
	at := time.Date(2026, 11, 13, 1, 2, 3, 4e6, time.UTC)
	atStart := true
	got := string(stamp([]byte("a\nb"), at, &atStart)) + string(stamp([]byte("c\n\nd\n"), at, &atStart))
	want := "2026-11-13T01:02:03.004Z a\n2026-11-13T01:02:03.004Z bc\n2026-11-13T01:02:03.004Z \n2026-11-13T01:02:03.004Z d\n"
	if got != want || !atStart {
		t.Fatalf("got %q", got)
	}
}

func TestReadLogTailSinceAndLinks(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "t1-hook")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := "2026-11-13T01:00:00.000Z old\nno stamp\n"
	recent := "2026-11-13T02:00:00.000Z new\ncontinued\n2026-11-13T02:00:01.000Z last\n"
	os.WriteFile(filepath.Join(dir, "log.1"), []byte(old), 0o600)
	os.WriteFile(filepath.Join(dir, "log"), []byte(recent), 0o600)

	a, err := ReadLog(root, LogRequest{ID: "1", Function: "t1-hook"})
	if err != nil || a.Text != old+recent || a.Truncated {
		t.Fatalf("all: %v %+v", err, a)
	}
	since := time.Date(2026, 11, 13, 1, 30, 0, 0, time.UTC).Unix()
	if a, _ := ReadLog(root, LogRequest{Function: "t1-hook", Since: since}); a.Text != recent {
		t.Fatalf("since: %q", a.Text)
	}
	if a, _ := ReadLog(root, LogRequest{Function: "t1-hook", MaxBytes: 40}); !a.Truncated || a.Text != "2026-11-13T02:00:01.000Z last\n" {
		t.Fatalf("tail: %+v", a)
	}
	// A link never leads out of the function's directory.
	secret := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secret, []byte("secret\n"), 0o600)
	os.Symlink(secret, filepath.Join(dir, "build.log"))
	if a, err := ReadLog(root, LogRequest{Function: "t1-hook", Build: true}); err == nil || strings.Contains(a.Text, "secret") {
		t.Fatalf("followed a link: %v %+v", err, a)
	}
	if _, err := ReadLog(root, LogRequest{Function: "../etc"}); err == nil {
		t.Fatal("read outside the root")
	}
	// No log yet is empty, not an error.
	if a, err := ReadLog(root, LogRequest{Function: "t1-none"}); err != nil || a.Text != "" {
		t.Fatalf("missing: %v %+v", err, a)
	}
}
