package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type entry struct {
	name, link, body string
	kind             byte
}

func archive(t *testing.T, entries ...entry) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Linkname: e.link, Typeflag: e.kind, Mode: 0644, Size: int64(len(e.body))}
		if e.kind == tar.TypeDir {
			h.Mode = 0755
		}
		if e.kind != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.kind == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	gz.Close()
	return bytes.NewReader(buf.Bytes())
}

func TestExtractWritesFilesAndInsideLinks(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "release")
	err := extract(archive(t,
		entry{name: "app/", kind: tar.TypeDir},
		entry{name: "app/server.js", body: "ok", kind: tar.TypeReg},
		entry{name: "bin", link: "app", kind: tar.TypeSymlink},
	), dir, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "bin", "server.js")); string(b) != "ok" {
		t.Fatalf("got %q", b)
	}
}

func TestExtractRejectsEscapes(t *testing.T) {
	for name, entries := range map[string][]entry{
		"dotdot":        {{name: "../evil", body: "x", kind: tar.TypeReg}},
		"absolute link": {{name: "l", link: "/etc", kind: tar.TypeSymlink}},
		"outside link":  {{name: "l", link: "../..", kind: tar.TypeSymlink}},
		"chained links": {{name: "d/", kind: tar.TypeDir}, {name: "d/up", link: "..", kind: tar.TypeSymlink}, {name: "evil", link: "d/up/d/up/../../../evil", kind: tar.TypeSymlink}, {name: "evil", body: "x", kind: tar.TypeReg}},
		// Issue #33: a link that leaves through another link, even when
		// nothing writes through it, in either order.
		"link through a link":  {{name: "d/", kind: tar.TypeDir}, {name: "d/up", link: "..", kind: tar.TypeSymlink}, {name: "x", link: "d/up/d/up/../..", kind: tar.TypeSymlink}},
		"link loop":            {{name: "a", link: "b", kind: tar.TypeSymlink}, {name: "b", link: "a", kind: tar.TypeSymlink}},
		"entry through a link": {{name: "d", link: ".", kind: tar.TypeSymlink}, {name: "d/f", body: "x", kind: tar.TypeReg}},
		"hard link":            {{name: "a", body: "x", kind: tar.TypeReg}, {name: "b", link: "a", kind: tar.TypeLink}},
		// The outer link first, the link it goes through after (review of #134).
		"link order": {{name: "d/", kind: tar.TypeDir}, {name: "evil", link: "d/up/d/up/../../../secret", kind: tar.TypeSymlink}, {name: "d/up", link: "..", kind: tar.TypeSymlink}},
	} {
		base := t.TempDir()
		if err := extract(archive(t, entries...), filepath.Join(base, "release"), os.Getuid(), os.Getgid()); err == nil {
			t.Fatalf("%s: accepted", name)
		}
		for _, outside := range []string{filepath.Join(base, "evil"), filepath.Join(filepath.Dir(base), "evil")} {
			if _, err := os.Stat(outside); err == nil {
				t.Fatalf("%s: wrote %s", name, outside)
			}
		}
	}
}

func TestExtractRefusesExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := extract(archive(t, entry{name: "a", body: "x", kind: tar.TypeReg}), dir, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("extracted into an existing directory")
	}
}

func TestSwapReplacesLinkAtomically(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "current")
	for _, target := range []string{"a", "b"} {
		if err := swap(link, filepath.Join(dir, target)); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := os.Readlink(link); got != filepath.Join(dir, "b") {
		t.Fatalf("link points at %s", got)
	}
}

// Issue #33: the app user owns <root> and releases; root must not follow
// a link they plant there, nor reuse a release it did not unpack.
func TestFetchPinsTheReleasesDirectoryAndReusesOnlyItsOwnUnpacks(t *testing.T) {
	body := archive(t, entry{name: "index.js", body: "v1", kind: tar.TypeReg})
	raw, _ := io.ReadAll(body)
	sum := sha256.Sum256(raw)
	downloads := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloads++
		w.Write(raw)
	}))
	defer srv.Close()
	base := t.TempDir()
	a := &agent{cfg: config{Origin: srv.URL, Token: "t"}, root: filepath.Join(base, "app"), state: filepath.Join(base, "state"), http: srv.Client(), uid: os.Getuid(), gid: os.Getgid()}
	r := release{ID: "r1", SHA256: hex.EncodeToString(sum[:])}
	ctx := context.Background()

	// releases is a link to somewhere else: refused.
	os.MkdirAll(a.root, 0755)
	os.MkdirAll(filepath.Join(base, "elsewhere"), 0755)
	os.Symlink(filepath.Join(base, "elsewhere"), filepath.Join(a.root, "releases"))
	if err := a.fetch(ctx, r); err == nil {
		t.Fatal("followed a planted releases link")
	}
	if entries, _ := os.ReadDir(filepath.Join(base, "elsewhere")); len(entries) != 0 {
		t.Fatal("wrote through the link", entries)
	}
	os.Remove(filepath.Join(a.root, "releases"))
	os.Mkdir(filepath.Join(a.root, "releases"), 0755)

	// A directory the app user made under the release's name is replaced.
	os.MkdirAll(filepath.Join(a.root, "releases", "r1"), 0755)
	os.WriteFile(filepath.Join(a.root, "releases", "r1", "index.js"), []byte("planted"), 0644)
	if err := a.fetch(ctx, r); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(a.root, "releases", "r1", "index.js")); string(b) != "v1" || downloads != 1 {
		t.Fatalf("got %q after %d downloads", b, downloads)
	}
	// Its own finished unpack is reused without a download.
	if err := a.fetch(ctx, r); err != nil || downloads != 1 {
		t.Fatal("did not reuse its own release", err, downloads)
	}
}

// A release unpacked by an older agent has no marker; redeploying the live
// one keeps it, even when the download would fail.
func TestRedeployKeepsTheLiveReleaseOfAnOlderAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502) }))
	defer srv.Close()
	base := t.TempDir()
	a := &agent{cfg: config{Origin: srv.URL, Token: "t"}, root: filepath.Join(base, "app"), state: filepath.Join(base, "state"), http: srv.Client(), uid: os.Getuid(), gid: os.Getgid()}
	live := filepath.Join(a.root, "releases", "r1")
	os.MkdirAll(live, 0755)
	os.WriteFile(filepath.Join(live, "index.js"), []byte("live"), 0644)
	os.Symlink(live, filepath.Join(a.root, "current"))
	if err := a.fetch(context.Background(), release{ID: "r1", SHA256: "x"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(live, "index.js")); string(b) != "live" {
		t.Fatal("the live release was removed")
	}
	if _, err := os.Stat(filepath.Join(a.state, "r1")); err != nil {
		t.Fatal("the live release was not marked", err)
	}
}

// pnpm's layout: links through links that stay inside the release deploy.
func TestExtractAcceptsLinksThroughLinksInside(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "release")
	err := extract(archive(t,
		entry{name: ".pnpm/ts@5/nm/ts/bin/", kind: tar.TypeDir},
		entry{name: ".pnpm/ts@5/nm/ts/bin/tsc", body: "tsc", kind: tar.TypeReg},
		entry{name: "nm/.bin/tsc", link: "../ts/bin/tsc", kind: tar.TypeSymlink},
		entry{name: "nm/ts", link: "../.pnpm/ts@5/nm/ts", kind: tar.TypeSymlink},
	), dir, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "nm", ".bin", "tsc")); string(b) != "tsc" {
		t.Fatalf("got %q", b)
	}
}

// extract unpacks a tar.gz into dir, which must not exist. Tests only.
func extract(r io.Reader, dir string, uid, gid int) error {
	parent, err := os.OpenRoot(filepath.Dir(dir))
	if err != nil {
		return err
	}
	defer parent.Close()
	return extractAt(r, parent, filepath.Base(dir), uid, gid)
}

func TestParseJournalNamesTheRelease(t *testing.T) {
	out := `{"__REALTIME_TIMESTAMP":"1795000000000000","MESSAGE":"listening","_SYSTEMD_INVOCATION_ID":"inv2"}
{"__REALTIME_TIMESTAMP":"1795000001000000","MESSAGE":[104,105,255],"_SYSTEMD_INVOCATION_ID":"inv9"}
not json
{"__REALTIME_TIMESTAMP":"1795000002000000","MESSAGE":"` + strings.Repeat("x", logMaxLineText+10) + `","_SYSTEMD_INVOCATION_ID":"inv1"}
`
	lines, truncated := parseJournal(strings.NewReader(out), []invocation{{"inv1", "r1"}, {"inv2", "r2"}})
	if len(lines) != 3 || !truncated {
		t.Fatalf("%d lines, truncated %v", len(lines), truncated)
	}
	if lines[0].Release != "r2" || lines[0].Text != "listening" || lines[0].Time != "2026-11-18T11:06:40Z" {
		t.Fatalf("first: %+v", lines[0])
	}
	// Bytes that are not UTF-8 come out valid; an unknown invocation has no release.
	if lines[1].Release != "" || lines[1].Text != "hi�" {
		t.Fatalf("second: %+v", lines[1])
	}
	if lines[2].Release != "r1" || len(lines[2].Text) != logMaxLineText {
		t.Fatalf("third: %d bytes", len(lines[2].Text))
	}
}

func TestALogRequestAloneIsAValidPoll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"logs":[{"id":"q1","lines":20,"since":5}]}`))
	}))
	defer srv.Close()
	a := &agent{cfg: config{Origin: srv.URL, Token: "t"}, http: srv.Client()}
	r, pull, logs, status, err := a.next(context.Background())
	if err != nil || status != 200 || r != nil || pull || len(logs) != 1 || logs[0] != (logRequest{ID: "q1", Lines: 20, Since: 5}) {
		t.Fatalf("%v %v %v %d %v", r, pull, logs, status, err)
	}
}
