package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
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
