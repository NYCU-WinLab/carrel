package fn

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

type entry struct {
	name, link, content string
	kind                byte
	mode                int64
}

// imageOf builds an image whose layers hold the given entries.
func imageOf(t *testing.T, layers ...[]entry) v1.Image {
	t.Helper()
	image := empty.Image
	for _, entries := range layers {
		var buffer bytes.Buffer
		writer := tar.NewWriter(&buffer)
		for _, e := range entries {
			kind := e.kind
			if kind == 0 {
				kind = tar.TypeReg
			}
			header := &tar.Header{Name: e.name, Typeflag: kind, Linkname: e.link, Mode: e.mode, Size: int64(len(e.content))}
			if err := writer.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write([]byte(e.content)); err != nil {
				t.Fatal(err)
			}
		}
		writer.Close()
		content := buffer.Bytes()
		layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(content)), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if image, err = mutate.AppendLayers(image, layer); err != nil {
			t.Fatal(err)
		}
	}
	return image
}

// rootOf runs rootTar and returns what it wrote: path to content, link target or type.
func rootOf(t *testing.T, image v1.Image) (map[string]string, error) {
	t.Helper()
	initPath := filepath.Join(t.TempDir(), "init")
	if err := os.WriteFile(initPath, []byte("the real init"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := rootTar(image, &out, initPath, guestSpec{Cmd: []string{"/app"}, Port: 8080}); err != nil {
		return nil, err
	}
	files := map[string]string{}
	reader := tar.NewReader(&out)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return files, nil
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, twice := files[header.Name]; twice {
			t.Fatalf("%s is written twice", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeReg:
			content, _ := io.ReadAll(reader)
			files[header.Name] = string(content)
		case tar.TypeDir:
			files[header.Name] = "dir"
		default:
			files[header.Name] = "-> " + header.Linkname
		}
	}
}

func TestRootTarKeepsTheImageAndAddsInit(t *testing.T) {
	files, err := rootOf(t, imageOf(t,
		[]entry{
			{name: "app/", kind: tar.TypeDir, mode: 0o755},
			{name: "app/server", content: "v1", mode: 0o755},
			{name: "app/old", content: "gone in layer 2"},
			{name: "./etc/passwd", content: "root:x:0:0:root:/root:/bin/sh\n"},
			{name: "usr/bin/tool", content: "no parent directory in the layer"},
			{name: "lib", kind: tar.TypeSymlink, link: "usr/lib"},
			{name: "app/hard", kind: tar.TypeLink, link: "app/server"},
		},
		[]entry{
			{name: "app/server", content: "v2", mode: 0o755},
			{name: "app/.wh.old"}, // a deletion marker
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"app/": "dir", "app/server": "v2", "etc/": "dir", "etc/passwd": "root:x:0:0:root:/root:/bin/sh\n",
		"usr/": "dir", "usr/bin/": "dir", "usr/bin/tool": "no parent directory in the layer",
		"lib": "-> usr/lib", "app/hard": "-> app/server",
		".fn/": "dir", ".fn/rw/": "dir", ".fn/newroot/": "dir", ".fn/old/": "dir",
		".fn/init": "the real init", ".fn/spec.json": `{"name":"","cmd":["/app"],"env":null,"cwd":"","user":"","port":8080,"mtu":0,"dns":null}`,
	}
	var got, expected []string
	for name, content := range files {
		got = append(got, name+" = "+content)
	}
	for name, content := range want {
		expected = append(expected, name+" = "+content)
	}
	sort.Strings(got)
	sort.Strings(expected)
	if strings.Join(got, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("root file system:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(expected, "\n"))
	}
}

// The image is the tenant's. It must not bring its own process 1, devices,
// or a path that leaves the root.
func TestRootTarRefusesWhatAHostileImageBrings(t *testing.T) {
	files, err := rootOf(t, imageOf(t, []entry{
		{name: ".fn/", kind: tar.TypeDir},
		{name: ".fn/init", content: "the image's own init", mode: 0o755},
		{name: ".fn/spec.json", content: `{"cmd":["/evil"]}`},
		{name: "/.fn/extra", content: "x"},
		{name: "sneaky", kind: tar.TypeLink, link: ".fn/init"},
		{name: "dev/sda", kind: tar.TypeBlock},
		{name: "dev/mem", kind: tar.TypeChar},
		{name: "pipe", kind: tar.TypeFifo},
		{name: "/abs/file", content: "absolute names land inside the root"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if files[".fn/init"] != "the real init" || !strings.Contains(files[".fn/spec.json"], `"/app"`) {
		t.Fatalf("the image replaced process 1: init %q, spec %q", files[".fn/init"], files[".fn/spec.json"])
	}
	for _, name := range []string{".fn/extra", "sneaky", "dev/sda", "dev/mem", "pipe"} {
		if _, ok := files[name]; ok {
			t.Errorf("%s was kept", name)
		}
	}
	if files["abs/file"] == "" {
		t.Errorf("abs/file is missing: %v", files)
	}
	// The flattening library drops entries that leave the root. Whatever a
	// later version of it does, nothing with ".." may reach the file system.
	hostile := imageOf(t, []entry{
		{name: "../escape", content: "x"},
		{name: "a/../../escape", content: "x"},
		{name: "ok/../../../etc/shadow", content: "x"},
		{name: "link", kind: tar.TypeLink, link: "../../etc/shadow"},
		{name: "fine", content: "kept"},
	})
	files, err = rootOf(t, hostile)
	if err != nil {
		return // refusing the whole image is safe, and what the library does today
	}
	t.Log("the library kept the image; checking what it let through")
	for name, content := range files {
		if strings.Contains(name, "..") || strings.Contains(content, "..") ||
			strings.Contains(name, "escape") || strings.Contains(name, "shadow") {
			t.Errorf("%s (%s) reached the file system", name, content)
		}
	}
	if files["fine"] != "kept" {
		t.Errorf("an ordinary file beside the hostile ones is missing: %v", files)
	}
}

func TestPlainName(t *testing.T) {
	for name, want := range map[string]string{
		"./etc/passwd": "etc/passwd", "/abs/file": "abs/file", "a//b/./c/": "a/b/c", ".": "", "/": "",
	} {
		if got, err := plainName(name); err != nil || got != want {
			t.Errorf("plainName(%q) = %q, %v; want %q", name, got, err, want)
		}
	}
	for _, name := range []string{"..", "../x", "a/../b", "a/b/.."} {
		if _, err := plainName(name); err == nil {
			t.Errorf("plainName(%q) accepted a path with ..", name)
		}
	}
}

func TestSpecOfNeedsACommandForLinuxAMD64(t *testing.T) {
	configured := func(os, arch string, config v1.Config) v1.Image {
		image, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{OS: os, Architecture: arch, Config: config})
		if err != nil {
			t.Fatal(err)
		}
		return image
	}
	spec, err := specOf(configured("linux", "amd64", v1.Config{
		Entrypoint: []string{"python"}, Cmd: []string{"app.py"}, Env: []string{"A=1"}, WorkingDir: "/app", User: "node:node",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(spec.Cmd, " ") != "python app.py" || spec.Cwd != "/app" || spec.User != "node:node" || spec.Env[0] != "A=1" {
		t.Fatalf("spec = %+v", spec)
	}
	if _, err := specOf(configured("linux", "amd64", v1.Config{})); err == nil {
		t.Error("an image with no command was accepted")
	}
	if _, err := specOf(configured("linux", "arm64", v1.Config{Cmd: []string{"x"}})); err == nil {
		t.Error("an arm64 image was accepted")
	}
}

// A layer that cannot be read must fail the build. The library still ends
// its stream with a valid tar trailer, which once hid the error.
func TestRootTarFailsOnABrokenLayer(t *testing.T) {
	good := imageOf(t, []entry{{name: "app", content: "x"}})
	broken, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("this is not a tar stream, and long enough to be read as a header block" + strings.Repeat("!", 512))), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	image, err := mutate.AppendLayers(good, broken)
	if err != nil {
		t.Fatal(err)
	}
	if files, err := rootOf(t, image); err == nil {
		t.Fatalf("a broken layer was accepted: %v", files)
	}
	if _, err := rootOf(t, imageOf(t, []entry{{name: "../escape", content: "x"}, {name: "fine", content: "kept"}})); err == nil {
		t.Fatal("an image with a path that leaves the root built a file system")
	}
}
