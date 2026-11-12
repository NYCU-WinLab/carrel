package fn

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
	image, err := budgeted(image)
	if err != nil {
		t.Fatal(err)
	}
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

// layerOf makes a layer from raw tar bytes.
func layerOf(t *testing.T, content []byte) v1.Layer {
	t.Helper()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(content)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return layer
}

type countingWriter struct{ written int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.written += int64(len(p))
	return len(p), nil
}

// One entry can claim more than the host's disk: a sparse file, or zeros
// that compress to nothing. It must be refused before its content is written.
func TestRootTarRefusesAHugeFileBeforeWritingIt(t *testing.T) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	if err := writer.WriteHeader(&tar.Header{Name: "huge", Typeflag: tar.TypeReg, Size: 1 << 40, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	buffer.Write(make([]byte, 1<<20)) // some of the claimed content, then the stream just ends
	image, err := mutate.AppendLayers(empty.Image, layerOf(t, buffer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	image, err = budgeted(image)
	if err != nil {
		t.Fatal(err)
	}
	initPath := filepath.Join(t.TempDir(), "init")
	os.WriteFile(initPath, []byte("init"), 0o755)
	out := &countingWriter{}
	if _, err := rootTar(image, out, initPath, guestSpec{Cmd: []string{"/app"}}); !errors.Is(err, errImageTooLarge) {
		t.Fatalf("err = %v, want the size limit", err)
	}
	if out.written > 64<<10 {
		t.Fatalf("%d bytes were written before the image was refused", out.written)
	}
}

// Names are not counted as content, so they have their own limits.
func TestLongNamesAreRefused(t *testing.T) {
	deep := strings.Repeat("a/", 3000) + "f" // 6001 bytes, more than PATH_MAX
	if _, err := rootOf(t, imageOf(t, []entry{{name: deep, content: "x"}})); err == nil {
		t.Error("a path longer than 4096 bytes was accepted")
	}
	if _, err := rootOf(t, imageOf(t, []entry{{name: strings.Repeat("n", 300), content: "x"}})); err == nil {
		t.Error("a file name longer than 255 bytes was accepted")
	}
	if _, err := rootOf(t, imageOf(t, []entry{{name: "l", kind: tar.TypeSymlink, link: strings.Repeat("t", 5000)}})); err == nil {
		t.Error("a link target longer than 4096 bytes was accepted")
	}
	if _, err := rootOf(t, imageOf(t, []entry{{name: strings.Repeat("a/", 100000) + "f", content: "x"}})); err == nil {
		t.Error("a 200 KB path was accepted")
	}
}

// filtered runs one layer through the budget and reads what comes out.
func filtered(content []byte, b *budget) (int, error) {
	reader, writer := io.Pipe()
	go func() { writer.CloseWithError(b.filter(writer, bytes.NewReader(content))) }()
	entries := 0
	tr := tar.NewReader(reader)
	for {
		if _, err := tr.Next(); err != nil {
			if errors.Is(err, io.EOF) {
				return entries, nil
			}
			return entries, err
		}
		entries++
	}
}

// The limits apply to what the layers hold, before they are merged: deleted
// and replaced files, and deletion markers, cost the host as much to read.
func TestFilterStopsAtItsBudget(t *testing.T) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for i := range 10 {
		writer.WriteHeader(&tar.Header{Name: "f" + string(rune('0'+i)), Typeflag: tar.TypeReg, Size: 1000, Mode: 0o644})
		writer.Write(make([]byte, 1000))
	}
	writer.Close()
	full := func() *budget { return &budget{raw: 1 << 20, content: 1 << 20, entries: 100, names: 1 << 20} }
	if n, err := filtered(buffer.Bytes(), full()); err != nil || n != 10 {
		t.Fatalf("a stream inside its budget: %d entries, %v", n, err)
	}
	for name, cut := range map[string]func(*budget){
		"entries": func(b *budget) { b.entries = 9 },
		"content": func(b *budget) { b.content = 9000 },
		"raw":     func(b *budget) { b.raw = 4000 },
		"names":   func(b *budget) { b.names = 15 },
	} {
		b := full()
		cut(b)
		if _, err := filtered(buffer.Bytes(), b); !errors.Is(err, errImageTooLarge) {
			t.Errorf("the %s budget did not stop the stream: %v", name, err)
		}
	}

	// A long name travels in an extended header, which archive/tar caps.
	buffer.Reset()
	writer = tar.NewWriter(&buffer)
	writer.WriteHeader(&tar.Header{Name: strings.Repeat("d/", 40000) + "f", Typeflag: tar.TypeReg, Mode: 0o644})
	writer.Close()
	if _, err := filtered(buffer.Bytes(), newBudget()); err == nil {
		t.Error("an 80 KB name passed")
	}
}

// A PAX record can give an entry a size other than its header block's. The
// count must follow archive/tar, which the merge uses: here the PAX size is 0
// and the block claims 1 GiB, behind which hide entries the merge will read.
func TestFilterCountsWhatArchiveTarReads(t *testing.T) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	if err := writer.WriteHeader(&tar.Header{Name: "big", Typeflag: tar.TypeReg, Size: 1 << 33, Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	stream := buffer.Bytes()[:1536] // the PAX header, its records and the file's block; no content
	stream = bytes.Replace(stream, []byte("size=8589934592"), []byte("size=0000000000"), 1)
	block := stream[1024:1536]
	copy(block[124:136], "07777777777\x00")
	copy(block[148:156], "        ")
	sum := 0
	for _, c := range block {
		sum += int(c)
	}
	copy(block[148:156], fmt.Sprintf("%06o\x00 ", sum))

	var rest bytes.Buffer
	more := tar.NewWriter(&rest)
	for i := range 10 {
		more.WriteHeader(&tar.Header{Name: fmt.Sprintf(".wh.f%d", i), Typeflag: tar.TypeReg, Mode: 0o644})
	}
	more.Close()
	stream = append(append([]byte{}, stream...), rest.Bytes()...)

	n, err := filtered(stream, &budget{raw: 1 << 20, content: 1 << 20, entries: 100, names: 1 << 20})
	if err != nil || n != 11 {
		t.Fatalf("got %d entries, %v; archive/tar reads 11", n, err)
	}
	if _, err := filtered(stream, &budget{raw: 1 << 20, content: 1 << 20, entries: 5, names: 1 << 20}); !errors.Is(err, errImageTooLarge) {
		t.Errorf("entries behind a PAX size escaped the count: %v", err)
	}
}

// The library reads a configuration of unknown size without a limit.
func TestConfigSizeMustBeKnownAndSmall(t *testing.T) {
	for size, ok := range map[int64]bool{-1: false, 0: true, 1000: true, maxConfigBytes + 1: false} {
		manifest := &v1.Manifest{Config: v1.Descriptor{Size: size}}
		if err := checkConfig(manifest); (err == nil) != ok {
			t.Errorf("size %d: %v", size, err)
		}
	}
}

// The tenant chooses the image reference. The host must not connect to
// itself or to a private network on the tenant's word.
func TestPullRefusesAddressesThatAreNotPublic(t *testing.T) {
	control, err := publicOnly([]string{"140.113.60.189"})
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{
		"127.0.0.1:5000", "10.200.0.2:443", "192.168.19.101:8006", "169.254.169.254:80", "100.100.1.4:443",
		"172.16.0.2:80", "0.0.0.0:80", "140.113.60.189:443", "[::1]:443", "[fd00::1]:443", "[::ffff:127.0.0.1]:80",
	} {
		if err := control("tcp4", address, nil); err == nil {
			t.Errorf("a connection to %s was allowed", address)
		}
	}
	for _, address := range []string{"1.1.1.1:443", "140.82.112.34:443"} {
		if err := control("tcp4", address, nil); err != nil {
			t.Errorf("a connection to %s was refused: %v", address, err)
		}
	}
	// End to end: a registry on loopback is never reached.
	reached := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	_, err = openImage(context.Background(), host+"/some/image:tag", "", nil)
	if err == nil || reached {
		t.Fatalf("the pull reached a loopback registry: err=%v reached=%v", err, reached)
	}
	if !strings.Contains(err.Error(), "not a public address") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}
