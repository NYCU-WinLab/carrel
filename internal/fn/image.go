package fn

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// The image is the tenant's and may be hostile. Every limit below is checked
// before the host spends the disk, memory or time it guards.
const (
	// maxImageBytes is the largest image a function may have, unpacked (PLAN 7.11).
	maxImageBytes = 2 << 30
	maxImageFiles = 1_000_000
	// maxStreamBytes caps what rootTar really writes: the image plus tar headers.
	maxStreamBytes = maxImageBytes + 512<<20
	// Layers hold more than the final image: files a later layer replaces or
	// deletes. These cap what is read and unpacked before the layers merge.
	maxLayerBytes   = 4 * maxImageBytes
	maxLayerEntries = 4 * maxImageFiles
	// The merge keeps every name of every layer in memory, deletion markers too.
	maxLayerNames  = 256 << 20
	maxConfigBytes = 1 << 20
	maxNameBytes   = 4096 // PATH_MAX
	maxPartBytes   = 255  // NAME_MAX
	initDir        = ".fn"
)

// imageSource is the part of an image a function needs.
type imageSource = v1.Image

// guestSpec is what carrel-fn-init reads from /.fn/spec.json.
type guestSpec struct {
	Name string   `json:"name"`
	Cmd  []string `json:"cmd"`
	Env  []string `json:"env"`
	Cwd  string   `json:"cwd"`
	User string   `json:"user"`
	Port int      `json:"port"`
	// MTU and DNS describe the function host's network to the guest.
	MTU int      `json:"mtu"`
	DNS []string `json:"dns"`
}

// publicOnly refuses a connection to any address a function must not reach.
// It runs on every connection the pull makes, after the name is resolved, so
// a reference, a redirect or a token endpoint cannot point the host at
// itself or at a private network. The tenant chooses the reference.
func publicOnly(extra []string) (func(network, address string, _ syscall.RawConn) error, error) {
	var refused []netip.Prefix
	for _, entry := range append(append([]string{}, blocked...), extra...) {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			address, addrErr := netip.ParseAddr(entry)
			if addrErr != nil {
				return nil, fmt.Errorf("blocked address %q: %w", entry, err)
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		refused = append(refused, prefix)
	}
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return err
		}
		addr = addr.Unmap()
		if !addr.Is4() {
			return fmt.Errorf("%s is not a public IPv4 address", addr)
		}
		for _, prefix := range refused {
			if prefix.Contains(addr) {
				return fmt.Errorf("%s is not a public address", addr)
			}
		}
		return nil
	}, nil
}

// pullTransport is the only way the host talks to a registry.
func pullTransport(extra []string) (http.RoundTripper, error) {
	control, err := publicOnly(extra)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second, Control: control}
	return &http.Transport{
		Proxy: nil, // a proxy would make the connection for us, to anywhere
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", address)
		},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          4,
	}, nil
}

// openImage reads an image from a registry, without credentials, or from a
// tarball made by `docker save`. No Docker daemon is involved.
func openImage(ctx context.Context, ref, tarPath string, blockedExtra []string) (v1.Image, error) {
	var image v1.Image
	var err error
	if tarPath != "" {
		image, err = tarball.ImageFromPath(tarPath, nil)
	} else {
		var parsed name.Reference
		if parsed, err = name.ParseReference(ref); err != nil {
			return nil, fmt.Errorf("image reference %q: %w", ref, err)
		}
		var transport http.RoundTripper
		if transport, err = pullTransport(blockedExtra); err != nil {
			return nil, err
		}
		image, err = remote.Image(parsed,
			remote.WithContext(ctx),
			remote.WithAuth(authn.Anonymous),
			remote.WithTransport(transport),
			remote.WithPlatform(v1.Platform{OS: "linux", Architecture: "amd64"}))
	}
	if err != nil {
		return nil, err
	}
	// The configuration is read into memory whole. Its size comes from the manifest.
	manifest, err := image.Manifest()
	if err != nil {
		return nil, err
	}
	if err := checkConfig(manifest); err != nil {
		return nil, err
	}
	return budgeted(image)
}

// checkConfig bounds the configuration, which the library reads into memory
// whole. It reads at most the size the manifest gives, and a negative size
// means unknown to it: then it reads whatever the registry sends.
func checkConfig(manifest *v1.Manifest) error {
	if size := manifest.Config.Size; size < 0 || size > maxConfigBytes {
		return fmt.Errorf("the image's configuration is %d bytes, it must be 0 to %d", size, maxConfigBytes)
	}
	return nil
}

// specOf takes the command the image would run.
func specOf(image v1.Image) (guestSpec, error) {
	file, err := image.ConfigFile()
	if err != nil {
		return guestSpec{}, err
	}
	if file.OS != "linux" || file.Architecture != "amd64" {
		return guestSpec{}, fmt.Errorf("the image is for %s/%s, a function needs linux/amd64", file.OS, file.Architecture)
	}
	config := file.Config
	spec := guestSpec{
		Cmd:  append(append([]string{}, config.Entrypoint...), config.Cmd...),
		Env:  config.Env,
		Cwd:  config.WorkingDir,
		User: config.User,
	}
	if len(spec.Cmd) == 0 {
		return spec, errors.New("the image has no entrypoint or command")
	}
	return spec, nil
}

var errImageTooLarge = fmt.Errorf("the image is larger than %d MiB unpacked, or has more than %d files", maxImageBytes>>20, maxImageFiles)

// budget is shared by every layer of one image.
type budget struct {
	mu                           sync.Mutex
	raw, content, entries, names int64
}

func newBudget() *budget {
	return &budget{raw: maxLayerBytes, content: maxLayerBytes, entries: maxLayerEntries, names: maxLayerNames}
}

func (b *budget) take(field *int64, n int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if *field -= n; *field < 0 {
		return errImageTooLarge
	}
	return nil
}

// budgeted wraps the image's layers so that reading them stops at the
// limits. The library that merges layers keeps every name it saw in memory
// and reads deleted and replaced files in full, so the limits must apply
// before it, not to its output.
func budgeted(image v1.Image) (v1.Image, error) {
	layers, err := image.Layers()
	if err != nil {
		return nil, err
	}
	shared := newBudget()
	wrapped := make([]v1.Layer, len(layers))
	for i, layer := range layers {
		wrapped[i] = budgetedLayer{Layer: layer, budget: shared}
	}
	return budgetedImage{Image: image, layers: wrapped}, nil
}

type budgetedImage struct {
	v1.Image
	layers []v1.Layer
}

func (i budgetedImage) Layers() ([]v1.Layer, error) { return i.layers, nil }

type budgetedLayer struct {
	v1.Layer
	budget *budget
}

// Uncompressed hands the merge a copy of the layer that archive/tar parsed
// and wrote again. The merge then reads exactly the entries that were
// counted: a layer cannot hide entries from the count with headers that a
// raw byte scanner and archive/tar read differently.
func (l budgetedLayer) Uncompressed() (io.ReadCloser, error) {
	stream, err := l.Layer.Uncompressed()
	if err != nil {
		return nil, err
	}
	reader, writer := io.Pipe()
	go func() {
		err := l.budget.filter(writer, stream)
		_ = stream.Close()
		_ = writer.CloseWithError(err) // nil ends the reader with io.EOF
	}()
	return reader, nil
}

// rawMeter counts the bytes of a layer as they arrive, headers included.
type rawMeter struct {
	in     io.Reader
	budget *budget
}

func (m rawMeter) Read(p []byte) (int, error) {
	n, err := m.in.Read(p)
	if takeErr := m.budget.take(&m.budget.raw, int64(n)); takeErr != nil {
		return 0, takeErr
	}
	return n, err
}

// filter parses one layer, counts every entry, name and byte against the
// budget, and writes the entries again with only the fields a root file
// system keeps. archive/tar caps each extended header at 1 MiB.
func (b *budget) filter(out io.Writer, in io.Reader) error {
	reader, writer := tar.NewReader(rawMeter{in: in, budget: b}), tar.NewWriter(out)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			// The library checks the layer's digest only when its stream
			// reaches EOF, which is past the tar trailer. Without this read
			// a registry could swap a layer and the build would not notice.
			if _, err := io.Copy(io.Discard, rawMeter{in: in, budget: b}); err != nil {
				return err
			}
			return writer.Close()
		}
		if err != nil {
			return err
		}
		if err := b.take(&b.entries, 1); err != nil {
			return err
		}
		if long := max(len(header.Name), len(header.Linkname)); long > maxNameBytes {
			return fmt.Errorf("the image has a path of %d bytes", long)
		}
		if err := b.take(&b.names, int64(len(header.Name)+len(header.Linkname))); err != nil {
			return err
		}
		clean := &tar.Header{
			Typeflag: header.Typeflag, Name: header.Name, Linkname: header.Linkname,
			Mode: header.Mode, Uid: header.Uid, Gid: header.Gid, ModTime: header.ModTime,
			Format: tar.FormatPAX,
		}
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeGNUSparse, '\x00':
			// A sparse file is read with its holes filled, at its full size.
			if header.Size < 0 || header.Size > maxImageBytes {
				return errImageTooLarge
			}
			if err := b.take(&b.content, header.Size); err != nil {
				return err
			}
			clean.Typeflag, clean.Size = tar.TypeReg, header.Size
		case tar.TypeDir, tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		default:
			continue // a type no file system holds
		}
		if err := writer.WriteHeader(clean); err != nil {
			return err
		}
		if clean.Size > 0 {
			if _, err := io.CopyN(writer, reader, clean.Size); err != nil {
				return err
			}
		}
	}
}

// capped stops a stream that grows past its limit.
type capped struct {
	out  io.Writer
	left int64
}

func (c *capped) Write(p []byte) (int, error) {
	if c.left -= int64(len(p)); c.left < 0 {
		return 0, errImageTooLarge
	}
	return c.out.Write(p)
}

// rootSize is what an ext4 file system needs for a root tar.
type rootSize struct {
	Bytes int64
	Files int64
}

// rootTar writes the image's file system as one tar stream, with
// carrel-fn-init and the spec under /.fn.
//
// The stream is never unpacked on the host: mke2fs reads it straight into
// the file system image. Names are still made plain here, so that a strange
// name fails with a clear error and the image cannot bring its own /.fn.
func rootTar(image v1.Image, out io.Writer, initPath string, spec guestSpec) (rootSize, error) {
	flat := mutate.Extract(image) // layers merged, deletions applied
	defer flat.Close()
	reader, writer := tar.NewReader(flat), tar.NewWriter(&capped{out: out, left: maxStreamBytes})
	seen := map[string]bool{"": true}
	var size rootSize

	emit := func(header *tar.Header, content io.Reader) error {
		// Counted before anything is written: one sparse or compressed entry
		// can claim more than the disk holds.
		size.Bytes += 4096 + int64(len(header.Name)+len(header.Linkname)) // an inode and its directory entry, generously
		if header.Typeflag == tar.TypeReg {
			if header.Size < 0 || header.Size > maxImageBytes {
				return errImageTooLarge
			}
			size.Bytes += (header.Size + 4095) &^ 4095
		}
		size.Files++
		if size.Bytes > maxImageBytes || size.Files > maxImageFiles {
			return errImageTooLarge
		}
		header.Format = tar.FormatPAX
		header.Uname, header.Gname = "", ""
		header.PAXRecords, header.Xattrs = nil, nil //nolint:staticcheck // drop extended attributes
		if err := writer.WriteHeader(header); err != nil {
			return err
		}
		if header.Typeflag == tar.TypeReg {
			if _, err := io.CopyN(writer, content, header.Size); err != nil {
				return err
			}
		}
		return nil
	}
	// parents writes the directories above a path that the stream did not carry.
	parents := func(target string) error {
		dir := path.Dir(target)
		if dir == "." || seen[dir] {
			return nil
		}
		var missing []string
		for ; dir != "." && !seen[dir]; dir = path.Dir(dir) {
			missing = append(missing, dir)
		}
		for i := len(missing) - 1; i >= 0; i-- {
			seen[missing[i]] = true
			if err := emit(&tar.Header{Typeflag: tar.TypeDir, Name: missing[i] + "/", Mode: 0o755}, nil); err != nil {
				return err
			}
		}
		return nil
	}

	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return size, fmt.Errorf("read the image: %w", err)
		}
		target, err := plainName(header.Name)
		if err != nil {
			return size, err
		}
		if target == "" || target == initDir || strings.HasPrefix(target, initDir+"/") {
			continue // the root itself, or the image's own /.fn
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if seen[target] {
				continue
			}
			header.Name = target + "/"
		case tar.TypeReg:
			header.Name = target
		case tar.TypeSymlink:
			if len(header.Linkname) > maxNameBytes {
				return size, fmt.Errorf("the image has a link target of %d bytes", len(header.Linkname))
			}
			header.Name = target
		case tar.TypeLink:
			link, err := plainName(header.Linkname)
			if err != nil {
				return size, err
			}
			if link == initDir || strings.HasPrefix(link, initDir+"/") {
				continue
			}
			header.Name, header.Linkname = target, link
		default:
			continue // devices and FIFOs: the guest has its own /dev
		}
		if err := parents(target); err != nil {
			return size, err
		}
		if header.Typeflag == tar.TypeDir {
			seen[target] = true
		}
		if err := emit(header, reader); err != nil {
			return size, err
		}
	}
	// The library ends its stream with a valid tar trailer even when it
	// stopped on an error, such as a layer it could not read or a path that
	// leaves the root. The error is behind the trailer; without this check a
	// broken image would become an empty file system that looks fine.
	if _, err := io.Copy(io.Discard, io.LimitReader(flat, 1<<20)); err != nil {
		return size, fmt.Errorf("read the image: %w", err)
	}

	for _, dir := range []string{initDir, initDir + "/rw", initDir + "/newroot", initDir + "/old"} {
		if err := emit(&tar.Header{Typeflag: tar.TypeDir, Name: dir + "/", Mode: 0o755}, nil); err != nil {
			return size, err
		}
	}
	init, err := os.Open(initPath)
	if err != nil {
		return size, err
	}
	defer init.Close()
	info, err := init.Stat()
	if err != nil {
		return size, err
	}
	if err := emit(&tar.Header{Typeflag: tar.TypeReg, Name: initDir + "/init", Mode: 0o755, Size: info.Size()}, init); err != nil {
		return size, err
	}
	content, err := json.Marshal(spec)
	if err != nil {
		return size, err
	}
	header := &tar.Header{Typeflag: tar.TypeReg, Name: initDir + "/spec.json", Mode: 0o644, Size: int64(len(content))}
	if err := emit(header, strings.NewReader(string(content))); err != nil {
		return size, err
	}
	return size, writer.Close()
}

// plainName returns a path relative to the root with no "." or ".." part.
// An image that needs ".." to say where a file goes is refused, and so is a
// name no Linux file system would hold.
func plainName(name string) (string, error) {
	if len(name) > maxNameBytes {
		return "", fmt.Errorf("the image has a path of %d bytes", len(name))
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", fmt.Errorf("the image has a path that leaves its root: %q", name)
		}
		if len(part) > maxPartBytes {
			return "", fmt.Errorf("the image has a file name of %d bytes", len(part))
		}
	}
	return strings.TrimPrefix(path.Clean("/"+name), "/"), nil
}
