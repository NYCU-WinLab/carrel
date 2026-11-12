package fn

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

const (
	// maxImageBytes is the largest image a function may have, unpacked (PLAN 7.11).
	maxImageBytes = 2 << 30
	maxImageFiles = 1_000_000
	initDir       = ".fn"
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

// openImage reads an image from a registry, without credentials, or from a
// tarball made by `docker save`. No Docker daemon is involved.
func openImage(ctx context.Context, ref, tarPath string) (v1.Image, error) {
	if tarPath != "" {
		return tarball.ImageFromPath(tarPath, nil)
	}
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("image reference %q: %w", ref, err)
	}
	return remote.Image(parsed,
		remote.WithContext(ctx),
		remote.WithAuth(authn.Anonymous),
		remote.WithPlatform(v1.Platform{OS: "linux", Architecture: "amd64"}))
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

// rootTar writes the image's file system as one tar stream, with
// carrel-fn-init and the spec under /.fn. It returns the bytes an ext4 file
// system needs for it.
//
// The image is the tenant's and may be hostile. The stream is never unpacked
// on the host: mke2fs reads it straight into the file system image. Names
// are still made plain here, so that a strange name fails with a clear
// error and the image cannot bring its own /.fn.
func rootTar(image v1.Image, out io.Writer, initPath string, spec guestSpec) (int64, error) {
	flat := mutate.Extract(image) // layers merged, deletions applied
	defer flat.Close()
	reader, writer := tar.NewReader(flat), tar.NewWriter(out)
	seen := map[string]bool{"": true}
	var need, files int64

	emit := func(header *tar.Header, content io.Reader) error {
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
			need += (header.Size + 4095) &^ 4095
		}
		need += 4096 // an inode and directory entry, rounded up generously
		files++
		if need > maxImageBytes || files > maxImageFiles {
			return fmt.Errorf("the image is larger than %d MiB or has more than %d files", maxImageBytes>>20, maxImageFiles)
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
			return 0, fmt.Errorf("read the image: %w", err)
		}
		target, err := plainName(header.Name)
		if err != nil {
			return 0, err
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
		case tar.TypeReg, tar.TypeSymlink:
			header.Name = target
		case tar.TypeLink:
			link, err := plainName(header.Linkname)
			if err != nil {
				return 0, err
			}
			if link == initDir || strings.HasPrefix(link, initDir+"/") {
				continue
			}
			header.Name, header.Linkname = target, link
		default:
			continue // devices and FIFOs: the guest has its own /dev
		}
		if err := parents(target); err != nil {
			return 0, err
		}
		if header.Typeflag == tar.TypeDir {
			seen[target] = true
		}
		if err := emit(header, reader); err != nil {
			return 0, err
		}
	}

	// The library ends its stream with a valid tar trailer even when it
	// stopped on an error, such as a layer it could not read or a path that
	// leaves the root. The error is behind the trailer; without this check a
	// broken image would become an empty file system that looks fine.
	if _, err := io.Copy(io.Discard, flat); err != nil {
		return 0, fmt.Errorf("read the image: %w", err)
	}

	for _, dir := range []string{initDir, initDir + "/rw", initDir + "/newroot", initDir + "/old"} {
		if err := emit(&tar.Header{Typeflag: tar.TypeDir, Name: dir + "/", Mode: 0o755}, nil); err != nil {
			return 0, err
		}
	}
	init, err := os.Open(initPath)
	if err != nil {
		return 0, err
	}
	defer init.Close()
	info, err := init.Stat()
	if err != nil {
		return 0, err
	}
	if err := emit(&tar.Header{Typeflag: tar.TypeReg, Name: initDir + "/init", Mode: 0o755, Size: info.Size()}, init); err != nil {
		return 0, err
	}
	content, err := json.Marshal(spec)
	if err != nil {
		return 0, err
	}
	header := &tar.Header{Typeflag: tar.TypeReg, Name: initDir + "/spec.json", Mode: 0o644, Size: int64(len(content))}
	if err := emit(header, strings.NewReader(string(content))); err != nil {
		return 0, err
	}
	return need, writer.Close()
}

// plainName returns a path relative to the root with no "." or ".." part.
// An image that needs ".." to say where a file goes is refused.
func plainName(name string) (string, error) {
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", fmt.Errorf("the image has a path that leaves its root: %q", name)
		}
	}
	return strings.TrimPrefix(path.Clean("/"+name), "/"), nil
}
