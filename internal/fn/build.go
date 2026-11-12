//go:build linux

package fn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// keptVersions is how many versions of a function stay on disk (PLAN 7.11).
const keptVersions = 3

// BuildOptions describes one deploy of a function.
type BuildOptions struct {
	Function Function
	// Image is a registry reference, pulled without credentials. ImageTar,
	// when set, is a tarball from `docker save` and is read in its place.
	Image    string
	ImageTar string
	// Init is the carrel-fn-init binary copied into the image as process 1.
	Init string
	// Root is the directory that holds every function.
	Root string
	// MTU is the largest packet the host's uplink carries, and DNS the
	// public resolvers the function asks. A function reaches no private
	// address, so the host's own resolver is no use to it.
	MTU int
	DNS []string
}

// Build turns an image into a sleeping function: a root file system and a
// snapshot taken after the function answered its first request. The new
// version goes live when function.json is replaced.
func (fc *Firecracker) Build(ctx context.Context, opts BuildOptions) (Function, error) {
	f := opts.Function
	f.Version = time.Now().UTC().Format("20060102t150405")
	if err := f.normalize(); err != nil {
		return f, err
	}
	base := filepath.Join(opts.Root, f.Name)
	f.Dir = filepath.Join(base, "v", f.Version)
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return f, err
	}
	built := false
	defer func() {
		if !built {
			_ = os.RemoveAll(f.Dir)
		}
	}()

	image, err := openImage(ctx, opts.Image, opts.ImageTar)
	if err != nil {
		return f, err
	}
	spec, err := specOf(image)
	if err != nil {
		return f, err
	}
	spec.Port, spec.MTU, spec.DNS = f.Port, opts.MTU, opts.DNS
	if err := makeRootfs(ctx, image, opts.Init, spec, filepath.Join(f.Dir, "rootfs.ext4")); err != nil {
		return f, err
	}
	if err := fc.snapshot(ctx, f, filepath.Join(base, "log")); err != nil {
		return f, err
	}
	content, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return f, err
	}
	pending := filepath.Join(base, "function.json.new")
	if err := os.WriteFile(pending, append(content, '\n'), 0o600); err != nil {
		return f, err
	}
	if err := os.Rename(pending, filepath.Join(base, "function.json")); err != nil {
		return f, err
	}
	built = true
	prune(filepath.Join(base, "v"), f.Version)
	return f, nil
}

// makeRootfs writes the image into a new ext4 file system. The image's
// files never exist on the host: mke2fs reads the tar stream straight into
// the file system image.
func makeRootfs(ctx context.Context, image imageSource, initPath string, spec guestSpec, target string) error {
	stream, err := os.CreateTemp(filepath.Dir(target), "rootfs-*.tar")
	if err != nil {
		return err
	}
	defer os.Remove(stream.Name())
	defer stream.Close()
	need, err := rootTar(image, stream, initPath, spec)
	if err != nil {
		return err
	}
	if err := stream.Close(); err != nil {
		return err
	}
	file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	// A tenth for the file system's own tables, and room for the journal.
	if err := file.Truncate(need*11/10 + 64<<20); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	_, err = output(ctx, "mkfs.ext4", "-q", "-d", stream.Name(), target)
	return err
}

// prune keeps the newest versions and the current one.
func prune(dir, current string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() && entry.Name() != current {
			names = append(names, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names))) // version names sort by time
	for i, name := range names {
		if i >= keptVersions-1 {
			_ = os.RemoveAll(filepath.Join(dir, name))
		}
	}
}

func output(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(stderr.Bytes()))
	}
	return string(out), nil
}
