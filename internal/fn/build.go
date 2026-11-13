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
	"strconv"
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
	// Blocked adds to the addresses the pull must not connect to: the
	// site's protected addresses, as for the egress filter.
	Blocked []string
	// Activate puts the new version live at once and prunes old versions.
	// The host agent leaves both to the control plane's desired state.
	Activate bool
	// Env adds KEY=VALUE pairs to the image's environment; a pair wins
	// over the image's value of its key.
	Env []string
	// Auth pulls Image from a private registry.
	Auth *RegistryAuth
}

// buildTime is the longest one build may take, from the pull to the snapshot.
const buildTime = 15 * time.Minute

// Build turns an image into a sleeping function: a root file system and a
// snapshot taken after the function answered its first request. A version
// keeps its own function.json; it goes live when that file is copied over the
// function's function.json (Activate). Function.Version names the version,
// or the build names it by the second.
func (fc *Firecracker) Build(ctx context.Context, opts BuildOptions) (Function, error) {
	ctx, cancel := context.WithTimeout(ctx, buildTime)
	defer cancel()
	f := opts.Function
	if f.Version == "" {
		f.Version = time.Now().UTC().Format("20060102t150405")
	}
	if !versionRE.MatchString(f.Version) {
		return f, fmt.Errorf("invalid version %q", f.Version)
	}
	if err := f.normalize(); err != nil {
		return f, err
	}
	base := filepath.Join(opts.Root, f.Name)
	f.Dir = filepath.Join(base, "v", f.Version)
	if err := os.MkdirAll(filepath.Dir(f.Dir), 0o700); err != nil {
		return f, err
	}
	// A version is built once: its snapshot records its own paths.
	if err := os.Mkdir(f.Dir, 0o700); err != nil {
		return f, err
	}
	built := false
	defer func() {
		if !built {
			_ = os.RemoveAll(f.Dir)
			// A function that never built leaves no directory. os.Remove
			// takes only empty ones, so earlier versions stay.
			_ = os.Remove(filepath.Join(base, "v"))
			_ = os.Remove(base)
		}
	}()

	image, err := openImage(ctx, opts.Image, opts.ImageTar, opts.Blocked, opts.Auth)
	if err != nil {
		return f, err
	}
	spec, err := specOf(image)
	if err != nil {
		return f, err
	}
	f.Image = opts.Image
	if digest, err := image.Digest(); err == nil {
		f.Digest = digest.String()
	}
	spec.Name, spec.Port, spec.MTU, spec.DNS = f.Name, f.Port, opts.MTU, opts.DNS
	spec.Env = append(spec.Env, opts.Env...)
	if err := makeRootfs(ctx, image, opts.Init, spec, filepath.Join(f.Dir, "rootfs.ext4")); err != nil {
		// Layers come over the same credentials: their errors are kept short too.
		return f, pullError(err, opts.Auth)
	}
	// The build has a log of its own: the router rotates log, and two
	// processes must not rotate one file.
	if err := fc.snapshot(ctx, f, filepath.Join(base, "build.log")); err != nil {
		return f, err
	}
	content, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return f, err
	}
	if err := writeFile(filepath.Join(f.Dir, "function.json"), append(content, '\n')); err != nil {
		return f, err
	}
	built = true
	if opts.Activate {
		if err := Activate(opts.Root, f.Name, f.Version); err != nil {
			return f, err
		}
		prune(filepath.Join(base, "v"), f.Version)
	}
	return f, nil
}

// Built reports whether a version of a function finished its build.
func Built(root, name, version string) bool {
	if !nameRE.MatchString(name) || !versionRE.MatchString(version) {
		return false
	}
	_, err := os.Stat(filepath.Join(root, name, "v", version, "function.json"))
	return err == nil
}

// Activate makes a built version the one the router wakes. The router reads
// function.json again when it changes, and a new request wakes the version.
func Activate(root, name, version string) error {
	if !Built(root, name, version) {
		return fmt.Errorf("version %s of %s is not built", version, name)
	}
	content, err := os.ReadFile(filepath.Join(root, name, "v", version, "function.json"))
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(root, name, "function.json"), content)
}

// writeFile replaces a file in one step, so a reader sees the old or the new one.
func writeFile(path string, content []byte) error {
	pending := path + ".new"
	if err := os.WriteFile(pending, content, 0o600); err != nil {
		return err
	}
	return os.Rename(pending, path)
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
	size, err := rootTar(image, stream, initPath, spec)
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
	// One inode for every file, with room to spare: mke2fs would give a
	// large image one inode for each 16 KiB, too few for many small files.
	inodes := size.Files + size.Files/8 + 1024
	// A tenth for the file system's own tables, the inode tables, and the journal.
	if err := file.Truncate(size.Bytes*11/10 + inodes*256 + 64<<20); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "mkfs.ext4", "-q", "-N", strconv.FormatInt(inodes, 10), "-d", stream.Name(), target)
	// File names in an image are bytes. In the C locale the archive library
	// refuses names that are not ASCII.
	cmd.Env = append(os.Environ(), "LC_ALL=C.UTF-8")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mkfs.ext4: %w: %s", err, bytes.TrimSpace(out))
	}
	return nil
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
