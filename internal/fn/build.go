//go:build linux

package fn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	// Image is a Docker image present on this host. Step 2 of PLAN 7.11
	// replaces this with a pull that needs no Docker daemon.
	Image string
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

type guestSpec struct {
	Cmd  []string `json:"cmd"`
	Env  []string `json:"env"`
	Cwd  string   `json:"cwd"`
	Port int      `json:"port"`
	// MTU and DNS describe the function host's network to the guest.
	MTU int      `json:"mtu"`
	DNS []string `json:"dns"`
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

	tree, err := os.MkdirTemp(base, "tree-")
	if err != nil {
		return f, err
	}
	defer os.RemoveAll(tree)
	spec, err := exportImage(ctx, opts.Image, tree)
	if err != nil {
		return f, err
	}
	spec.Port = f.Port
	spec.MTU = opts.MTU
	spec.DNS = opts.DNS
	if err := addInit(tree, opts.Init, spec); err != nil {
		return f, err
	}
	if err := makeExt4(ctx, tree, filepath.Join(f.Dir, "rootfs.ext4")); err != nil {
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

// exportImage unpacks a Docker image's file system into dir and returns the
// command the image would run.
func exportImage(ctx context.Context, image, dir string) (guestSpec, error) {
	var spec guestSpec
	id, err := output(ctx, "docker", "create", image)
	if err != nil {
		return spec, err
	}
	container := strings.TrimSpace(id)
	defer exec.Command("docker", "rm", "-f", container).Run()

	inspect, err := output(ctx, "docker", "inspect", container)
	if err != nil {
		return spec, err
	}
	var described []struct {
		Config struct {
			Entrypoint []string
			Cmd        []string
			Env        []string
			WorkingDir string
		}
	}
	if err := json.Unmarshal([]byte(inspect), &described); err != nil || len(described) != 1 {
		return spec, errors.New("unexpected docker inspect output")
	}
	config := described[0].Config
	spec = guestSpec{Cmd: append(config.Entrypoint, config.Cmd...), Env: config.Env, Cwd: config.WorkingDir}
	if len(spec.Cmd) == 0 {
		return spec, fmt.Errorf("image %s has no entrypoint or command", image)
	}

	export := exec.CommandContext(ctx, "docker", "export", container)
	unpack := exec.CommandContext(ctx, "tar", "-x", "-C", dir)
	pipe, err := export.StdoutPipe()
	if err != nil {
		return spec, err
	}
	unpack.Stdin = pipe
	var exportErr, unpackErr bytes.Buffer
	export.Stderr, unpack.Stderr = &exportErr, &unpackErr
	if err := unpack.Start(); err != nil {
		return spec, err
	}
	if err := export.Run(); err != nil {
		_ = unpack.Wait()
		return spec, fmt.Errorf("docker export: %w: %s", err, bytes.TrimSpace(exportErr.Bytes()))
	}
	if err := unpack.Wait(); err != nil {
		return spec, fmt.Errorf("unpack image: %w: %s", err, bytes.TrimSpace(unpackErr.Bytes()))
	}
	return spec, nil
}

// addInit puts carrel-fn-init, its mount points and the image's command
// under /.fn. The image's own files are not changed.
func addInit(tree, initPath string, spec guestSpec) error {
	for _, dir := range []string{"rw", "newroot", "old"} {
		if err := os.MkdirAll(filepath.Join(tree, ".fn", dir), 0o755); err != nil {
			return err
		}
	}
	source, err := os.Open(initPath)
	if err != nil {
		return err
	}
	defer source.Close()
	target, err := os.OpenFile(filepath.Join(tree, ".fn", "init"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(target, source); err != nil {
		target.Close()
		return err
	}
	if err := target.Close(); err != nil {
		return err
	}
	content, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(tree, ".fn", "spec.json"), content, 0o644)
}

// makeExt4 writes tree into a new ext4 image with a fifth of headroom.
func makeExt4(ctx context.Context, tree, image string) error {
	usage, err := output(ctx, "du", "-sm", tree)
	if err != nil {
		return err
	}
	var megabytes int
	if _, err := fmt.Sscan(usage, &megabytes); err != nil {
		return fmt.Errorf("du: %q", usage)
	}
	size := megabytes*12/10 + 50
	file, err := os.OpenFile(image, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := file.Truncate(int64(size) << 20); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	_, err = output(ctx, "mkfs.ext4", "-q", "-d", tree, image)
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
