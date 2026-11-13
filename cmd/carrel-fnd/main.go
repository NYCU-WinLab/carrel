//go:build linux

// carrel-fnd runs on a function host (PLAN 7.11). `serve` routes requests to
// functions and wakes them from snapshots. `build` turns an image into a
// sleeping function.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/NYCU-WinLab/carrel/internal/fn"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "build":
		err = build(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		slog.Error(os.Args[1], "error", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: carrel-fnd serve|build [flags]")
	os.Exit(2)
}

type common struct {
	root, firecracker, jailer, kernel string
	uidBase, gid                      int
	uplink, block, rate               string
	initPath, dns                     string
	mtu                               int
}

func commonFlags(flags *flag.FlagSet) *common {
	c := &common{}
	flags.StringVar(&c.root, "root", "/var/lib/carrel-fn", "directory that holds every function")
	flags.StringVar(&c.firecracker, "firecracker", "/usr/local/bin/firecracker", "firecracker executable")
	flags.StringVar(&c.jailer, "jailer", "/usr/local/bin/jailer", "Firecracker jailer executable")
	flags.StringVar(&c.kernel, "kernel", "/var/lib/carrel-fn/vmlinux", "guest kernel, on the file system of -root")
	flags.IntVar(&c.uidBase, "uid-base", 300000, "first of the user IDs instances run as, one per slot")
	flags.IntVar(&c.gid, "gid", 300000, "group ID that reads function files")
	flags.StringVar(&c.uplink, "uplink", "", "the one interface functions leave through (default: the default route's)")
	flags.StringVar(&c.block, "block", "", "more addresses functions must not reach, comma separated: the site's protected public addresses")
	flags.StringVar(&c.rate, "rate", "", "what one instance may send, and receive, such as 100mbit (default 100mbit)")
	flags.StringVar(&c.initPath, "init", "/usr/local/lib/carrel-fn/carrel-fn-init", "carrel-fn-init binary, for builds")
	flags.IntVar(&c.mtu, "mtu", 1450, "largest packet the host's uplink carries (tenant networks run at 1450, PLAN 6.2)")
	flags.StringVar(&c.dns, "dns", "1.1.1.1,8.8.8.8", "public resolvers for functions, comma separated")
	return c
}

func list(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool { return r == ',' })
}

// buildVersion builds one version in a build slot of its own, so a build
// never takes a slot from the router and two builds never share a jail, a
// user or a network namespace.
// The caller holds the function's lock.
func (c *common) buildVersion(ctx context.Context, f fn.Function, image, imageTar string, activate bool, env []string) (fn.Function, error) {
	index, slot, err := buildSlot(c.root)
	if err != nil {
		return f, err
	}
	defer slot.Close()
	runtime, err := fn.NewFirecracker(c.config("cfnb", index, 1, firstBuildLink+index-firstBuildSlot, false))
	if err != nil {
		return f, err
	}
	defer runtime.Close()
	return runtime.Build(ctx, fn.BuildOptions{
		Function: f, Image: image, ImageTar: imageTar, Init: c.initPath, Root: c.root,
		MTU: c.mtu, DNS: list(c.dns), Blocked: list(c.block), Activate: activate, Env: env,
	})
}

// config places jails under the functions' directory: a jail holds hard
// links to function files, which need one file system.
func (c *common) config(prefix string, first, slots, egressFirst int, router bool) fn.Config {
	egress := fn.Egress{Uplink: c.uplink, Rate: c.rate, Blocked: list(c.block)}
	return fn.Config{
		Egress: egress, Router: router,
		Firecracker: c.firecracker, Jailer: c.jailer, Kernel: c.kernel,
		JailBase: filepath.Join(c.root, ".jail"),
		Prefix:   prefix, First: first, Slots: slots,
		UIDBase: c.uidBase, GID: c.gid,
		EgressFirst: egressFirst,
	}
}

func serve(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	c := commonFlags(flags)
	listen := flags.String("listen", "127.0.0.1:8090", "address the router listens on")
	slots := flags.Int("slots", 32, "instances that may be awake at once")
	control := flags.String("control", "", "control plane URL; with it the host builds and removes functions as the control plane asks")
	tokenFile := flags.String("token-file", "/etc/carrel-fn/token", "file that holds the host's token for -control")
	_ = flags.Parse(args)
	if *slots < 1 || *slots > maxSlots {
		return fmt.Errorf("-slots must be 1 to %d", maxSlots)
	}
	var token string
	if *control != "" {
		content, err := os.ReadFile(*tokenFile)
		if err != nil {
			return fmt.Errorf("-control needs the host's token: %w", err)
		}
		token = strings.TrimSpace(string(content))
		if token == "" {
			return fmt.Errorf("%s is empty", *tokenFile)
		}
	}

	// Two routers would hand out the same slots.
	held, err := lock(c.root, "serve")
	if err != nil {
		return fmt.Errorf("another carrel-fnd serve runs on %s: %w", c.root, err)
	}
	defer held.Close()
	runtime, err := fn.NewFirecracker(c.config("cfn", 0, *slots, 0, true))
	if err != nil {
		return err
	}
	router := fn.NewRouter(c.root, runtime)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	reaped := make(chan struct{})
	go func() {
		router.Run(ctx)
		close(reaped)
	}()
	agented := make(chan struct{})
	go func() {
		defer close(agented)
		if *control == "" {
			return
		}
		agent := &fn.Agent{
			Control: strings.TrimRight(*control, "/"), Token: token, Root: c.root,
			Client: &http.Client{Timeout: 2 * time.Minute},
			Build: func(ctx context.Context, f fn.Function, image string, env []string) error {
				_, err := c.buildVersion(ctx, f, image, "", false, env)
				return err
			},
			Lock:   c.lockFunction,
			Forget: router.Forget,
		}
		agent.Run(ctx)
	}()
	guarded := make(chan struct{})
	go func() {
		defer close(guarded)
		ticker := time.NewTicker(fn.GuardPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				runtime.Guard()
			case <-ctx.Done():
				return
			}
		}
	}()
	server := &http.Server{Addr: *listen, Handler: router, ReadHeaderTimeout: 10 * time.Second}
	drained := make(chan struct{})
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		close(drained)
	}()
	slog.Info("serving", "listen", *listen, "root", c.root, "slots", *slots)
	err = server.ListenAndServe()
	// ListenAndServe returns when the shutdown starts. Wait until requests
	// drained and instances stopped before the namespaces go away.
	if errors.Is(err, http.ErrServerClosed) {
		<-drained
	}
	stop()
	<-reaped
	<-guarded
	<-agented
	runtime.Close()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func build(args []string) error {
	flags := flag.NewFlagSet("build", flag.ExitOnError)
	c := commonFlags(flags)
	var f fn.Function
	flags.StringVar(&f.Name, "name", "", "function name")
	image := flags.String("image", "", "image reference in a registry, pulled without credentials")
	imageTar := flags.String("image-tar", "", "a tarball from `docker save`, read in place of -image")
	flags.IntVar(&f.Port, "port", 8080, "port the image serves HTTP on")
	flags.IntVar(&f.MemoryMB, "memory", 512, "guest memory in MiB")
	flags.StringVar(&f.Mode, "mode", fn.ModeReuse, "reuse or fresh")
	flags.IntVar(&f.IdleSeconds, "idle", 0, "seconds without a request before the instance stops")
	flags.IntVar(&f.TimeoutSeconds, "timeout", 0, "seconds one request may take")
	flags.IntVar(&f.MaxInstances, "max-instances", 0, "instances at once in fresh mode")
	flags.StringVar(&f.WakePath, "wake-path", "", "path called once after every wake")
	_ = flags.Parse(args)
	if !fn.ValidName(f.Name) || (*image == "") == (*imageTar == "") {
		return errors.New("build needs a valid -name and one of -image and -image-tar")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	start := time.Now()
	unlock, err := c.lockFunction(f.Name)
	if err != nil {
		return err
	}
	defer unlock()
	built, err := c.buildVersion(ctx, f, *image, *imageTar, true, nil)
	if err != nil {
		return err
	}
	slog.Info("built", "function", built.Name, "version", built.Version, "seconds", time.Since(start).Seconds())
	return nil
}

// buildSlots is how many builds may run on one host at once. Their slot
// numbers start above any router slot.
const (
	buildSlots     = 16
	firstBuildSlot = 100000
	// Links to the host are numbered below 16384. Routers use the low
	// numbers, builds the last 16.
	firstBuildLink = 16384 - buildSlots
	maxSlots       = firstBuildLink
)

// lockFunction takes a function's lock: one build or change of a function's
// files at a time, from the agent or the command line.
func (c *common) lockFunction(name string) (func(), error) {
	held, err := lock(c.root, "function-"+name)
	if err != nil {
		return nil, fmt.Errorf("function %s is being built: %w", name, err)
	}
	return func() { held.Close() }, nil
}

// lock takes an exclusive lock that lasts until the file is closed or the
// process ends. It fails at once when another process holds it.
func lock(root, name string) (*os.File, error) {
	dir := filepath.Join(root, ".lock")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

// buildSlot locks the first free build slot.
func buildSlot(root string) (int, *os.File, error) {
	for i := range buildSlots {
		if held, err := lock(root, "build-"+strconv.Itoa(i)); err == nil {
			return firstBuildSlot + i, held, nil
		}
	}
	return 0, nil, fmt.Errorf("%d builds already run on this host", buildSlots)
}
