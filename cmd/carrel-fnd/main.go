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
	root, firecracker, kernel, run string
}

func commonFlags(flags *flag.FlagSet) *common {
	c := &common{}
	flags.StringVar(&c.root, "root", "/var/lib/carrel-fn", "directory that holds every function")
	flags.StringVar(&c.firecracker, "firecracker", "/usr/local/bin/firecracker", "firecracker executable")
	flags.StringVar(&c.kernel, "kernel", "/var/lib/carrel-fn/vmlinux", "guest kernel")
	flags.StringVar(&c.run, "run", "/run/carrel-fn", "directory for API sockets")
	return c
}

func serve(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	c := commonFlags(flags)
	listen := flags.String("listen", "127.0.0.1:8090", "address the router listens on")
	slots := flags.Int("slots", 32, "instances that may be awake at once")
	_ = flags.Parse(args)

	runtime, err := fn.NewFirecracker(c.firecracker, c.kernel, c.run, "cfn", *slots)
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
	server := &http.Server{Addr: *listen, Handler: router, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	slog.Info("serving", "listen", *listen, "root", c.root, "slots", *slots)
	err = server.ListenAndServe()
	<-reaped
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
	image := flags.String("image", "", "Docker image on this host")
	initPath := flags.String("init", "/usr/local/lib/carrel-fn/carrel-fn-init", "carrel-fn-init binary")
	flags.IntVar(&f.Port, "port", 8080, "port the image serves HTTP on")
	flags.IntVar(&f.MemoryMB, "memory", 512, "guest memory in MiB")
	flags.StringVar(&f.Mode, "mode", fn.ModeReuse, "reuse or fresh")
	flags.IntVar(&f.IdleSeconds, "idle", 0, "seconds without a request before the instance stops")
	flags.IntVar(&f.TimeoutSeconds, "timeout", 0, "seconds one request may take")
	flags.IntVar(&f.MaxInstances, "max-instances", 0, "instances at once in fresh mode")
	flags.StringVar(&f.WakePath, "wake-path", "", "path called once after every wake")
	_ = flags.Parse(args)
	if f.Name == "" || *image == "" {
		return errors.New("build needs -name and -image")
	}

	// One namespace of its own, so a build never takes a slot from the router.
	runtime, err := fn.NewFirecracker(c.firecracker, c.kernel, c.run, "cfnbuild-"+f.Name+"-", 1)
	if err != nil {
		return err
	}
	defer runtime.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	start := time.Now()
	built, err := runtime.Build(ctx, fn.BuildOptions{Function: f, Image: *image, Init: *initPath, Root: c.root})
	if err != nil {
		return err
	}
	slog.Info("built", "function", built.Name, "version", built.Version, "seconds", time.Since(start).Seconds())
	return nil
}
