package main

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/NYCU-WinLab/carrel/internal/carrel"
)

func main() {
	configFile := flag.String("config", "/etc/carrel/config.json", "Control plane configuration")
	listen := flag.String("listen", ":8080", "HTTP listen address")
	version := flag.Bool("version", false, "Print version")
	backup := flag.Bool("backup", false, "Create a consistent backup and send it to the backup target")
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if *version {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"version": carrel.Version})
		return
	}
	content, err := os.ReadFile(*configFile)
	if err != nil {
		slog.Error("read configuration", "error", err)
		os.Exit(1)
	}
	cfg, err := carrel.LoadConfig(content)
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	store, err := carrel.OpenStore(cfg.Database)
	if err != nil {
		slog.Error("open database", "error", err)
		os.Exit(1)
	}
	defer store.DB.Close()
	if unplaced := carrel.UnplacedMachines(store, cfg); len(unplaced) > 0 {
		slog.Error("machines without a configured node", "machines", unplaced)
		os.Exit(1)
	}
	backend := &carrel.SSHBackend{Config: "/etc/carrel/ssh_config"}
	if cfg.SSHConfig != "" {
		backend.Config = cfg.SSHConfig
	}
	platform := carrel.NewPlatform(store, backend, cfg)
	if *backup {
		result, err := platform.Backup(context.Background(), filepath.Dir(*configFile))
		if err != nil {
			slog.Error("backup_failed", "error", err)
			os.Exit(1)
		}
		if result["missing_nodes"] != nil {
			// The archive landed, but some node files are not in it.
			slog.Warn("backup_complete_without_nodes", "result", result)
		} else {
			slog.Info("backup_complete", "result", result)
		}
		return
	}
	app := carrel.NewApp(platform, nil)
	server := &http.Server{Addr: *listen, Handler: app, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 16}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	platform.Start()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	slog.Info("carrel_started", "version", carrel.Version)
	if err = server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("http_server_failed", "error", err)
		stop()
	}
	platform.Close()
}
