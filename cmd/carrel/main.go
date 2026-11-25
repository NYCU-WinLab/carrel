package main

import (
	"context"
	"crypto/tls"
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
	reseal := flag.Bool("reseal-function-values", false, "Seal stored function values again with function_env_key and print how many each key opened")
	dryRun := flag.Bool("dry-run", false, "With -reseal-function-values: only count, change nothing")
	flag.Parse()
	stderr := slog.NewJSONHandler(os.Stderr, nil)
	slog.SetDefault(slog.New(stderr))
	if *version {
		_ = json.NewEncoder(os.Stdout).Encode(carrel.Build())
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
	// From here WARN and ERROR records also go to the collector, when the
	// configuration names one. Close sends what is queued before any exit.
	telemetry := carrel.NewTelemetry(cfg, stderr)
	slog.SetDefault(slog.New(telemetry.Handler(stderr)))
	fatal := func() {
		telemetry.Close()
		os.Exit(1)
	}
	store, err := carrel.OpenStore(cfg.Database)
	if err != nil {
		slog.Error("open database", "error", err)
		fatal()
	}
	defer store.DB.Close()
	if unplaced := carrel.UnplacedMachines(store, cfg); len(unplaced) > 0 {
		slog.Error("machines without a configured node", "machines", unplaced)
		fatal()
	}
	backend := &carrel.SSHBackend{Config: "/etc/carrel/ssh_config"}
	if cfg.SSHConfig != "" {
		backend.Config = cfg.SSHConfig
	}
	platform := carrel.NewPlatform(store, backend, cfg)
	platform.Telemetry = telemetry
	if *reseal {
		result, err := platform.ResealFunctionValues(*dryRun)
		if err != nil {
			slog.Error("reseal_failed", "error", err)
			fatal()
		}
		_ = json.NewEncoder(os.Stdout).Encode(result)
		telemetry.Close()
		return
	}
	if *backup {
		result, err := platform.Backup(context.Background(), filepath.Dir(*configFile))
		if err != nil {
			slog.Error("backup_failed", "error", err)
			fatal()
		}
		if result["missing_nodes"] != nil {
			// The archive landed, but some node files are not in it.
			slog.Warn("backup_complete_without_nodes", "result", result)
		} else {
			slog.Info("backup_complete", "result", result)
		}
		telemetry.Close()
		return
	}
	platform.UseAgents()
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
	if cfg.AgentListen != "" {
		// Node agents (PLAN 8.6): their own TLS listener, never the gateway.
		agents := &http.Server{Addr: cfg.AgentListen, Handler: platform.AgentHandler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 16,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
		go func() {
			<-ctx.Done()
			_ = agents.Close()
		}()
		go func() {
			if err := agents.ListenAndServeTLS(cfg.AgentCertFile, cfg.AgentKeyFile); err != nil && err != http.ErrServerClosed {
				slog.Error("agent_listener_failed", "error", err)
				stop()
			}
		}()
	}
	slog.Info("carrel_started", "build", carrel.Build())
	if err = server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("http_server_failed", "error", err)
		stop()
	}
	platform.Close()
	telemetry.Close()
}
