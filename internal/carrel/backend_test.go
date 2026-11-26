package carrel

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdapterFailureIsBoundedAndCorrelated(t *testing.T) {
	dir := t.TempDir()
	must(os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/sh\nprintf '%s' '{\"ok\":false,\"error_code\":\"command_failed\",\"error\":\"secret-node-output\"}'\nexit 1\n"), 0700))
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	b := &SSHBackend{Config: "unused"}
	ctx := context.WithValue(context.Background(), operationLogKey{}, "op-test")
	_, err := b.Call(ctx, D{"op": "action", "action": "resize", "request_id": "receipt-test"}, "carrel-node")
	if err == nil {
		t.Fatal("failed backend accepted")
	}
	result := failureResult(err)
	detail := obj(result["error"])
	if detail["code"] != "backend_unavailable" || detail["backend_code"] != "command_failed" || detail["operation"] != "op-test" || detail["request_id"] != "receipt-test" || strings.Contains(string(encoded(result)), "secret-node-output") {
		t.Fatalf("unsafe or unhelpful adapter failure: %s", encoded(result))
	}
}

func TestShutdownCancellationLogsBelowWarn(t *testing.T) {
	live, cancelled := context.Background(), func() context.Context {
		c, cancel := context.WithCancel(context.Background())
		cancel()
		return c
	}()
	if levelUnlessStopping(live, slog.LevelError) != slog.LevelError || levelUnlessStopping(live, slog.LevelWarn) != slog.LevelWarn {
		t.Fatal("live context must keep its level")
	}
	if levelUnlessStopping(cancelled, slog.LevelError) != slog.LevelInfo || levelUnlessStopping(cancelled, slog.LevelWarn) != slog.LevelInfo {
		t.Fatal("cancelled context must log at INFO")
	}
}

func TestAHungJumpHostCallReturnsAfterTheShortJumpTimeout(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/sh\nexec sleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	old := jumpTimeout
	jumpTimeout = 200 * time.Millisecond
	defer func() { jumpTimeout = old }()
	started := time.Now()
	_, err := (&SSHBackend{Config: "/dev/null"}).Call(context.Background(), D{"op": "certs"}, jumpTarget)
	if err == nil {
		t.Fatal("a hung jump call must fail")
	}
	if time.Since(started) > 5*time.Second {
		t.Fatalf("jump call took %s", time.Since(started))
	}
}

// A plugin job's error code reaches the caller, so it can tell ask again
// (plugin_unavailable) from no.
func TestPluginErrorCodesReachTheCaller(t *testing.T) {
	for _, code := range []string{"plugin_unavailable", "plugin_refused", "plugin_error", "not_found", "invalid", "conflict"} {
		dir := t.TempDir()
		must(os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/sh\nprintf '%s' '{\"ok\":false,\"error_code\":\""+code+"\",\"error\":\"x\"}'\nexit 1\n"), 0700))
		t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
		_, err := (&SSHBackend{Config: "unused"}).Call(context.Background(), D{"op": "plugin", "plugin": "snapshot"}, "carrel-node")
		if detail := obj(failureResult(err)["error"]); detail["backend_code"] != code {
			t.Fatalf("%s: %v", code, detail)
		}
	}
}
