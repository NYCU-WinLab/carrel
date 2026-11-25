package carrel

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The nightly backup goes through the serving process, so the files of a
// node on the agent transport come from its agent, not over SSH (#606).
func TestBackupThroughTheControlSocketReachesAgents(t *testing.T) {
	p, b := fixture(t)
	root := t.TempDir()
	config := filepath.Join(root, "etc")
	must(os.MkdirAll(config, 0o700))
	p.Config.Database = filepath.Join(root, "state.db")
	p.Config.CertificateDir = filepath.Join(root, "certificates")
	for _, name := range []string{"config.json", "node_key", "node_key.pub", "ssh_config", "known_hosts"} {
		must(os.WriteFile(filepath.Join(config, name), []byte("fixture"), 0o600))
	}
	p.Config.Nodes[0].Transport = "agent"
	p.UseAgents()
	sent := false
	b.call = func(r D, target string) (any, error) {
		if r["op"] == "node_files" {
			t.Error("node_files for an agent node went over SSH")
		}
		if r["op"] == "backup" && target == "carrel-backup" {
			sent = true
			return D{"stored": true}, nil
		}
		return nil, Failure{D{"ok": false, "error": D{"code": "invalid"}}}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The agent of carrel01 answers node_files.
	go func() {
		for seq := uint64(1); ctx.Err() == nil; seq++ {
			for _, j := range p.Hub.Claim(ctx, "carrel01", "s", seq, nil, time.Second) {
				out := `{"ok":true,"result":{"node":"carrel01","files":{"node.json":"{}"}}}`
				p.Hub.Complete("carrel01", j.ID, []byte(out), false)
			}
		}
	}()
	socket := filepath.Join(root, "control.sock")
	must(ServeControl(ctx, socket, p.ControlHandler(config)))
	if info, err := os.Stat(socket); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", info, err)
	}
	result, err := RequestBackup(context.Background(), socket)
	if err != nil || !sent || result["stored"] != true || result["missing_nodes"] != nil {
		t.Fatalf("%v %v", err, encoded(result))
	}
	// A failed backup is reported as a failure, not as a missing server, so
	// the caller does not run a second one.
	b.call = func(D, string) (any, error) {
		return nil, Failure{D{"ok": false, "error": D{"code": "backend_unavailable"}}}
	}
	if _, err := RequestBackup(context.Background(), socket); err == nil || errors.Is(err, ErrNoServer) {
		t.Fatalf("failed backup: %v", err)
	}
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socket); errors.Is(err, os.ErrNotExist) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := RequestBackup(context.Background(), socket); !errors.Is(err, ErrNoServer) {
		t.Fatalf("stopped server: %v", err)
	}
}

// A socket file left by a process that did not stop cleanly means no server,
// and the next server replaces it.
func TestControlSocketLeftBehind(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "control.sock")
	must(os.WriteFile(socket, nil, 0o600))
	if _, err := RequestBackup(context.Background(), socket); !errors.Is(err, ErrNoServer) {
		t.Fatalf("stale socket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, _ := fixture(t)
	must(ServeControl(ctx, socket, p.ControlHandler(t.TempDir())))
	if info, err := os.Stat(socket); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("not replaced: %v %v", info, err)
	}
}

// A second server leaves a live socket alone, and a server that stops removes
// the file only while it is its own.
func TestControlSocketBelongsToItsServer(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "control.sock")
	answer := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			jsonResponse(w, 200, D{"ok": true, "result": D{"server": name}})
		})
	}
	first, stopFirst := context.WithCancel(context.Background())
	defer stopFirst()
	must(ServeControl(first, socket, answer("first")))
	if err := ServeControl(context.Background(), socket, answer("second")); err == nil {
		t.Fatal("a second server took a live socket")
	}
	if r, err := RequestBackup(context.Background(), socket); err != nil || r["server"] != "first" {
		t.Fatalf("%v %v", r, err)
	}
	// The first server's file is moved away and a new server takes the path;
	// the first one stopping leaves the new file.
	must(os.Rename(socket, filepath.Join(dir, "old.sock")))
	second, stopSecond := context.WithCancel(context.Background())
	defer stopSecond()
	must(ServeControl(second, socket, answer("second")))
	stopFirst()
	time.Sleep(100 * time.Millisecond)
	if r, err := RequestBackup(context.Background(), socket); err != nil || r["server"] != "second" {
		t.Fatalf("%v %v", r, err)
	}
}

// A server that stops before it answers counts as no server, so the timer
// makes the backup itself.
func TestControlSocketLostAnswer(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "control.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	must(ServeControl(ctx, socket, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		c, _, err := w.(http.Hijacker).Hijack()
		must(err)
		c.Close()
	})))
	if _, err := RequestBackup(context.Background(), socket); !errors.Is(err, ErrNoServer) {
		t.Fatalf("lost answer: %v", err)
	}
}
