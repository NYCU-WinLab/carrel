package carrel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
)

// The control socket lets a one-shot run of the same binary ask the serving
// process to do the work, because only the serving process reaches the node
// agents (#606). The nightly `carrel -backup` sends its backup here, so the
// files of a node on the agent transport are kept like any other node's. The
// socket is a file of the carrel user, mode 0600, beside the database.

// ControlSocket is the socket's path for a configuration.
func ControlSocket(c Config) string {
	return filepath.Join(filepath.Dir(c.Database), "control.sock")
}

// ControlHandler serves the control socket.
func (p *Platform) ControlHandler(configDir string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /backup", func(w http.ResponseWriter, r *http.Request) {
		result, err := p.Backup(r.Context(), configDir)
		if err != nil {
			jsonResponse(w, 500, D{"ok": false, "error": err.Error()})
			return
		}
		jsonResponse(w, 200, D{"ok": true, "result": result})
	})
	return mux
}

// ServeControl listens on path until ctx ends. A socket file nobody answers
// on was left by a process that did not stop cleanly and is replaced; one
// that answers belongs to another carrel and is left alone. At the end the
// file is removed only while it is still this server's.
func ServeControl(ctx context.Context, path string, handler http.Handler) error {
	if c, err := net.Dial("unix", path); err == nil {
		c.Close()
		return errors.New("another carrel serves " + path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	unix := listener.(*net.UnixListener)
	unix.SetUnlinkOnClose(false)
	mine, err := os.Lstat(path)
	if err == nil {
		err = os.Chmod(path, 0o600)
	}
	if err != nil {
		listener.Close()
		return err
	}
	server := &http.Server{Handler: handler}
	go func() {
		<-ctx.Done()
		_ = server.Close()
		if now, err := os.Lstat(path); err == nil && os.SameFile(now, mine) {
			_ = os.Remove(path)
		}
	}()
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			slog.Error("control_socket_failed", "error", err)
		}
	}()
	return nil
}

// ErrNoServer means no serving process answered: none was running, or it
// stopped before it answered. The caller makes the backup itself. A second
// archive on the same day replaces the first (backup-target.py), so running
// again after a lost answer is safe.
var ErrNoServer = errors.New("the serving process did not answer")

// RequestBackup asks the serving process for a backup and waits for it.
func RequestBackup(ctx context.Context, path string) (D, error) {
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://carrel/backup", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoServer, err)
	}
	defer resp.Body.Close()
	var answer struct {
		OK     bool   `json:"ok"`
		Result D      `json:"result"`
		Error  string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&answer); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrNoServer, resp.Status)
	}
	if !answer.OK {
		return nil, errors.New(answer.Error)
	}
	return answer.Result, nil
}
