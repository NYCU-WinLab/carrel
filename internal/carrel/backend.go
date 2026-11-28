package carrel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

type Backend interface {
	Call(context.Context, D, string) (any, error)
}
type SSHBackend struct{ Config string }
type operationLogKey struct{}

// levelUnlessStopping demotes a failure to INFO once ctx is cancelled: a
// process that is shutting down cancels its own work, and that is not an
// incident for the telemetry sink.
func levelUnlessStopping(ctx context.Context, level slog.Level) slog.Level {
	if ctx.Err() != nil {
		return slog.LevelInfo
	}
	return level
}

func (b *SSHBackend) Call(ctx context.Context, request D, target string) (any, error) {
	if target == "" {
		target = "carrel-node"
	}
	timeout := callTimeout(request, target)
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now()
	// Keepalives notice a node that stopped answering within 45 seconds.
	cmd := exec.CommandContext(ctx, "ssh", "-F", b.Config,
		"-o", "ControlMaster=auto", "-o", "ControlPersist=120",
		"-o", "ControlPath=/var/lib/carrel/ssh-%C",
		"-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3", target)
	cmd.Stdin = bytes.NewReader(encoded(request))
	out := cappedBuffer{max: maxAdapterReply}
	cmd.Stdout = &out
	err := cmd.Run()
	return adapterReply(parent, ctx, request, target, started, out.buf.Bytes(), err)
}

// adapterReply turns what node-agent.py printed into a result or a Failure,
// the same way for every transport. ctx is the call's own context: once it
// is done the call timed out. failed is the transport's error, such as a
// process that exited non-zero or an agent that lost the job.
func adapterReply(parent, ctx context.Context, request D, target string, started time.Time, out []byte, failed error) (any, error) {
	var result D
	if json.Unmarshal(out, &result) != nil || failed != nil || !boolean(result["ok"]) {
		code := "adapter_rejected"
		if ctx.Err() != nil {
			code = "adapter_timeout"
		} else if failed != nil {
			code = "adapter_process_failed"
		}
		if contains([]string{"invalid_request", "command_failed", "command_timeout", "adapter_internal", "storage_unavailable",
			// Plugin jobs (#660): kept, so a caller can tell ask again from no.
			"plugin_unavailable", "plugin_refused", "plugin_error", "not_found", "invalid", "conflict"}, result["error_code"]) {
			code = str(result["error_code"])
		}
		details := D{"code": "backend_unavailable", "message": "Infrastructure action failed; use the operation ID for operator diagnostics", "component": "node_adapter", "backend_code": code, "action": fallback(request, "action", request["op"]), "operation": ctx.Value(operationLogKey{}), "request_id": request["request_id"], "recovery": "retry_infrastructure"}
		// The adapter's own error text stays in the operator log.
		slog.Log(parent, levelUnlessStopping(parent, slog.LevelError), "adapter_failed", "event", "adapter_failed", "component", target, "backend_code", code, "detail", truncate(str(result["error"]), 400), "action", details["action"], "operation", details["operation"], "request_id", details["request_id"], "seconds", time.Since(started).Seconds())
		return nil, Failure{D{"ok": false, "error": details}}
	}
	slog.Info("adapter_completed", "event", "adapter_completed", "op", request["op"], "target", target,
		"operation", ctx.Value(operationLogKey{}), "seconds", time.Since(started).Seconds())
	return result["result"], nil
}

// maxAdapterReply bounds what one adapter or the gateway can make the control
// plane hold; the largest real reply (an inventory) is far smaller.
const maxAdapterReply = 32 << 20

// A named field, not an embedded one: an embedded bytes.Buffer brings its
// ReadFrom, and io.Copy from the process pipe would use it past the cap.
type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.max {
		return 0, errors.New("adapter reply too large")
	}
	return b.buf.Write(p)
}

const jumpTarget = "carrel-jump"

// jumpTimeout bounds every request to the jump host. A variable so tests can shorten it.
var jumpTimeout = 30 * time.Second

// callTimeout bounds one call, whatever carries it.
func callTimeout(request D, target string) time.Duration {
	if target == jumpTarget {
		// The jump helper only writes two small files; a hung jump host must
		// not hold jumpMu for the node-sized timeouts.
		return jumpTimeout
	}
	if request["op"] == "create" && obj(request["machine"])["import_volume"] != nil {
		// Hashing and importing up to 20 GB over NFS (PLAN 7.8).
		return 3 * time.Hour
	}
	return adapterTimeout(str(request["op"]))
}

// adapterTimeout bounds one adapter request. Reads and the backup's node files
// are quick; a reconcile can wait for an SDN reload; creation clones disks.
func adapterTimeout(op string) time.Duration {
	switch op {
	case "inventory", "guest_memory", "status", "metrics", "node_files", "storage_usage", "cloud_init_read", "disk_volume", "vmids_present", "guest_tasks":
		return 60 * time.Second
	case "reconcile":
		return 300 * time.Second
	case "plugin":
		// A plugin answers within its own 5 second call limit (#660).
		return 30 * time.Second
	case "migrate", "migrate_finish", "import_finish", "fetch_store", "freeze", "thaw", "backup_remove":
		// A disk copy at the migration bandwidth limit (PLAN 7.10).
		return 4 * time.Hour
	case "sync":
		// gateway-sync.py runs up to 3 commands of 60 seconds each.
		return 240 * time.Second
	}
	return 900 * time.Second
}

// Only observational responses use this cache. Admission bypasses it entirely.
// Every caller gets an independent JSON value and its original observation time.
type observation struct {
	Value any
	At    time.Time
	Epoch uint64
}
type ObservationCache struct {
	mu    sync.Mutex
	item  observation
	epoch uint64
	group singleflight.Group
}

func (c *ObservationCache) Invalidate() {
	c.mu.Lock()
	c.epoch++
	c.item = observation{}
	c.mu.Unlock()
}
func (c *ObservationCache) Get(ctx context.Context, ttl time.Duration, fetch func(context.Context) (any, error)) (any, time.Time, error) {
	c.mu.Lock()
	v := c.item
	epoch := c.epoch
	c.mu.Unlock()
	if v.Value != nil && time.Since(v.At) < ttl {
		return copyValue(v.Value), v.At, nil
	}
	ch := c.group.DoChan(fmt.Sprint(epoch), func() (any, error) {
		value, e := fetch(ctx)
		if e != nil {
			return nil, e
		}
		o := observation{value, time.Now(), epoch}
		c.mu.Lock()
		if c.epoch == epoch {
			c.item = o
		}
		c.mu.Unlock()
		return o, nil
	})
	select {
	case <-ctx.Done():
		return nil, time.Time{}, ctx.Err()
	case r := <-ch:
		if r.Err != nil {
			return nil, time.Time{}, r.Err
		}
		o := r.Val.(observation)
		return copyValue(o.Value), o.At, nil
	}
}
func copyValue(v any) any { var o any; must(json.Unmarshal(encoded(v), &o)); return o }
