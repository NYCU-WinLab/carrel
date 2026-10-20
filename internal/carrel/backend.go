package carrel

import (
	"bytes"
	"context"
	"encoding/json"
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

func (b *SSHBackend) Call(ctx context.Context, request D, target string) (any, error) {
	if target == "" {
		target = "carrel-node"
	}
	ctx, cancel := context.WithTimeout(ctx, adapterTimeout(str(request["op"])))
	defer cancel()
	started := time.Now()
	// Keepalives notice a node that stopped answering within 45 seconds.
	cmd := exec.CommandContext(ctx, "ssh", "-F", b.Config,
		"-o", "ControlMaster=auto", "-o", "ControlPersist=120",
		"-o", "ControlPath=/var/lib/carrel/ssh-%C",
		"-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3", target)
	cmd.Stdin = bytes.NewReader(encoded(request))
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	var result D
	if json.Unmarshal(out.Bytes(), &result) != nil || err != nil || !boolean(result["ok"]) {
		code := "adapter_rejected"
		if ctx.Err() != nil {
			code = "adapter_timeout"
		} else if err != nil {
			code = "adapter_process_failed"
		}
		if contains([]string{"invalid_request", "command_failed", "command_timeout", "adapter_internal"}, result["error_code"]) {
			code = str(result["error_code"])
		}
		details := D{"code": "backend_unavailable", "message": "Infrastructure action failed; use the operation ID for operator diagnostics", "component": target, "backend_code": code, "action": fallback(request, "action", request["op"]), "operation": ctx.Value(operationLogKey{}), "request_id": request["request_id"], "recovery": "retry_infrastructure"}
		slog.Error("adapter_failed", "event", "adapter_failed", "component", target, "backend_code", code, "action", details["action"], "operation", details["operation"], "request_id", details["request_id"], "seconds", time.Since(started).Seconds())
		return nil, Failure{D{"ok": false, "error": details}}
	}
	slog.Info("adapter_completed", "event", "adapter_completed", "op", request["op"], "target", target,
		"operation", ctx.Value(operationLogKey{}), "seconds", time.Since(started).Seconds())
	return result["result"], nil
}

// adapterTimeout bounds one adapter request. Reads and the backup's node files
// are quick; a reconcile can wait for an SDN reload; creation clones disks.
func adapterTimeout(op string) time.Duration {
	switch op {
	case "inventory", "status", "metrics", "node_files", "storage_usage":
		return 60 * time.Second
	case "reconcile":
		return 300 * time.Second
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
