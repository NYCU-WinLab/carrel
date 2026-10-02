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
	ctx, cancel := context.WithTimeout(ctx, 900*time.Second)
	defer cancel()
	started := time.Now()
	cmd := exec.CommandContext(ctx, "ssh", "-F", b.Config,
		"-o", "ControlMaster=auto", "-o", "ControlPersist=120",
		"-o", "ControlPath=/var/lib/carrel/ssh-%C", target)
	cmd.Stdin = bytes.NewReader(encoded(request))
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	var result D
	if json.Unmarshal(out.Bytes(), &result) != nil || err != nil || !boolean(result["ok"]) {
		return nil, fmt.Errorf("node operation failed; allocation retained for repair")
	}
	slog.Info("adapter_completed", "event", "adapter_completed", "op", request["op"], "target", target,
		"operation", ctx.Value(operationLogKey{}), "seconds", time.Since(started).Seconds())
	return result["result"], nil
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
