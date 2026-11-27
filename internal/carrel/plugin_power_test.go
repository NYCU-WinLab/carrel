package carrel

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

func rewindPlugin() []PluginInfo {
	return []PluginInfo{{Name: "disks", Version: "1.0.0", Contract: 1, Supported: true, Operations: []PluginOperation{
		{Name: "rewind", Member: true, Stopped: true, Rewinds: true, Params: json.RawMessage(`{"type":"object","properties":{"machine":{"type":"string"}},"required":["machine"]}`)},
	}}}
}

// guest is a node's view of one guest's power: it records every power call
// and, after a start, reports a new boot a little later.
type guest struct {
	mu                          sync.Mutex
	power                       string
	calls                       []string
	refuseStart, ignoreShutdown int
	boots                       int
}

func (g *guest) seen() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string{}, g.calls...)
}

func withRewindPlugin(t *testing.T, power string) (*Platform, *fakePlugins, *guest) {
	t.Helper()
	p, b := fixture(t)
	f := withPlugin(t, p, b)
	pluginPatience = 100 * time.Millisecond
	t.Cleanup(func() { pluginPatience = 10 * time.Minute })
	g := &guest{power: power}
	b.call = func(r D, target string) (any, error) {
		switch r["op"] {
		case "inventory":
			return baseInventory(), nil
		case "status":
			g.mu.Lock()
			defer g.mu.Unlock()
			g.calls = append(g.calls, "status")
			if g.power == "paused" {
				return D{"status": "running", "qmpstatus": "paused"}, nil
			}
			return D{"status": g.power}, nil
		case "action":
			g.mu.Lock()
			defer g.mu.Unlock()
			action := str(r["action"])
			g.calls = append(g.calls, action)
			switch action {
			case "shutdown":
				if g.ignoreShutdown > 0 {
					g.ignoreShutdown--
					return D{"power_state": g.power}, nil
				}
				g.power = "stopped"
			case "start":
				if g.refuseStart > 0 {
					g.refuseStart--
					return D{"power_state": "stopped"}, nil
				}
				g.power = "running"
				g.boots++
				boot := fmt.Sprintf("boot-%d", g.boots)
				go func() {
					time.Sleep(200 * time.Millisecond)
					p.Store.Put("guest_reports", 10100, 1, D{"vmid": 10100, "boot_id": boot, "reported_at": now(), "initialization_status": "complete", "application_status": "not_checked"})
					p.notifyReport(10100)
				}()
			}
			return D{"power_state": g.power, "changed": true}, nil
		case "plugin":
			g.mu.Lock()
			if r["call"] == "start" {
				g.calls = append(g.calls, "plugin:"+str(obj(r["machine"])["power_state"]))
			}
			g.mu.Unlock()
		}
		return f.call(r, target)
	}
	p.sshProbe = func(context.Context, D) bool { return true }
	reportPlugins(p, rewindPlugin())
	runQueue(p)
	m := seedMachine(p, "web", 10100)
	m["power_state"] = power
	if power == "stopped" {
		m["state"] = "stopped"
	}
	p.Store.Put("machines", 10100, 1, m)
	p.Store.Put("guest_reports", 10100, 1, D{"vmid": 10100, "boot_id": "old", "reported_at": now(), "initialization_status": "complete", "application_status": "not_checked"})
	return p, f, g
}

func pluginStarts(calls []string) int {
	n := 0
	for _, c := range calls {
		if c == "plugin:stopped" || c == "plugin:running" || c == "plugin:ready" {
			n++
		}
	}
	return n
}

// A running guest is shut down before the plugin starts, started again once
// the run ended, and is ready only on a report from the new boot.
func TestAStoppingPluginOperationStopsAndRestores(t *testing.T) {
	p, f, g := withRewindPlugin(t, "running")
	r := member(p, "disks_rewind", D{"machine": "web", "dry_run": true})
	if r["downtime_expected"] != true || len(g.seen()) != 0 {
		t.Fatalf("dry run: %s, calls %v", encoded(r), g.seen())
	}
	r = member(p, "disks_rewind", D{"machine": "web", "wait_seconds": 10})
	op := obj(r["operation"])
	result := obj(op["result"])
	if op["state"] != "succeeded" || result["power_state"] != "running" || result["power_state_restored"] != true || obj(result["machine"])["state"] != "ready" {
		t.Fatalf("rewind: %s", encoded(r))
	}
	if want := []string{"status", "shutdown", "plugin:stopped", "start"}; !equal(g.seen(), want) {
		t.Fatalf("calls %v, want %v", g.seen(), want)
	}
	if start := f.starts[0]; start["operation_spec"] == "" || obj(start["machine"])["configuration"] == nil {
		t.Fatalf("the plugin got %v", start)
	}

	// A guest that was stopped stays stopped.
	p2, _, g2 := withRewindPlugin(t, "stopped")
	r = member(p2, "disks_rewind", D{"machine": "web", "wait_seconds": 10})
	if obj(r["operation"])["state"] != "succeeded" || obj(obj(r["operation"])["result"])["power_state"] != "stopped" {
		t.Fatalf("stopped: %s", encoded(r))
	}
	if want := []string{"status", "plugin:stopped"}; !equal(g2.seen(), want) {
		t.Fatalf("calls %v, want %v", g2.seen(), want)
	}

	// A paused guest is refused before anything changes.
	p3, _, g3 := withRewindPlugin(t, "paused")
	if r := member(p3, "disks_rewind", D{"machine": "web", "wait_seconds": 10}); failure(r)["code"] != "conflict" || len(g3.seen()) != 1 {
		t.Fatalf("paused: %s, calls %v", encoded(r), g3.seen())
	}
}

// A refused start never began, so the guest comes back. A run whose fate is
// unknown leaves it stopped, and a retry finishes the run and restores it.
func TestAStoppedGuestComesBackOnlyOnceTheRunEnded(t *testing.T) {
	p, f, g := withRewindPlugin(t, "running")
	f.mu.Lock()
	f.fail = "plugin_refused"
	f.mu.Unlock()
	r := member(p, "disks_rewind", D{"machine": "web", "wait_seconds": 10})
	if obj(r["operation"])["state"] != "failed" || g.seen()[len(g.seen())-1] != "start" {
		t.Fatalf("refused: %s, calls %v", encoded(r), g.seen())
	}
	// The retry is a new run: it stops the guest again.
	f.mu.Lock()
	f.fail = ""
	f.mu.Unlock()
	first := str(obj(r["operation"])["id"])
	p.Operations.Retry(p.Store.TenantN(1), first, person("alice", false))
	awaitState(t, p, first, "succeeded")
	if want := []string{"status", "shutdown", "plugin:stopped", "start", "status", "shutdown", "plugin:stopped", "start"}; !equal(g.seen(), want) {
		t.Fatalf("calls %v, want %v", g.seen(), want)
	}

	p2, f2, g2 := withRewindPlugin(t, "running")
	f2.mu.Lock()
	f2.fail = "plugin_unavailable"
	f2.mu.Unlock()
	r = member(p2, "disks_rewind", D{"machine": "web", "wait_seconds": 10})
	id := str(obj(r["operation"])["id"])
	if failure(r)["machine_left_stopped"] != true || g2.seen()[len(g2.seen())-1] == "start" {
		t.Fatalf("unknown fate: %s, calls %v", encoded(r), g2.seen())
	}
	// Fenced: nothing starts the guest while the plugin may still write.
	if r := member(p2, "machine_power", D{"machine": "web", "action": "start", "wait_seconds": 5}); failure(r)["code"] != "conflict" {
		t.Fatalf("a start on a fenced machine: %s", encoded(r))
	}
	f2.mu.Lock()
	f2.fail = ""
	f2.mu.Unlock()
	p2.Operations.Retry(p2.Store.TenantN(1), id, person("alice", false))
	op := awaitState(t, p2, id, "succeeded")
	calls := g2.seen()
	if calls[len(calls)-1] != "start" || obj(op["plugin"])["key"] != id+"-1" {
		t.Fatalf("retry: calls %v, op %s", calls, encoded(op["plugin"]))
	}
	if p2.Store.Get("machines", "10100")["plugin_fence"] != nil {
		t.Fatal("the fence outlived the run")
	}
}

// A run that succeeded is never repeated: when the guest does not come back,
// a retry only starts it again.
func TestARetryAfterSuccessOnlyRestoresPower(t *testing.T) {
	p, _, g := withRewindPlugin(t, "running")
	g.mu.Lock()
	g.refuseStart = 1
	g.mu.Unlock()
	r := member(p, "disks_rewind", D{"machine": "web", "wait_seconds": 10})
	id := str(obj(r["operation"])["id"])
	if failure(r)["code"] != "conflict" {
		t.Fatalf("first: %s", encoded(r))
	}
	p.Operations.Retry(p.Store.TenantN(1), id, person("alice", false))
	awaitState(t, p, id, "succeeded")
	calls := g.seen()
	if pluginStarts(calls) != 1 || calls[len(calls)-1] != "start" {
		t.Fatalf("calls %v", calls)
	}
}

// A guest that ignored the shutdown is still running: the retry stops it
// again before the plugin starts, and the result says what it is.
func TestARetryAfterAnIgnoredShutdownStopsAgain(t *testing.T) {
	p, _, g := withRewindPlugin(t, "running")
	g.mu.Lock()
	g.ignoreShutdown = 1
	g.mu.Unlock()
	r := member(p, "disks_rewind", D{"machine": "web", "wait_seconds": 10})
	id := str(obj(r["operation"])["id"])
	if failure(r)["code"] != "conflict" || pluginStarts(g.seen()) != 0 {
		t.Fatalf("ignored shutdown: %s, calls %v", encoded(r), g.seen())
	}
	p.Operations.Retry(p.Store.TenantN(1), id, person("alice", false))
	op := awaitState(t, p, id, "succeeded")
	g.mu.Lock()
	power := g.power
	g.mu.Unlock()
	calls := g.seen()
	if power != "running" || obj(op["result"])["power_state"] != "running" || calls[len(calls)-3] != "shutdown" || calls[len(calls)-2] != "plugin:stopped" {
		t.Fatalf("power %s, calls %v, result %s", power, calls, encoded(op["result"]))
	}
}

// A rewind that does not stop the guest is not a tool.
func TestARewindMustStopTheGuest(t *testing.T) {
	p, b := fixture(t)
	withPlugin(t, p, b)
	bad := rewindPlugin()
	bad[0].Operations[0].Stopped = false
	reportPlugins(p, bad)
	if _, left := p.pluginRegistry(); left["disks_rewind"] != "an operation that rewinds the disk must also declare stopped" {
		t.Fatalf("left out: %v", left)
	}
}
