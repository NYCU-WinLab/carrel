package carrel

import (
	"context"
	"strings"
	"testing"
)

// An admin clears a plugin fence only once the node shows no lock and no
// active task on the guest (#682).
func TestUnfenceReadsTheNodeFirst(t *testing.T) {
	p, b := fixture(t)
	runQueue(p)
	seedMachine(p, "web", 10100)
	m := p.Store.Get("machines", "10100")
	m["plugin_fence"] = "op-1"
	p.Store.Put("machines", 10100, 1, m)
	lock, tasks := "rollback", []D{{"upid": "UPID:carrel01:1:qmrollback:10100:root@pam!carrel-snapshot:", "type": "qmrollback", "user": "root@pam!carrel-snapshot", "pid": 7}}
	b.call = func(r D, _ string) (any, error) {
		switch r["op"] {
		case "status":
			return D{"status": "stopped", "lock": lock}, nil
		case "guest_tasks":
			return tasks, nil
		}
		return D{"status": "running"}, nil
	}
	ctx, admin := context.Background(), person("root", true)
	unfence := func(extra D) D {
		return p.Execute(ctx, "machine_unfence", merge(D{"tenant": "alice", "machine": "web", "confirm": "web"}, extra), admin)
	}
	fenced := func() bool { return p.Store.Get("machines", "10100")["plugin_fence"] == "op-1" }

	if f := failure(p.Execute(ctx, "machine_unfence", D{"tenant": "alice", "machine": "web", "confirm": "web"}, person("alice", false))); f["code"] != "forbidden" {
		t.Fatalf("a member: %s", encoded(f))
	}
	if f := failure(unfence(D{"confirm": "other"})); f["code"] != "invalid" || !fenced() {
		t.Fatalf("a wrong confirm: %s", encoded(f))
	}
	f := failure(unfence(nil))
	if f["code"] != "conflict" || len(dicts(f["active_tasks"])) != 1 || dicts(f["active_tasks"])[0]["pid"] != nil || !fenced() {
		t.Fatalf("an active task: %s", encoded(f))
	}
	tasks = nil
	f = failure(unfence(nil))
	if f["code"] != "conflict" || !strings.Contains(str(f["message"]), "qm unlock 10100 on carrel01") || !fenced() {
		t.Fatalf("a stale lock: %s", encoded(f))
	}
	lock = ""
	if r := unfence(D{"dry_run": true}); r["fenced"] != true || !fenced() {
		t.Fatalf("dry run: %s", encoded(r))
	}
	if r := unfence(nil); r["fenced"] != false || r["operation"] != "op-1" || p.Store.Get("machines", "10100")["plugin_fence"] != nil {
		t.Fatalf("unfence: %s", encoded(r))
	}
	if f := failure(unfence(nil)); f["code"] != "conflict" || f["message"] != "The machine is not fenced" {
		t.Fatalf("again: %s", encoded(f))
	}
}

// A fenced operation that runs again keeps its fence: its retry settles it.
func TestUnfenceRefusesWhileTheFencedOperationRuns(t *testing.T) {
	p, f, _ := withRewindPlugin(t, "running")
	f.mu.Lock()
	f.forget = true
	f.mu.Unlock()
	r := member(p, "disks_rewind", D{"machine": "web", "wait_seconds": 10})
	id := str(obj(r["operation"])["id"])
	op := p.Store.Get("operations", id)
	op["state"] = "running"
	p.Store.Put("operations", id, 1, op)
	if f := failure(p.Execute(context.Background(), "machine_unfence", D{"tenant": "alice", "machine": "web", "confirm": "web"}, person("root", true))); f["code"] != "conflict" || f["operation"] != id {
		t.Fatalf("a running fenced operation: %s", encoded(f))
	}
	if p.Store.Get("machines", "10100")["plugin_fence"] != id {
		t.Fatal("the fence went")
	}
}
