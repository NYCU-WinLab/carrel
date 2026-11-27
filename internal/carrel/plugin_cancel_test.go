package carrel

import (
	"context"
	"strings"
	"testing"
	"time"
)

// operation_cancel on a running plugin operation sends cancel with the
// operation's key, and the poll loop ends it failed with code cancelled.
func TestCancelStopsARunningPluginOperation(t *testing.T) {
	p, b := fixture(t)
	f := withPlugin(t, p, b)
	f.hold = true
	runQueue(p)
	seedMachine(p, "web", 10100)
	op := obj(member(p, "backup_take", D{"machine": "web", "wait_seconds": 0})["operation"])
	id := str(op["id"])
	awaitStarted(t, f)
	// A dry run sends nothing.
	assertOK(t, member(p, "operation_cancel", D{"id": id, "dry_run": true}))
	f.mu.Lock()
	n := len(f.cancels)
	f.mu.Unlock()
	if n != 0 {
		t.Fatal("dry run sent cancel")
	}
	assertOK(t, member(p, "operation_cancel", D{"id": id}))
	awaitState(t, p, id, "failed")
	got := p.Store.Get("operations", id)
	if obj(got["error"])["code"] != "cancelled" {
		t.Fatal(encoded(got))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.cancels) != 1 || f.cancels[0]["idempotency_key"] != f.starts[0]["idempotency_key"] {
		t.Fatalf("cancels: %v", f.cancels)
	}
}

// A plugin that refuses leaves the operation running; the call is a conflict.
func TestCancelRefusedByThePluginLeavesItRunning(t *testing.T) {
	p, b := fixture(t)
	f := withPlugin(t, p, b)
	f.hold, f.refuseCancel = true, true
	runQueue(p)
	seedMachine(p, "web", 10100)
	id := str(obj(member(p, "backup_take", D{"machine": "web", "wait_seconds": 0})["operation"])["id"])
	awaitStarted(t, f)
	if code := str(failure(member(p, "operation_cancel", D{"id": id}))["code"]); code != "conflict" {
		t.Fatalf("code %s", code)
	}
	if st := p.Store.Get("operations", id)["state"]; st != "running" {
		t.Fatalf("state %v", st)
	}
	f.mu.Lock()
	f.hold, f.refuseCancel = false, false
	f.mu.Unlock()
	awaitState(t, p, id, "succeeded")
}

// A plugin that answers cancel with a run still going, as the snapshot
// plugin does, did not cancel it: the call is a conflict naming the state,
// and the operation runs on to its own end.
func TestCancelAnsweredRunningIsAConflict(t *testing.T) {
	p, b := fixture(t)
	f := withPlugin(t, p, b)
	f.hold, f.cancelAnswer = true, "running"
	runQueue(p)
	seedMachine(p, "web", 10100)
	id := str(obj(member(p, "backup_take", D{"machine": "web", "wait_seconds": 0})["operation"])["id"])
	awaitStarted(t, f)
	e := failure(member(p, "operation_cancel", D{"id": id}))
	if e["code"] != "conflict" || !strings.Contains(str(e["message"]), "did not cancel the operation; it is running") {
		t.Fatal(encoded(e))
	}
	if st := p.Store.Get("operations", id)["state"]; st != "running" {
		t.Fatalf("state %v", st)
	}
	f.mu.Lock()
	f.hold = false
	f.mu.Unlock()
	awaitState(t, p, id, "succeeded")
}

// A run that ended before the cancel reached it is returned as it is: the
// call is a conflict, and the operation ends as the run did.
func TestCancelOfARunThatAlreadySucceededIsAConflict(t *testing.T) {
	p, b := fixture(t)
	f := withPlugin(t, p, b)
	f.hold, f.cancelAnswer = true, "succeeded"
	runQueue(p)
	seedMachine(p, "web", 10100)
	id := str(obj(member(p, "backup_take", D{"machine": "web", "wait_seconds": 0})["operation"])["id"])
	awaitStarted(t, f)
	e := failure(member(p, "operation_cancel", D{"id": id}))
	if e["code"] != "conflict" || !strings.Contains(str(e["message"]), "it is succeeded") {
		t.Fatal(encoded(e))
	}
	awaitState(t, p, id, "succeeded")
}

// A member cannot cancel a running admin plugin operation.
func TestCancelRunningAdminPluginOperationNeedsAnAdmin(t *testing.T) {
	p, b := fixture(t)
	f := withPlugin(t, p, b)
	f.hold = true
	runQueue(p)
	id := str(obj(p.Execute(context.Background(), "backup_prune", D{"keep": 2, "wait_seconds": 0}, person("alice", true))["operation"])["id"])
	awaitStarted(t, f)
	if code := str(failure(member(p, "operation_cancel", D{"id": id}))["code"]); code != "forbidden" {
		t.Fatalf("code %s", code)
	}
	assertOK(t, p.Execute(context.Background(), "operation_cancel", D{"id": id}, person("alice", true)))
	awaitState(t, p, id, "failed")
}

func awaitStarted(t *testing.T, f *fakePlugins) {
	t.Helper()
	for i := 0; i < 400; i++ {
		f.mu.Lock()
		n := len(f.starts)
		f.mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("plugin never started")
}
