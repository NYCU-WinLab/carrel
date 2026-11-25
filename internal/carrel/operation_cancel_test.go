package carrel

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A queued operation that is cancelled ends failed with code cancelled, and
// the worker that picks it up afterwards does not run it (#584).
func TestCancelStopsAQueuedOperationBeforeItRuns(t *testing.T) {
	p, b := fixture(t)
	seedMachine(p, "dev", 10100)
	var calls atomic.Int32
	b.call = func(D, string) (any, error) {
		calls.Add(1)
		return D{"power_state": "running", "changed": true, "boot_changed": true}, nil
	}
	alice := person("alice", false)
	submitted := p.Execute(context.Background(), "machine_power", D{"machine": "dev", "action": "reboot", "wait_seconds": 0}, alice)
	assertOK(t, submitted)
	id := str(obj(submitted["operation"])["id"])

	preview := p.Execute(context.Background(), "operation_cancel", D{"id": id, "dry_run": true}, alice)
	assertOK(t, preview)
	if p.Store.Get("operations", id)["state"] != "queued" {
		t.Fatal("dry run cancelled the operation")
	}
	r := p.Execute(context.Background(), "operation_cancel", D{"id": id}, alice)
	assertOK(t, r)
	op := obj(r["operation"])
	if op["state"] != "failed" || op["done"] != true || obj(op["error"])["code"] != "cancelled" || op["next_action"] != "operation_retry" {
		t.Fatal(encoded(op))
	}
	runQueue(p)
	time.Sleep(200 * time.Millisecond)
	if calls.Load() != 0 || p.Store.Get("operations", id)["phase"] != "cancelled" {
		t.Fatalf("cancelled operation ran: %d calls, %s", calls.Load(), encoded(p.Store.Get("operations", id)))
	}
	// operation_retry runs it as submitted.
	assertOK(t, p.Execute(context.Background(), "operation_retry", D{"id": id, "wait_seconds": 0}, alice))
	awaitState(t, p, id, "waiting_for_guest")
	if calls.Load() == 0 {
		t.Fatal("retry did not run the operation")
	}
}

func TestCancelRefusesAnOperationThatMayHaveChangedSomething(t *testing.T) {
	alice := person("alice", false)
	for name, c := range map[string]struct {
		op      D
		reserve string
	}{
		"running":              {D{"state": "running", "phase": "applying", "attempts": 1, "dispatched": true}, ""},
		"succeeded":            {D{"state": "succeeded", "phase": "complete", "attempts": 1, "dispatched": true}, ""},
		"retried":              {D{"state": "queued", "phase": "retry_queued", "attempts": 1, "dispatched": true}, ""},
		"certificate":          {D{"state": "waiting", "phase": "waiting_for_certificate", "attempts": 1, "dispatched": false}, ""},
		"prepared":             {D{"state": "waiting", "phase": "waiting_for_machine_operation", "attempts": 1, "dispatched": false, "prepared_result": D{}}, ""},
		"changed":              {D{"state": "waiting", "phase": "waiting_for_machine_operation", "attempts": 1, "dispatched": false, "resource_changes": true}, ""},
		"dispatched before":    {D{"state": "waiting", "phase": "waiting_for_priority_operation", "attempts": 2, "dispatched": true}, ""},
		"from before the flag": {D{"state": "waiting", "phase": "waiting_for_priority_operation", "attempts": 1}, ""},
		"holds a machine":      {D{"state": "waiting", "phase": "waiting_for_import_slot", "attempts": 1, "dispatched": false}, "machines"},
		"holds an image":       {D{"state": "waiting", "phase": "waiting_for_import_slot", "attempts": 1, "dispatched": false}, "images"},
	} {
		t.Run(name, func(t *testing.T) {
			p, _ := fixture(t)
			op := merge(D{"id": "job", "tenant_n": 1, "tool": "machine_create", "args": D{}, "who": alice, "resource_changes": false}, c.op)
			p.Store.Put("operations", "job", 1, op)
			switch c.reserve {
			case "machines":
				m := seedMachine(p, "dev", 10100)
				m["operation_id"] = "job"
				p.Store.Put("machines", 10100, 1, m)
			case "images":
				p.Store.Put("images", "img", 1, D{"id": "img", "tenant_n": 1, "state": "importing", "operation_id": "job"})
			}
			r := p.Execute(context.Background(), "operation_cancel", D{"id": "job"}, alice)
			assertCode(t, r, "conflict")
			if !strings.Contains(str(obj(r["error"])["message"]), str(c.op["state"])) {
				t.Fatal(encoded(r))
			}
			if got := p.Store.Get("operations", "job"); got["state"] != c.op["state"] {
				t.Fatal(encoded(got))
			}
		})
	}
}

func TestCancelEndsAJobWaitingItsTurn(t *testing.T) {
	p, _ := fixture(t)
	alice := person("alice", false)
	p.Store.Put("operations", "job", 1, D{"id": "job", "tenant_n": 1, "tool": "image_import", "args": D{}, "who": alice, "state": "waiting", "phase": "waiting_for_import_slot", "attempts": 1, "dispatched": false, "resource_changes": false, "ready_at": now() + 30})
	r := p.Execute(context.Background(), "operation_cancel", D{"id": "job"}, alice)
	assertOK(t, r)
	if got := p.Store.Get("operations", "job"); got["state"] != "failed" || got["ready_at"] != nil || got["cancelled_by"] != "alice" {
		t.Fatal(encoded(got))
	}
	// Another tenant cannot see it, let alone cancel it.
	assertCode(t, p.Execute(context.Background(), "operation_cancel", D{"id": "job"}, person("bob", false)), "not_found")
}

// The flag follows the job: a wait raised before the tool runs keeps it
// false, and an attempt that reached the tool sets it for good.
func TestDispatchedMarksAJobThatReachedItsTool(t *testing.T) {
	p, b := fixture(t)
	seedMachine(p, "dev", 10100)
	alice := person("alice", false)
	// Another job of higher priority makes this one wait before it runs.
	p.Store.Put("operations", "suspend", 2, D{"id": "suspend", "tenant_n": 2, "tool": "tenant_suspend", "state": "running", "phase": "applying"})
	r := p.Execute(context.Background(), "machine_power", D{"machine": "dev", "action": "reboot", "wait_seconds": 0}, alice)
	id := str(obj(r["operation"])["id"])
	runQueue(p)
	op := awaitState(t, p, id, "waiting_for_priority_operation")
	if op["dispatched"] != false {
		t.Fatal(encoded(op))
	}
	// The other job ends; this one now fails inside the tool.
	p.Store.Remove("operations", "suspend")
	b.call = func(D, string) (any, error) { return nil, errors.New("node down") }
	op = awaitState(t, p, id, "failed")
	if op["dispatched"] != true {
		t.Fatal(encoded(op))
	}
}
