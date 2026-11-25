package carrel

import (
	"context"
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
		reserve bool
	}{
		"running":             {D{"state": "running", "phase": "applying", "attempts": 1}, false},
		"succeeded":           {D{"state": "succeeded", "phase": "complete", "attempts": 1}, false},
		"retried":             {D{"state": "queued", "phase": "retry_queued", "attempts": 1}, false},
		"certificate":         {D{"state": "waiting", "phase": "waiting_for_certificate", "attempts": 1}, false},
		"prepared":            {D{"state": "waiting", "phase": "waiting_for_machine_operation", "attempts": 1, "prepared_result": D{}}, false},
		"changed":             {D{"state": "waiting", "phase": "waiting_for_machine_operation", "attempts": 1, "resource_changes": true}, false},
		"holds a reservation": {D{"state": "waiting", "phase": "waiting_for_import_slot", "attempts": 1}, true},
	} {
		t.Run(name, func(t *testing.T) {
			p, _ := fixture(t)
			op := merge(D{"id": "job", "tenant_n": 1, "tool": "machine_create", "args": D{}, "who": alice, "resource_changes": false}, c.op)
			p.Store.Put("operations", "job", 1, op)
			if c.reserve {
				m := seedMachine(p, "dev", 10100)
				m["operation_id"] = "job"
				p.Store.Put("machines", 10100, 1, m)
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
	p.Store.Put("operations", "job", 1, D{"id": "job", "tenant_n": 1, "tool": "image_import", "args": D{}, "who": alice, "state": "waiting", "phase": "waiting_for_import_slot", "attempts": 1, "resource_changes": false, "ready_at": now() + 30})
	r := p.Execute(context.Background(), "operation_cancel", D{"id": "job"}, alice)
	assertOK(t, r)
	if got := p.Store.Get("operations", "job"); got["state"] != "failed" || got["ready_at"] != nil || got["cancelled_by"] != "alice" {
		t.Fatal(encoded(got))
	}
	// Another tenant cannot see it, let alone cancel it.
	assertCode(t, p.Execute(context.Background(), "operation_cancel", D{"id": "job"}, person("bob", false)), "not_found")
}
