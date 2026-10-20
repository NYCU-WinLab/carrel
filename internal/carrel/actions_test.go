package carrel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestPowerWaitsAndReturnsObservedMachine(t *testing.T) {
	for _, action := range []string{"shutdown", "stop", "pause"} {
		t.Run(action, func(t *testing.T) {
			p, b := fixture(t)
			seedMachine(p, "dev", 10100)
			before := p.execution(context.Background()).Quota(p.Store.TenantN(1))
			state := "stopped"
			if action == "pause" {
				state = "paused"
			}
			b.call = func(r D, _ string) (any, error) {
				if r["op"] != "action" || r["action"] != action {
					return nil, errors.New("unexpected backend call")
				}
				return D{"power_state": state, "changed": true}, nil
			}
			runQueue(p)
			r := NewApp(p, nil).Call(context.Background(), "machine_power", D{"machine": "dev", "action": action}, person("alice", false))
			assertOK(t, r)
			op := obj(r["operation"])
			result := obj(op["result"])
			m := obj(result["machine"])
			if op["state"] != "succeeded" || m["state"] != state || boolean(m["ssh_ready"]) || result["quota_released"] != false {
				t.Fatalf("unconfirmed power result: %s", encoded(r))
			}
			if b.count("action") != 1 || b.count("inventory") != 0 || b.count("reconcile") != 0 {
				t.Fatal("unnecessary infrastructure calls")
			}
			if !equal(p.execution(context.Background()).Quota(p.Store.TenantN(1)), before) || len(p.Store.Objects("machines")) != 1 {
				t.Fatal("power operation removed the allocation")
			}
		})
	}
}

func TestRestartRequiresFreshBootAndResumesCheckpoint(t *testing.T) {
	for _, action := range []string{"start", "reboot", "resume"} {
		t.Run(action, func(t *testing.T) {
			p, b := fixture(t)
			m := seedMachine(p, "dev", 10100)
			m["state"] = "stopped"
			p.Store.Put("machines", 10100, 1, m)
			p.Store.Put("guest_reports", 10100, 1, D{"boot_id": "old", "reported_at": now(), "initialization_status": "complete", "application_status": "not_checked"})
			b.call = func(r D, _ string) (any, error) {
				return D{"power_state": "running", "changed": true, "boot_changed": action != "resume"}, nil
			}
			p.sshProbe = func(context.Context, D) bool { return true }
			runQueue(p)
			who := person("alice", false)
			r := p.Execute(context.Background(), "machine_power", D{"machine": "dev", "action": action, "wait_seconds": 0}, who)
			assertOK(t, r)
			id := str(obj(r["operation"])["id"])
			if action != "resume" {
				op := awaitState(t, p, id, "waiting_for_guest")
				if obj(op["power_restore"])["boot_id"] != "old" || p.Store.Get("machines", "10100")["state"] == "ready" {
					t.Fatal("old boot report accepted after restart")
				}
				p.Store.Put("guest_reports", 10100, 1, D{"boot_id": "new", "reported_at": now(), "initialization_status": "complete", "application_status": "not_checked"})
				p.notifyReport(10100)
			}
			op := awaitState(t, p, id, "succeeded")
			if obj(obj(op["result"])["machine"])["state"] != "ready" || b.count("action") != 1 {
				t.Fatal("startup not ready or action replayed")
			}
		})
	}
}

func TestNoopStartStillChecksReadinessWithoutRequiringNewBoot(t *testing.T) {
	p, b := fixture(t)
	seedMachine(p, "dev", 10100)
	p.Store.Put("guest_reports", 10100, 1, D{"boot_id": "same", "reported_at": now(), "initialization_status": "complete", "application_status": "not_checked"})
	p.sshProbe = func(context.Context, D) bool { return true }
	b.call = func(D, string) (any, error) {
		return D{"power_state": "running", "changed": false, "boot_changed": false}, nil
	}
	runQueue(p)
	r := p.Execute(context.Background(), "machine_power", D{"machine": "dev", "action": "start"}, person("alice", false))
	op := obj(r["operation"])
	if op["state"] != "succeeded" || op["resource_changes"] != false || obj(obj(op["result"])["machine"])["state"] != "ready" {
		t.Fatalf("no-op start failed: %s", encoded(r))
	}
}

func TestRebootRetryRejectsIntermediateBootReport(t *testing.T) {
	p, b := fixture(t)
	seedMachine(p, "dev", 10100)
	p.Store.Put("guest_reports", 10100, 1, D{"boot_id": "intermediate", "reported_at": now(), "initialization_status": "complete", "application_status": "not_checked"})
	p.sshProbe = func(context.Context, D) bool { return true }
	b.call = func(D, string) (any, error) {
		return D{"power_state": "running", "changed": true, "boot_changed": true}, nil
	}
	op := D{"id": "reboot-retry", "tenant_n": 1, "tool": "machine_power", "args": D{"machine": "dev", "action": "reboot"}, "who": person("alice", false), "state": "failed", "power_restore": D{"boot_id": "original"}}
	p.Operations.Save(op)
	runQueue(p)
	r := p.Execute(context.Background(), "operation_retry", D{"id": "reboot-retry", "wait_seconds": 0}, person("alice", false))
	assertOK(t, r)
	awaitState(t, p, "reboot-retry", "waiting_for_guest")
	if p.Store.Get("machines", "10100")["state"] == "ready" {
		t.Fatal("intermediate boot report satisfied another reboot")
	}
	p.Store.Put("guest_reports", 10100, 1, D{"boot_id": "final", "reported_at": now(), "initialization_status": "complete", "application_status": "not_checked"})
	p.notifyReport(10100)
	awaitState(t, p, "reboot-retry", "succeeded")
}

func TestPowerFailureAndUnsupportedCTDoNotClaimSuccess(t *testing.T) {
	for _, kind := range []string{"vm", "ct"} {
		p, b := fixture(t)
		m := seedMachine(p, "dev", 10100)
		m["kind"] = kind
		p.Store.Put("machines", 10100, 1, m)
		b.call = func(D, string) (any, error) { return D{"power_state": "running"}, nil }
		runQueue(p)
		r := NewApp(p, nil).Call(context.Background(), "machine_power", D{"machine": "dev", "action": "pause"}, person("alice", false))
		op := obj(r["operation"])
		if op["state"] != "failed" || op["error"] == nil || p.Store.Get("machines", "10100")["state"] != "ready" {
			t.Fatalf("failure hidden: %s", encoded(r))
		}
		if kind == "ct" && b.count("action") != 0 {
			t.Fatal("unsupported CT pause reached hypervisor")
		}
	}
}

func TestLiveStatusDoesNotConfusePausedProcessWithReadyGuest(t *testing.T) {
	p, b := fixture(t)
	m := seedMachine(p, "dev", 10100)
	m["ssh_ready"], m["power_state"] = true, "running"
	p.Store.Put("machines", 10100, 1, m)
	b.call = func(D, string) (any, error) { return D{"status": "running", "qmpstatus": "paused", "uptime": 99}, nil }
	r := NewApp(p, nil).Call(context.Background(), "machine_get", D{"machine": "dev"}, person("alice", false))
	assertOK(t, r)
	got := dicts(r["machines"])[0]
	if got["state"] != "paused" || got["power_state"] != "paused" || boolean(obj(got["readiness"])["ssh_ready"]) {
		t.Fatal("paused process reported as ready")
	}
	if b.count("status") != 1 || b.count("inventory") != 0 {
		t.Fatal("status did not use one targeted observation")
	}
}

func TestPausedRollbackCannotDestroyInMemorySession(t *testing.T) {
	p, b := fixture(t)
	m := seedMachine(p, "dev", 10100)
	p.Store.Put("snapshots", "10100-before", 1, D{"id": "10100-before", "vmid": 10100, "name": "before", "disk_gb": 20, "configuration": pick(m, "cpu", "memory_mb", "disk_gb", "nics")})
	b.call = func(D, string) (any, error) { return D{"status": "running", "qmpstatus": "paused"}, nil }
	runQueue(p)
	r := p.Execute(context.Background(), "snapshot_rollback", D{"machine": "dev", "name": "before", "confirm": "before"}, person("alice", false))
	op := obj(r["operation"])
	if op["state"] != "failed" || obj(op["error"])["code"] != "conflict" || b.count("action") != 0 {
		t.Fatal("paused memory was discarded by rollback")
	}
}

func TestSummaryPreservesFullDurableResultAndIdempotency(t *testing.T) {
	p, _ := fixture(t)
	m := seedMachine(p, "dev", 10100)
	e := p.execution(context.Background())
	op := D{"id": "done", "tenant_n": 1, "tool": "machine_create", "state": "succeeded", "created_at": 100.25, "updated_at": 128.536, "result": mutationResult(e.Quota(p.Store.TenantN(1)), D{"ok": true, "machine": e.PublicMachine(m, nil)}, false)}
	p.Store.Put("operations", "done", 1, op)
	app := NewApp(p, nil)
	args := D{"id": "done"}
	summary := app.Call(context.Background(), "operation_get", args, person("alice", false))
	full := app.Call(context.Background(), "operation_get", merge(args, D{"detail": "full"}), person("alice", false))
	retried := app.Call(context.Background(), "operation_retry", args, person("alice", false))
	if retried["quota_before"] != nil || retried["quota_after"] != nil || retried["dry_run"] != nil || obj(retried["operation"])["state"] != "succeeded" {
		t.Fatal("successful retry leaked outer accounting into summary")
	}
	small := dicts(summary["operations"])[0]
	if num(small["duration_seconds"]) != 28.286 || obj(small["result"])["quota_after"] != nil || obj(dicts(full["operations"])[0]["result"])["quota_after"] == nil {
		t.Fatalf("summary damaged full result: %s", encoded(summary))
	}
	if len(encoded(summary)) >= len(encoded(full))/2 {
		t.Fatal("summary did not reduce response by at least half")
	}
	for _, state := range []string{"queued", "waiting", "failed", "rolled_back", "cleanup_failed"} {
		complex := merge(op, D{"state": state, "error": D{"code": "conflict"}, "cleanup": D{"remaining": []any{"dev"}}})
		if !equal(operationSummary(complex), complex) {
			t.Fatal("recovery evidence omitted")
		}
	}
	preview := app.Call(context.Background(), "machine_create", D{"name": "planned", "dry_run": true}, person("alice", false))
	if preview["quota_before"] == nil || !strings.Contains(string(encoded(preview)), "ssh_public_key") {
		t.Fatal("preview requirements or accounting omitted")
	}
	a := D{"name": "other", "idempotency_key": "same-request", "wait_seconds": 0}
	one := app.Call(context.Background(), "machine_create", a, person("alice", false))
	two := app.Call(context.Background(), "machine_create", merge(a, D{"detail": "full"}), person("alice", false))
	if obj(one["operation"])["id"] != obj(two["operation"])["id"] {
		t.Fatal("presentation changed request identity")
	}
}

func TestAQuotaRefusalNamesTheSameDimensionEveryTime(t *testing.T) {
	p, _ := fixture(t)
	e := p.execution(context.Background())
	for range 20 {
		f, _ := attempt(func() { e.Quota(p.Store.TenantN(1), D{"vcpu": 100, "memory_mb": 1 << 30, "disk_gb": 1 << 20}) }).(Failure)
		err := obj(f.Result["error"])
		if err["dimension"] != "disk_gb" || len(arr(err["violations"])) != 3 || fmt.Sprint(obj(err["quota_after"])["over_limit"]) != "[disk_gb memory_mb vcpu]" {
			t.Fatal(err)
		}
	}
}
