package carrel

import (
	"context"
	"testing"
)

func TestCurrentObservationDoesNotReusePriorBootOrProbeLists(t *testing.T) {
	p, b := fixture(t)
	m := seedMachine(p, "db", 10100)
	m["power_state"], m["ssh_ready"], m["ssh_checked_at"] = "running", true, now()
	p.Store.Put("machines", 10100, 1, m)
	p.Store.Put("guest_reports", 10100, 1, D{"reported_at": now() - 30, "initialization_status": "complete", "application_status": "healthy"})
	probes := 0
	p.sshProbe = func(context.Context, D) bool { probes++; return true }
	b.call = func(D, string) (any, error) { return D{"status": "running", "uptime": 2}, nil }
	app, ctx, who := NewApp(p, nil), context.Background(), person("alice", false)
	app.Call(ctx, "machine_list", D{}, who)
	if probes != 0 || b.count("status") != 0 {
		t.Fatal("list performed per-machine observations")
	}
	r := app.Call(ctx, "machine_get", D{"machine": "db"}, who)
	assertOK(t, r)
	got := dicts(r["machines"])[0]
	if probes != 1 || got["state"] == "ready" || got["ssh_ready"] != true || obj(got["readiness"])["freshness"] != "previous_boot" {
		t.Fatalf("power or SSH confused with application readiness: %s", encoded(got))
	}
}

func TestLivePowerObservationPreservesApplicationWarmup(t *testing.T) {
	p, _ := fixture(t)
	m := seedMachine(p, "warming", 10100)
	m["state"] = "initializing"
	p.Store.Put("machines", 10100, 1, m)
	p.Store.Put("guest_reports", 10100, 1, D{"reported_at": now(), "initialization_status": "complete", "application_status": "failed"})
	p.sshProbe = func(context.Context, D) bool { return true }
	r := NewApp(p, nil).Call(context.Background(), "machine_get", D{"machine": "warming"}, person("alice", false))
	assertOK(t, r)
	got := dicts(r["machines"])[0]
	if got["state"] != "initializing" || got["power_state"] != "running" || got["ssh_ready"] != true {
		t.Fatalf("status ended the operation's warm-up window: %s", encoded(r))
	}
}

func TestRunningNICRequiresReportedInterface(t *testing.T) {
	p, b := fixture(t)
	seedMachine(p, "db", 10100)
	network := p.execution(context.Background()).NetworkSpec(p.Store.TenantN(1), D{"name": "private"}, nil)
	p.Store.Put("networks", network["id"], 1, network)
	b.call = func(r D, _ string) (any, error) { return D{"status": "running"}, nil }
	p.sshProbe = func(context.Context, D) bool { return true }
	oldNIC := p.execution(context.Background()).NICSpec(p.Store.Get("machines", "10100"), network, 1)
	p.Store.Put("guest_reports", 10100, 1, D{"reported_at": now() - 1, "initialization_status": "complete", "application_status": "not_checked", "interfaces": []D{pick(oldNIC, "ip", "mac", "mtu")}})
	runQueue(p)
	result := p.Execute(context.Background(), "machine_nic_attach", D{"machine": "db", "network": "private", "wait_seconds": 0}, person("alice", false))
	id := str(obj(result["operation"])["id"])
	awaitState(t, p, id, "waiting_for_guest")
	m := p.Store.Get("machines", "10100")
	if m["state"] != "initializing" {
		t.Fatal("NIC complete before guest interface report")
	}
	nic := dicts(m["nics"])[0]
	p.Store.Put("guest_reports", 10100, 1, D{"reported_at": now(), "initialization_status": "complete", "application_status": "not_checked", "interfaces": []D{pick(nic, "ip", "mac", "mtu")}})
	p.notifyReport(10100)
	op := awaitState(t, p, id, "succeeded")
	if obj(obj(op["result"])["machine"])["network_verification"] != "verified" {
		t.Fatal("interface completion missing")
	}
}

func TestResizePreservesAllocationAndExplainsGuestFollowup(t *testing.T) {
	p, _ := fixture(t)
	m := seedMachine(p, "db", 10100)
	runQueue(p)
	r := NewApp(p, nil).Call(context.Background(), "machine_resize", D{"machine": "db", "disk_gb": 30}, person("alice", false))
	op := obj(r["operation"])
	got := obj(obj(op["result"])["machine"])
	if op["state"] != "succeeded" || num(got["disk_gb"]) != 30 || obj(got["resize"])["guest_filesystem"] != "unverified" || obj(got["resize"])["owner_action"] == nil || !equal(machineIdentity(m), machineIdentity(p.Store.Get("machines", "10100"))) {
		t.Fatalf("resize claimed unverified guest success: %s", encoded(r))
	}
}
