package carrel

// Regression coverage for the member-intent scope audit.

import (
	"context"
	"testing"
	"time"
)

func auditEvidence(t *testing.T, finding string, evidence D) {
	t.Helper()
	t.Logf("AUDIT %s", encoded(merge(D{"finding": finding}, evidence)))
}

func TestScopeActionableSummary(t *testing.T) {
	p, _ := fixture(t)
	m := seedMachine(p, "db", 10100)
	m["network_access"] = "restricted"
	m["nics"] = []D{{"index": 1, "network": "p00101", "ip": "10.64.0.10"}}
	p.Store.Put("machines", 10100, 1, m)
	p.Store.Put("ports", "1-20010-tcp", 1, D{"id": "1-20010-tcp", "tenant_n": 1, "vmid": 10100, "ip": m["ip"], "port": 22, "public_port": 20010, "proto": "tcp"})
	app, who, ctx := NewApp(p, nil), person("alice", false), context.Background()
	summary := app.Call(ctx, "machine_get", D{"machine": "db"}, who)
	full := app.Call(ctx, "machine_get", D{"machine": "db", "detail": "full"}, who)
	s, f := dicts(summary["machines"])[0], dicts(full["machines"])[0]
	if s["ip"] == nil || s["access"] == nil || len(arr(s["nics"])) != 1 || f["ip"] == nil || f["access"] == nil || f["nics"] == nil {
		t.Fatal("corrected summary behavior changed")
	}
	ports := app.Call(ctx, "port_list", D{}, who)
	port := dicts(ports["ports"])[0]
	if port["machine"] != "db" || port["endpoint"] != "carrel.winlab.tw:20010" || port["vmid"] != nil {
		t.Fatal("corrected list behavior changed")
	}
	auditEvidence(t, "A1", D{"summary_private_ip": s["ip"], "summary_access": s["access"], "summary_nics": s["nics"], "full_has_all_three": true, "port_list_machine": port["machine"], "port_list_vmid": port["vmid"]})
}

func TestScopeStaleReadiness(t *testing.T) {
	for _, status := range []string{"stale_healthy", "current_failed"} {
		t.Run(status, func(t *testing.T) {
			p, b := fixture(t)
			m := seedMachine(p, "app", 10100)
			m["power_state"], m["ssh_ready"] = "running", true
			p.Store.Put("machines", 10100, 1, m)
			age, health := 1800.0, "healthy"
			if status == "current_failed" {
				age, health = 0, "failed"
			}
			p.Store.Put("guest_reports", 10100, 1, D{"reported_at": now() - age, "initialization_status": "complete", "application_status": health})
			b.call = func(D, string) (any, error) { return D{"status": "running", "qmpstatus": "running"}, nil }
			r := NewApp(p, nil).Call(context.Background(), "machine_get", D{"machine": "app"}, person("alice", false))
			assertOK(t, r)
			got := dicts(r["machines"])[0]
			want := "readiness_unknown"
			if status == "current_failed" {
				want = "needs_owner_fix"
			}
			if got["state"] != want || got["ssh_ready"] != false {
				t.Fatal("corrected status behavior changed")
			}
			auditEvidence(t, "A2", D{"scenario": status, "state": got["state"], "ssh_ready": got["ssh_ready"], "report_age_seconds": age, "application_status": obj(got["readiness"])["application_status"]})
		})
	}
}

func TestScopeOfflineNIC(t *testing.T) {
	for _, mode := range []string{"direct", "deployment"} {
		for _, state := range []string{"stopped", "paused"} {
			t.Run(mode+"_"+state, func(t *testing.T) {
				p, b := fixture(t)
				p.Config.GuestReadyTimeout = 1
				m := seedMachine(p, "offline", 10100)
				m["state"], m["power_state"], m["ssh_ready"] = state, state, false
				p.Store.Put("machines", 10100, 1, m)
				net := p.execution(context.Background()).NetworkSpec(p.Store.TenantN(1), D{"name": "private"}, nil)
				p.Store.Put("networks", net["id"], 1, net)
				b.call = func(r D, _ string) (any, error) {
					if r["op"] == "status" {
						return D{"power_state": state}, nil
					}
					return D{}, nil
				}
				runQueue(p)
				tool, args := "machine_nic_attach", D{"machine": "offline", "network": "private"}
				want := "succeeded"
				if mode == "deployment" {
					tool, args, want = "deployment_apply", D{"attachments": []D{{"machine": "offline", "network": "private"}}}, "succeeded"
				}
				r := p.Execute(context.Background(), tool, args, person("alice", false))
				op := obj(r["operation"])
				if op["state"] != want || op["error"] != nil {
					t.Fatalf("corrected NIC behavior changed: %s", encoded(r))
				}
				current := p.Store.Get("machines", "10100")
				if current["state"] != state || len(arr(current["nics"])) != 1 || b.count("status") != 1 {
					t.Fatalf("offline config changed power or lost NIC: %s", encoded(current))
				}
				for _, call := range b.calls {
					if call["action"] == "start" || call["action"] == "resume" {
						t.Fatal("implicit power action")
					}
				}
				auditEvidence(t, "A3", D{"tool": tool, "initial_power_state": state, "operation_state": op["state"], "error": obj(op["error"])["code"], "recorded_state": current["state"], "remaining_nics": len(arr(current["nics"])), "status_queries": b.count("status"), "timeout_shortened_to_seconds": 1})
			})
		}
	}
}

func TestScopeApplicationWarmup(t *testing.T) {
	for _, healthy := range []bool{true, false} {
		t.Run(str(healthy), func(t *testing.T) {
			p, b := fixture(t)
			p.Config.ApplicationReadyTimeout = 1
			b.call = func(r D, _ string) (any, error) {
				if r["op"] == "inventory" {
					return baseInventory(), nil
				}
				if r["op"] == "create" {
					m := obj(r["machine"])
					p.Store.Put("guest_reports", m["vmid"], 1, D{"reported_at": now(), "initialization_status": "complete", "application_status": "failed", "checks": []D{{"index": 0, "status": "failed"}}})
				}
				return D{}, nil
			}
			probes := 0
			p.sshProbe = func(_ context.Context, m D) bool {
				probes++
				if healthy && probes == 2 {
					p.Store.Put("guest_reports", m["vmid"], 1, D{"reported_at": now(), "initialization_status": "complete", "application_status": "healthy"})
				}
				return true
			}
			runQueue(p)
			r := p.Execute(context.Background(), "deployment_apply", D{"machines": []D{{"name": "warming", "ssh_keys": []any{"ssh-ed25519 AAAA test"}}}}, person("alice", false))
			op := obj(r["operation"])
			if healthy {
				if op["state"] != "succeeded" || len(p.Store.Objects("machines")) != 1 {
					t.Fatalf("warming app removed: %s", encoded(r))
				}
			} else {
				if op["state"] != "rolled_back" || len(p.Store.Objects("machines")) != 0 || len(arr(obj(op["error"])["checks"])) != 1 {
					t.Fatalf("persistent failure lost diagnostics or leaked guest: %s", encoded(r))
				}
			}
			if probes < 2 {
				t.Fatal("first failed sample ended readiness")
			}
		})
	}
}

func TestScopeQuotaRequests(t *testing.T) {
	p, _ := fixture(t)
	app, ctx, who := NewApp(p, nil), context.Background(), person("alice", false)
	args := D{"dimension": "public_ports", "amount": 11, "reason": "Regression", "idempotency_key": "dedup-quota"}
	assertCode(t, app.Call(ctx, "quota_request", args, who), "invalid")
	args["dimension"], args["amount"] = "vcpu", 12
	a := app.Call(ctx, "quota_request", args, who)
	b := app.Call(ctx, "quota_request", args, who)
	assertOK(t, a)
	assertOK(t, b)
	if obj(a["request"])["id"] != obj(b["request"])["id"] || len(p.Store.Objects("requests", 1)) != 1 {
		t.Fatal("duplicate quota request")
	}
	assertCode(t, app.Call(ctx, "quota_request", merge(args, D{"amount": 13}), who), "conflict")
	if dicts(app.Call(ctx, "request_list", D{}, who)["requests"])[0]["fingerprint"] != nil {
		t.Fatal("internal request receipt exposed")
	}

	request := D{"id": "expired-pending", "kind": "quota", "tenant_n": 1, "status": "pending", "dimension": "vcpu", "amount": 12, "until": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), "previous_limit": 8}
	p.Store.Put("requests", request["id"], 1, request)
	r := app.Call(ctx, "request_approve", D{"id": request["id"]}, person("alice", true))
	assertCode(t, r, "invalid")
	if p.Store.Get("requests", "expired-pending")["status"] != "pending" {
		t.Fatal("corrected expiration behavior changed")
	}
	auditEvidence(t, "A5", D{"expired_pending_request_status": obj(r["request"])["status"], "limit_after_approval": obj(p.Store.TenantN(1)["quota"])["vcpu"]})
}

func TestScopeRetryGuidance(t *testing.T) {
	p, _ := fixture(t)
	seedMachine(p, "taken", 10100)
	runQueue(p)
	r := p.Execute(context.Background(), "machine_create", D{"name": "taken"}, person("alice", false))
	op := obj(r["operation"])
	if op["state"] != "failed" || op["next_action"] != "revise_request" || obj(op["error"])["code"] != "conflict" {
		t.Fatal("corrected retry guidance changed")
	}
	r2 := p.Execute(context.Background(), "operation_retry", D{"id": op["id"]}, person("alice", false))
	op2 := obj(r2["operation"])
	if op2["state"] != "failed" || op2["next_action"] != "revise_request" || num(op2["attempts"]) != 1 {
		t.Fatal("corrected retry behavior changed")
	}
	auditEvidence(t, "A6", D{"scenario": "existing_machine_name", "first_error": op["error"], "next_action": op2["next_action"], "attempts": op2["attempts"], "new_allocations": len(p.Store.Objects("machines")) - 1})
}

func TestScopeDeletionPresentation(t *testing.T) {
	for _, tool := range []string{"snapshot_delete", "port_close", "network_delete"} {
		t.Run(tool, func(t *testing.T) {
			p, _ := fixture(t)
			seedMachine(p, "dev", 10100)
			kind, field, id := "snapshots", "snapshot", "10100-before"
			args := D{"machine": "dev", "name": "before"}
			record := D{"id": id, "vmid": 10100, "name": "before", "disk_gb": 20, "state": "ready"}
			if tool == "port_close" {
				kind, field, id, args = "ports", "port", "1-20011-tcp", D{"id": "1-20011-tcp"}
				record = D{"id": id, "vmid": 10100, "public_port": 20011, "port": 8080, "proto": "tcp"}
			} else if tool == "network_delete" {
				kind, field, id, args = "networks", "network", "p00101", D{"network": "private", "confirm": "private"}
				record = D{"id": id, "name": "private"}
			}
			p.Store.Put(kind, id, 1, record)
			runQueue(p)
			r := NewApp(p, nil).Call(context.Background(), tool, args, person("alice", false))
			op := obj(r["operation"])
			state := obj(obj(op["result"])[field])["state"]
			if op["state"] != "succeeded" || p.Store.Get(kind, id) != nil || state != "deleted" {
				t.Fatalf("corrected deletion result changed: %s", encoded(r))
			}
			auditEvidence(t, "A7", D{"tool": tool, "operation_state": op["state"], "result_resource_state": state, "resource_exists": false})
		})
	}
}
