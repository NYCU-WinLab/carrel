package carrel

import (
	"context"
	"testing"
	"time"
)

func TestQuotaDecisionIsAtomicAndDedupSurvivesApproval(t *testing.T) {
	p, _ := fixture(t)
	ctx, who := context.Background(), person("alice", false)
	app := NewApp(p, nil)
	args := D{"dimension": "vcpu", "amount": 12, "reason": "capacity", "idempotency_key": "quota-atomic", "until": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	submitted := app.Call(ctx, "quota_request", args, who)
	assertOK(t, submitted)
	id := obj(submitted["request"])["id"]
	p.Store.Exec("CREATE TRIGGER fail_request_save BEFORE INSERT ON objects WHEN NEW.kind='requests' BEGIN SELECT RAISE(ABORT, 'write failure'); END")
	failed := app.Call(ctx, "request_approve", D{"id": id}, person("alice", true))
	if boolean(failed["ok"]) || num(obj(p.Store.TenantN(1)["quota"])["vcpu"]) != 8 || p.Store.Get("requests", str(id))["status"] != "pending" {
		t.Fatal("partial approval survived failed transaction")
	}
	p.Store.Exec("DROP TRIGGER fail_request_save")
	approved := app.Call(ctx, "request_approve", D{"id": id}, person("alice", true))
	assertOK(t, approved)
	duplicate := app.Call(ctx, "quota_request", args, who)
	assertOK(t, duplicate)
	if obj(duplicate["request"])["id"] != id || obj(duplicate["request"])["status"] != "approved" || len(p.Store.Objects("requests")) != 1 {
		t.Fatal("retransmission after approval created another request")
	}
	r := p.Store.Get("requests", str(id))
	r["until"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	p.Store.Put("requests", id, 1, r)
	p.execution(ctx).ExpireGrants()
	if num(obj(p.Store.TenantN(1)["quota"])["vcpu"]) != 8 || p.Store.Get("requests", str(id))["status"] != "expired" {
		t.Fatal("grant expiry did not restore previous quota")
	}
}
