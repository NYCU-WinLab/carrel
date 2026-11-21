package carrel

import (
	"context"
	"fmt"
	"testing"
)

// TestRequestFlowEdges pins what the four request tools share: the bytes an
// idempotency fingerprint hashes (keys stay valid for 30 days), key reuse and
// conflict, the pending cap and the adopt guard.
func TestRequestFlowEdges(t *testing.T) {
	p, _ := fixture(t)
	ctx, who, admin := context.Background(), person("alice", false), person("root", true)
	app := NewApp(p, nil)
	p.Store.SitePut("public_pool", "netbox", D{"ranges": []any{D{"start": "203.0.113.10/24", "end": "203.0.113.11/24"}}})
	cases := []struct {
		tool, kind  string
		args        D
		other       D
		fingerprint string
	}{
		{"quota_request", "quota", D{"dimension": "vcpu", "amount": 24, "reason": "reason one", "idempotency_key": "key-quota-1"}, D{"dimension": "vcpu", "amount": 25, "reason": "reason one"}, "4bf7d2f20bcb27029eced276c4e5457fa9fe177b3c23cc3d1669f1e4bcf4530d"},
		{"port_request", "port", D{"public_port": 8443, "proto": "tcp", "reason": "reason one", "idempotency_key": "key-port-1"}, D{"public_port": 8444, "reason": "reason one"}, "edbc56393390a72892c3fcaf2781db4583f7bf4c8ceaad60aa354afe0545d0a9"},
		{"public_ip_request", "public_ip", D{"reason": "reason one", "idempotency_key": "key-ip-1"}, D{"reason": "reason two"}, "10561ae59a825762d5a6fb55ce380928c7fc8a64c695350d923b0644f388bb37"},
	}
	for _, c := range cases {
		dry := app.Call(ctx, c.tool, merge(c.args, D{"dry_run": true}), who)
		if obj(dry["request"])["status"] != "planned" {
			t.Fatalf("%s: dry run: %v", c.tool, dry)
		}
		first := app.Call(ctx, c.tool, c.args, who)
		if !boolean(first["ok"]) {
			t.Fatalf("%s: %v", c.tool, first)
		}
		id := str(obj(first["request"])["id"])
		stored := p.Store.Get("requests", id)
		if stored["fingerprint"] != c.fingerprint {
			t.Fatalf("%s fingerprint changed: %v", c.tool, stored["fingerprint"])
		}
		if _, leaked := obj(first["request"])["fingerprint"]; leaked {
			t.Fatalf("%s leaks the fingerprint", c.tool)
		}
		again := app.Call(ctx, c.tool, c.args, who)
		if again["reused"] != true || obj(again["request"])["id"] != id {
			t.Fatalf("%s: retry did not reuse the request: %v", c.tool, again)
		}
		bad := merge(c.other, D{"idempotency_key": c.args["idempotency_key"]})
		conflict := app.Call(ctx, c.tool, bad, who)
		if boolean(conflict["ok"]) || fmt.Sprint(conflict["error"]) == "" {
			t.Fatalf("%s: a reused key with other arguments was accepted", c.tool)
		}
		if boolean(app.Call(ctx, "request_approve", D{"id": id, "adopt": true}, admin)["ok"]) && c.kind != "domain" {
			t.Fatalf("%s: adopt accepted for a non-domain request", c.tool)
		}
	}
}
