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
	dns := &statefulDNS{records: map[string][]D{}, list: true, zones: []D{{"id": "0123456789abcdef0123456789abcdef", "name": "lab.example", "token": "zone-token-0123456789abcdef"}}}
	p.Config.CloudflareAPI = dns.serve(t).URL
	p.Config.CloudflareToken = "test"
	app := NewApp(p, nil)
	p.Store.SitePut("public_pool", "netbox", D{"ranges": []any{D{"start": "203.0.113.10/24", "end": "203.0.113.11/24"}}})
	cases := []struct {
		tool, kind  string
		args        D
		other       D
		fingerprint string
	}{
		{"domain_request", "domain", D{"name": "video.winlab.tw", "reason": "reason one", "idempotency_key": "key-domain-1"}, D{"name": "video2.winlab.tw", "reason": "reason one"}, "150be24d57608a187b196d914dcadf84b8ef5e513d61a8970e13fa5e2f08bc0f"},
		{"quota_request", "quota", D{"dimension": "vcpu", "amount": 24, "reason": "reason one", "idempotency_key": "key-quota-1"}, D{"dimension": "vcpu", "amount": 25, "reason": "reason one"}, "4bf7d2f20bcb27029eced276c4e5457fa9fe177b3c23cc3d1669f1e4bcf4530d"},
		{"port_request", "port", D{"public_port": 8443, "proto": "tcp", "reason": "reason one", "idempotency_key": "key-port-1"}, D{"public_port": 8444, "reason": "reason one"}, "edbc56393390a72892c3fcaf2781db4583f7bf4c8ceaad60aa354afe0545d0a9"},
		{"public_ip_request", "public_ip", D{"reason": "reason one", "idempotency_key": "key-ip-1"}, D{"reason": "reason two"}, "10561ae59a825762d5a6fb55ce380928c7fc8a64c695350d923b0644f388bb37"},
	}
	// The tool schema refuses upper case and a trailing dot, so the name
	// normalization is pinned on the fingerprint bytes themselves.
	mixed := digest(string(encoded(domainRequestKind.fingerprint(D{"name": "Video.WinLab.tw.", "reason": "reason one"}))))
	if mixed != cases[0].fingerprint {
		t.Fatalf("domain fingerprint of a mixed case name with a trailing dot: %s", mixed)
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
		if err := obj(conflict["error"]); boolean(conflict["ok"]) || err["code"] != "conflict" || err["message"] != "Idempotency key was already used for different arguments" {
			t.Fatalf("%s: a reused key with other arguments: %v", c.tool, conflict)
		}
		if c.kind != "domain" {
			adopt := app.Call(ctx, "request_approve", D{"id": id, "adopt": true}, admin)
			if boolean(adopt["ok"]) || obj(adopt["error"])["code"] != "invalid" {
				t.Fatalf("%s: adopt for a non-domain request: %v", c.tool, adopt)
			}
		}
	}
}

// TestRequestFlowPendingCap pins the cap of three pending requests for the
// kinds that have one, the text of its refusal, and that a quota request has
// no cap.
func TestRequestFlowPendingCap(t *testing.T) {
	p, _ := fixture(t)
	ctx, who := context.Background(), person("alice", false)
	dns := &statefulDNS{records: map[string][]D{}, list: true, zones: []D{{"id": "0123456789abcdef0123456789abcdef", "name": "lab.example", "token": "zone-token-0123456789abcdef"}}}
	p.Config.CloudflareAPI = dns.serve(t).URL
	p.Config.CloudflareToken = "test"
	app := NewApp(p, nil)
	p.Store.SitePut("public_pool", "netbox", D{"ranges": []any{D{"start": "203.0.113.10/24", "end": "203.0.113.20/24"}}})
	file := func(tool string, i int) D {
		args := D{"reason": "reason"}
		switch tool {
		case "domain_request":
			args["name"] = fmt.Sprintf("cap%d.winlab.tw", i)
		case "port_request":
			args["public_port"], args["proto"] = 8000+i, "tcp"
		case "quota_request":
			args["dimension"], args["amount"] = "vcpu", 20+i
		}
		return app.Call(ctx, tool, args, who)
	}
	for _, c := range []struct{ tool, noun string }{{"domain_request", "domain"}, {"port_request", "port"}, {"public_ip_request", "public address"}} {
		for i := range 3 {
			if r := file(c.tool, i); !boolean(r["ok"]) {
				t.Fatalf("%s %d: %v", c.tool, i, r)
			}
		}
		r := file(c.tool, 3)
		err := obj(r["error"])
		want := fmt.Sprintf("A tenant has at most 3 pending %s requests; wait for a decision", c.noun)
		if boolean(r["ok"]) || err["code"] != "quota_exceeded" || err["message"] != want {
			t.Fatalf("%s: the fourth request: %v", c.tool, r)
		}
	}
	for i := range 5 {
		if r := file("quota_request", i); !boolean(r["ok"]) {
			t.Fatalf("quota request %d is capped: %v", i, r)
		}
	}
}
