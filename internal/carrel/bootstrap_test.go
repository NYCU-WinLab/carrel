package carrel

import (
	"context"
	"strings"
	"testing"
)

func TestBootstrapArgumentLimitsBeforeQueueing(t *testing.T) {
	for _, route := range []struct {
		tool string
		dry  bool
	}{
		{"machine_create", false}, {"machine_create", true},
		{"deployment_plan", false}, {"deployment_apply", false},
	} {
		for _, tc := range []struct {
			name, argument string
			valid          bool
		}{
			{"reported-demo-size", strings.Repeat("a", 13297), true},
			{"ascii-boundary", strings.Repeat("a", 65536), true},
			{"utf8-boundary", strings.Repeat("界", 21845) + "a", true},
			{"ascii-oversized", strings.Repeat("a", 65537), false},
			{"utf8-oversized", strings.Repeat("界", 21845) + "ab", false},
		} {
			t.Run(route.tool+"/"+tc.name+map[bool]string{true: "/preview", false: "/request"}[route.dry], func(t *testing.T) {
				p, b := fixture(t)
				commands := []any{[]any{"python3", "-c", tc.argument}}
				machine := D{"name": "bootstrap", "runcmd": commands}
				args := clone(machine)
				if route.tool != "machine_create" {
					args = D{"machines": []any{machine}}
				}
				if route.tool == "machine_create" {
					args["dry_run"] = route.dry
				}
				if route.tool != "deployment_plan" {
					args["wait_seconds"] = 0
				}
				r := NewApp(p, nil).Call(context.Background(), route.tool, args, person("alice", false))
				if !tc.valid {
					assertCode(t, r, "invalid")
					if len(p.Store.Objects("operations")) != 0 || len(p.Store.Objects("machines")) != 0 || b.count("inventory") != 0 {
						t.Fatal("invalid bootstrap was queued or reached admission")
					}
					if tc.name == "utf8-oversized" && integer(obj(r["error"])["actual_bytes"]) != 65537 {
						t.Fatalf("missing UTF-8 byte diagnostic: %s", encoded(r))
					}
					return
				}
				assertOK(t, r)
				if route.dry || route.tool == "deployment_plan" {
					if len(p.Store.Objects("operations")) != 0 || len(p.Store.Objects("machines")) != 0 {
						t.Fatal("preview mutated resources")
					}
					return
				}
				op := p.Store.Get("operations", str(obj(r["operation"])["id"]))
				saved := obj(op["args"])
				if route.tool == "deployment_apply" {
					saved = dicts(saved["machines"])[0]
				}
				if !equal(saved["runcmd"], commands) || boolean(op["reserved"]) {
					t.Fatal("accepted script was truncated or reserved before admission")
				}
			})
		}
	}
}

func TestDeploymentSummaryPreservesAccessAndFullRecoveryData(t *testing.T) {
	p, _ := fixture(t)
	m := seedMachine(p, "demo", 10100)
	receipt := D{"machines": []any{10100}, "bindings": D{"10100": []any{"allocation", 123, "done"}}, "grants": D{"domains": []any{"domain-id"}}}
	access := D{"machines": []D{p.execution(context.Background()).PublicMachine(m, nil)}, "endpoints": []D{{"machine": "demo", "url": "https://demo.alice.winlab.tw", "verification": "routing_configured"}}, "connections": []D{{"from": "demo", "to": "db", "port": 5432}}}
	op := D{"id": "done", "tenant_n": 1, "tool": "deployment_apply", "state": "succeeded", "result": merge(access, D{"ok": true, "deployment": receipt})}
	p.Store.Put("operations", "done", 1, op)
	app := NewApp(p, nil)
	for _, tool := range []string{"operation_get", "operation_retry"} {
		response := app.Call(context.Background(), tool, D{"id": "done"}, person("alice", false))
		assertOK(t, response)
		summary := obj(response["operation"])
		if tool == "operation_get" {
			summary = dicts(response["operations"])[0]
		}
		result := obj(summary["result"])
		if result["deployment"] != nil || !equal(result["endpoints"], access["endpoints"]) || !equal(result["connections"], access["connections"]) || dicts(result["machines"])[0]["name"] != "demo" {
			t.Fatalf("summary lost access details or leaked internals: %s", encoded(result))
		}
	}
	full := app.Call(context.Background(), "operation_get", D{"id": "done", "detail": "full"}, person("alice", false))
	if !equal(obj(dicts(full["operations"])[0]["result"])["deployment"], receipt) || !equal(p.Store.Get("operations", "done"), op) {
		t.Fatal("presentation changed durable recovery data")
	}
	for _, state := range []string{"waiting", "failed", "cleanup_failed"} {
		pending := merge(op, D{"state": state, "cleanup": D{"remaining": []any{"demo"}}})
		if !equal(operationSummary(pending), pending) {
			t.Fatal("failure or pending details were removed")
		}
	}
}

func TestLargeBootstrapStillEnforcesHTTPBodyLimit(t *testing.T) {
	p, _ := fixture(t)
	app := NewApp(p, testVerifier{who: person("alice", false)})
	command := []any{"echo"}
	for range 5 {
		command = append(command, strings.Repeat("a", 65536))
	}
	body := D{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": D{"name": "machine_create", "arguments": D{"name": "oversized", "runcmd": []any{command}, "wait_seconds": 0}}}
	w := requestApp(app, "POST", "/mcp", string(encoded(body)), map[string]string{"Authorization": "Bearer test", "Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
	if w.Code < 400 || len(p.Store.Objects("operations")) != 0 || len(p.Store.Objects("machines")) != 0 {
		t.Fatalf("oversized request was accepted: HTTP %d", w.Code)
	}
}
