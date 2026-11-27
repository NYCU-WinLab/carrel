package carrel

import (
	"context"
	"testing"
)

// A plugin tool a node listed before answers unavailable while no node
// reports its plugin, on MCP as on Execute, and quota_get keeps showing the
// storage of its measured kind.
func TestAnUnreportedPluginToolIsUnavailable(t *testing.T) {
	p := withMeasuredCopies(t)
	alice := NewApp(p, testVerifier{who: person("alice", false)})
	if r := mcpCall(t, alice, "copies_list", D{"machine": "web"}); r["ok"] != true {
		t.Fatalf("reported: %s", encoded(r))
	}
	reportPlugins(p, nil)
	r := mcpCall(t, alice, "copies_take", D{"machine": "web", "name": "a"})
	if e := obj(r["error"]); e["code"] != "unavailable" || e["plugin"] != "copies" || e["recovery"] != "retry" {
		t.Fatalf("unreported over MCP: %s", encoded(r))
	}
	if f := failure(member(p, "copies_list", D{"machine": "web"})); f["code"] != "unavailable" {
		t.Fatalf("unreported: %s", encoded(f))
	}
	if r := member(p, "quota_get", D{}); obj(r["copy_storage"])["copy_gb_counts"] != "declared" {
		t.Fatalf("quota_get unreported: %s", encoded(r))
	}
	if f := failure(member(p, "nothing_here", D{})); f["code"] != "invalid" || f["message"] != "Unknown tool" {
		t.Fatalf("an unknown tool: %s", encoded(f))
	}
}

// A dimension's default follows what its plugin reports, so a changed
// default holds while the plugin is unreported (#680 item 4).
func TestAPluginDimensionKeepsTheLatestDefault(t *testing.T) {
	p, _ := withCopyPlugin(t)
	member(p, "copies_take", D{"machine": "web", "name": "a", "dry_run": true})
	pl := copyPlugin()
	pl[0].Quota[0].DefaultLimit = 3
	reportPlugins(p, pl)
	p.pluginTools()
	reportPlugins(p, nil)
	if q := obj(member(p, "quota_get", D{})["quota"]); obj(q["limit"])["copies"] != float64(3) {
		t.Fatalf("limit: %s", encoded(q))
	}
}

// An operation whose tool carrel no longer runs itself is submitted again,
// not retried into an unknown tool.
func TestARetryOfARemovedCoreToolIsRefused(t *testing.T) {
	p, _ := fixture(t)
	runQueue(p)
	p.Store.Put("operations", "op-gone", 1, D{"id": "op-gone", "tenant_n": 1, "tool": "gone_create", "state": "failed", "args": D{},
		"error": D{"code": "internal", "recovery": "retry"}})
	f := failure(p.Execute(context.Background(), "operation_retry", D{"id": "op-gone"}, person("alice", false)))
	if f["code"] != "conflict" || f["recovery"] != "revise_request" || f["tool"] != "gone_create" {
		t.Fatalf("retry: %s", encoded(f))
	}
}
