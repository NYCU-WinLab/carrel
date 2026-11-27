package carrel

import (
	"strings"
	"testing"
)

// done is true exactly in the terminal states (#583), and the summary of a
// succeeded operation keeps it.
func TestOperationDoneFollowsTheTerminalStates(t *testing.T) {
	for state, want := range map[string]bool{
		"queued": false, "running": false, "waiting": false, "cleaning_up": false,
		"succeeded": true, "failed": true, "rolled_back": true, "cleanup_failed": true,
	} {
		if got := publicOperation(D{"id": "op", "state": state})["done"]; got != want {
			t.Fatalf("%s: done %v", state, got)
		}
	}
	if operationSummary(publicOperation(D{"id": "op", "state": "succeeded"}))["done"] != true {
		t.Fatal("summary dropped done")
	}
}

// A failed snapshot operation from before the plugin cannot be retried: the
// refusal says to run the tool again and creates no record (#705).
func TestRetryRefusesLegacySnapshotOperation(t *testing.T) {
	p, _, _ := appFixture(t)
	tenant := p.Store.TenantN(1)
	// Once the core code is gone the tool is no longer a core tool.
	delete(coreTools, "snapshot_create")
	t.Cleanup(func() { coreTools["snapshot_create"] = true })
	p.Store.Put("operations", "op-legacy", 1, D{"id": "op-legacy", "tenant_n": 1, "tool": "snapshot_create", "state": "failed",
		"error": D{"code": "backend_unavailable", "message": "boom"}})
	before := len(p.Store.Objects("operations"))
	f, _ := attempt(func() { p.Operations.Retry(tenant, "op-legacy", person("alice", false)) }).(Failure)
	e := obj(f.Result["error"])
	if e["code"] != "conflict" || e["recovery"] != "retry_new_call" || !strings.Contains(str(e["message"]), "run the tool again") {
		t.Fatalf("retry of a legacy snapshot operation: %s", encoded(f.Result))
	}
	if got := len(p.Store.Objects("operations")); got != before {
		t.Fatalf("a refused retry changed the records: %d to %d", before, got)
	}
	if op := p.Store.Get("operations", "op-legacy"); op["state"] != "failed" {
		t.Fatalf("operation changed: %s", encoded(op))
	}
}
