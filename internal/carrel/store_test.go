package carrel

import "testing"

func TestOperationQueriesReadOnlyWhatTheyNeed(t *testing.T) {
	p, _ := fixture(t)
	s := p.Store
	old := now() - operationRetention - 60
	for id, op := range map[string]D{
		"running":   {"state": "running", "created_at": now(), "updated_at": now(), "idempotency_key": "k1"},
		"done":      {"state": "succeeded", "created_at": now() - 10, "updated_at": now() - 10},
		"stale":     {"state": "failed", "created_at": old, "updated_at": old, "idempotency_key": "k2"},
		"stuck":     {"state": "queued", "created_at": old, "updated_at": old},
		"elsewhere": {"state": "running", "created_at": now(), "updated_at": now()},
	} {
		tenant := 1
		if id == "elsewhere" {
			tenant = 2
		}
		s.Put("operations", id, tenant, merge(op, D{"id": id, "tenant_n": tenant}))
	}
	ids := func(ops []D) []string {
		out := []string{}
		for _, o := range ops {
			out = append(out, str(o["id"]))
		}
		return out
	}
	if got := ids(s.ActiveOperations(1)); !equalStrings(got, []string{"running", "stuck"}) {
		t.Fatalf("active %v", got)
	}
	if len(s.ActiveOperations()) != 3 {
		t.Fatal("active across tenants")
	}
	if s.OperationByKey(1, "k1")["id"] != "running" || s.OperationByKey(2, "k1") != nil {
		t.Fatal("idempotency keys are per tenant")
	}
	if got := ids(s.RecentOperations(1, 2)); !equalStrings(got, []string{"running", "done"}) {
		t.Fatalf("recent %v", got)
	}
	s.PruneOperations()
	// Only a finished operation past the retention goes; unfinished work stays.
	if s.Get("operations", "stale") != nil || s.Get("operations", "stuck") == nil || s.Get("operations", "done") == nil {
		t.Fatal("pruned the wrong operations")
	}
}
