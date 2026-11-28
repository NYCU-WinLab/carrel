package carrel

import (
	"context"
	"testing"
)

func TestMachineGetListsOwnerChecksOnlyForImportedMachine(t *testing.T) {
	p, _ := fixture(t)
	seedMachine(p, "web", 10100)
	seedMachine(p, "old", 10101)
	m := p.Store.Get("machines", "10101")
	m["imported"] = true
	p.Store.Put("machines", "10101", integer(m["tenant_n"]), m)
	e := &Execution{P: p, S: p.Store, Ctx: context.Background()}
	plain := e.PublicMachine(p.Store.Get("machines", "10100"), nil)
	if plain["owner_checks"] != nil {
		t.Errorf("an ordinary machine lists owner checks: %v", plain["owner_checks"])
	}
	checks := dicts(e.PublicMachine(p.Store.Get("machines", "10101"), nil)["owner_checks"])
	if len(checks) != 5 {
		t.Fatalf("owner_checks: %v", checks)
	}
	for i, id := range []string{"old_keys", "guest_exec", "host_key_change", "old_addresses", "resolvers"} {
		if checks[i]["id"] != id {
			t.Errorf("check %d: %v", i, checks[i])
		}
	}
}
