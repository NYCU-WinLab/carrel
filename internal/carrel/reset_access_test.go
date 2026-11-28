package carrel

import (
	"context"
	"testing"
)

// resetNode answers like a node for machine_reset_access: the VM's power,
// and the rewritten files for the reset action.
func resetNode(b *fakeBackend, power string, actions *[]D) {
	b.call = func(r D, _ string) (any, error) {
		switch r["op"] {
		case "status":
			return D{"status": power}, nil
		case "action":
			*actions = append(*actions, r)
			switch r["action"] {
			case "reset_access":
				return D{"cloud_init": D{"user": "#cloud-config\n{\"reset\":true}", "network": "{\"version\":2}"}}, nil
			case "shutdown", "stop":
				power = "stopped"
			case "start":
				power = "running"
			}
			return D{"power_state": power, "changed": true, "boot_changed": r["action"] == "start"}, nil
		}
		return D{}, nil
	}
}

func TestResetAccessStoresTheNewFilesAndRestartsARunningVM(t *testing.T) {
	p, b := fixture(t)
	var actions []D
	resetNode(b, "running", &actions)
	seedMachine(p, "web", 10100)
	e := p.execution(context.Background())
	key := "ssh-ed25519 AAAAnew owner@laptop"
	r := e.ResetAccess(D{"machine": "web", "confirm": "web", "ssh_keys": []any{key}}, D{"sub": "alice"}, p.Store.TenantN(1))
	if r["restart"] != true || r["host_keys"] != "kept" {
		t.Fatal(r)
	}
	if len(actions) != 3 || actions[0]["action"] != "reset_access" || actions[1]["action"] != "shutdown" || actions[2]["action"] != "start" {
		t.Fatal("reset, then shutdown and start", actions)
	}
	if !equal(actions[0]["ssh_keys"], []any{key}) {
		t.Fatal(actions[0])
	}
	stored := e.cloudInitFiles(p.Store.Get("machines", "10100"))
	if stored["user"] != "#cloud-config\n{\"reset\":true}" {
		t.Fatal("the record must hold the bytes the node wrote", stored)
	}
	if !equal(actions[2]["cloud_init"], stored) {
		t.Fatal("the start must carry the new files", actions[2])
	}
	if !contains(arr(p.Store.Get("machines", "10100")["ssh_keys"]), key) {
		t.Fatal("the jump host admits a machine's keys, so the record keeps the new one")
	}
	if len(p.Store.Rows("SELECT at FROM audit WHERE tool='machine_reset_access'")) != 1 {
		t.Fatal("every reset is audited")
	}
}

func TestResetAccessOnAStoppedVMDoesNotStartIt(t *testing.T) {
	p, b := fixture(t)
	var actions []D
	resetNode(b, "stopped", &actions)
	seedMachine(p, "web", 10100)
	r := p.execution(context.Background()).ResetAccess(D{"machine": "web", "confirm": "web", "ssh_keys": []any{"ssh-ed25519 AAAAnew"}}, D{}, p.Store.TenantN(1))
	if r["restart"] != false || len(actions) != 1 {
		t.Fatal("a stopped VM takes the keys at its next start", actions)
	}
}

func TestResetAccessDryRunChangesNothing(t *testing.T) {
	p, b := fixture(t)
	var actions []D
	resetNode(b, "running", &actions)
	seedMachine(p, "web", 10100)
	r := p.execution(context.Background()).ResetAccess(D{"machine": "web", "confirm": "web", "ssh_keys": []any{"ssh-ed25519 AAAAnew"}, "dry_run": true}, D{}, p.Store.TenantN(1))
	if r["dry_run"] != true || r["restart"] != true || len(actions) != 0 {
		t.Fatal(r, actions)
	}
}

func TestResetAccessRefusals(t *testing.T) {
	p, b := fixture(t)
	var actions []D
	resetNode(b, "running", &actions)
	seedMachine(p, "web", 10100)
	ct := seedMachine(p, "box", 10101)
	ct["kind"] = "ct"
	p.Store.Put("machines", 10101, 1, ct)
	iso := seedMachine(p, "inst", 10102)
	iso["guest_management"] = 0
	p.Store.Put("machines", 10102, 1, iso)
	e := p.execution(context.Background())
	key := []any{"ssh-ed25519 AAAAnew"}
	for name, a := range map[string]D{
		"wrong confirm": {"machine": "web", "confirm": "box", "ssh_keys": key},
		"a CT":          {"machine": "box", "confirm": "box", "ssh_keys": key},
		"an ISO VM":     {"machine": "inst", "confirm": "inst", "ssh_keys": key},
		"no key":        {"machine": "web", "confirm": "web"},
		"not a key":     {"machine": "web", "confirm": "web", "ssh_keys": []any{"command=\"sh\" ssh-ed25519 AAAA"}},
	} {
		if attempt(func() { e.ResetAccess(a, D{}, p.Store.TenantN(1)) }) == nil {
			t.Fatal("accepted", name)
		}
	}
	if len(actions) != 0 {
		t.Fatal("a refusal must not reach the node", actions)
	}
}
