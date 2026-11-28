package carrel

import (
	"context"
	"errors"
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

func TestResetAccessNeverForcesAMachineOff(t *testing.T) {
	p, b := fixture(t)
	var actions []D
	resetNode(b, "running", &actions)
	next := b.call
	b.call = func(r D, target string) (any, error) {
		if r["op"] == "action" && r["action"] == "shutdown" {
			actions = append(actions, r)
			return nil, errors.New("shutdown timed out")
		}
		return next(r, target)
	}
	seedMachine(p, "web", 10100)
	e := p.execution(context.Background())
	if attempt(func() {
		e.ResetAccess(D{"machine": "web", "confirm": "web", "ssh_keys": []any{"ssh-ed25519 AAAAnew"}}, D{}, p.Store.TenantN(1))
	}) == nil {
		t.Fatal("a failed shutdown must fail the reset")
	}
	for _, a := range actions {
		if a["action"] == "stop" || a["action"] == "start" {
			t.Fatal("forced off or started after a failed shutdown", actions)
		}
	}
	if e.cloudInitFiles(p.Store.Get("machines", "10100"))["user"] != "#cloud-config\n{\"reset\":true}" {
		t.Fatal("the keys are saved for the next start")
	}
}

func TestResetAccessReadsTheFilesWhenTheNodeReplaysItsAnswer(t *testing.T) {
	p, b := fixture(t)
	var actions []D
	resetNode(b, "stopped", &actions)
	next := b.call
	reads := 0
	b.call = func(r D, target string) (any, error) {
		switch {
		case r["op"] == "action" && r["action"] == "reset_access":
			// A journal replay: the node strips the files from it.
			return D{}, nil
		case r["op"] == "cloud_init_read":
			reads++
			return D{"cloud_init": D{"user": "#cloud-config\n# carrel reset x\n{}", "network": "{}"}}, nil
		}
		return next(r, target)
	}
	seedMachine(p, "web", 10100)
	p.execution(context.Background()).ResetAccess(D{"machine": "web", "confirm": "web", "ssh_keys": []any{"ssh-ed25519 AAAAnew"}}, D{}, p.Store.TenantN(1))
	if reads != 1 || p.execution(context.Background()).cloudInitFiles(p.Store.Get("machines", "10100"))["user"] != "#cloud-config\n# carrel reset x\n{}" {
		t.Fatal("the record must hold what the node has", reads)
	}
}

func TestResetAccessBoundsAndDeduplicatesTheMachinesKeys(t *testing.T) {
	p, b := fixture(t)
	var actions []D
	resetNode(b, "stopped", &actions)
	m := seedMachine(p, "web", 10100)
	full := []any{}
	for i := 0; i < maxMachineKeys; i++ {
		full = append(full, "ssh-ed25519 AAAA"+string(rune('a'+i%26))+string(rune('a'+i/26))+" n")
	}
	m["ssh_keys"] = full
	p.Store.Put("machines", 10100, 1, m)
	e := p.execution(context.Background())
	// The same key under another comment is not a new key.
	e.ResetAccess(D{"machine": "web", "confirm": "web", "ssh_keys": []any{"ssh-ed25519 AAAAaa other"}}, D{}, p.Store.TenantN(1))
	if len(arr(p.Store.Get("machines", "10100")["ssh_keys"])) != maxMachineKeys {
		t.Fatal("a known key was added twice")
	}
	if attempt(func() {
		e.ResetAccess(D{"machine": "web", "confirm": "web", "ssh_keys": []any{"ssh-ed25519 AAAAzzz"}}, D{}, p.Store.TenantN(1))
	}) == nil {
		t.Fatal("accepted a 51st key")
	}
}
