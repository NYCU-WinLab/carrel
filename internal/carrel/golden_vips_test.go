package carrel

import "testing"

// TestGoldenVIPs covers virtual addresses (issue #96): previews, holders,
// replacement, the per-tenant limit, machine deletion and removal.
func TestGoldenVIPs(t *testing.T) { runGolden(t, "vips.txt", vipScenario, false) }

func vipScenario(g *goldenRun) {
	alice, bob := person("alice", false), person("bob", false)
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoldenGoldenGoldenGoldenGoldenGoldenGold golden"
	call := g.call
	call("s", "ssh_key_add", D{"key": key}, alice)
	call("s", "machine_create", D{"name": "cp1"}, alice)
	call("s", "machine_create", D{"name": "cp2"}, alice)
	call("s", "machine_create", D{"name": "cp3"}, alice)
	call("s", "ssh_key_add", D{"key": key}, bob)
	call("s", "machine_create", D{"name": "other"}, bob)

	// Add: preview, create, list, replace the holders, bad requests.
	call("a", "vip_add", D{"name": "api", "machines": []any{"cp1", "cp2"}, "dry_run": true}, alice)
	call("a", "vip_add", D{"name": "api", "machines": []any{"cp2", "cp1"}, "detail": "full"}, alice)
	call("a", "vip_list", D{}, alice)
	call("a", "vip_add", D{"name": "api", "machines": []any{"cp1", "cp2", "cp3"}}, alice)
	call("a", "vip_add", D{"name": "dup", "machines": []any{"cp1", "cp1"}}, alice)
	call("a", "vip_add", D{"name": "theirs", "machines": []any{"other"}}, alice)
	call("a", "vip_list", D{}, bob)

	// Four per tenant.
	for _, name := range []string{"b", "c", "d", "e"} {
		call("l", "vip_add", D{"name": name, "machines": []any{"cp3"}}, alice)
	}

	// Deleting a holder keeps the address for the others.
	call("x", "machine_delete", D{"machine": "cp3", "confirm": "cp3"}, alice)
	call("x", "vip_list", D{}, alice)

	// Remove: preview, remove, missing, and the freed address is reused.
	call("r", "vip_remove", D{"name": "api", "dry_run": true}, alice)
	call("r", "vip_remove", D{"name": "api", "detail": "full"}, alice)
	call("r", "vip_remove", D{"name": "api"}, alice)
	call("r", "vip_add", D{"name": "web", "machines": []any{"cp1"}}, alice)
	for _, name := range []string{"b", "c", "d", "web"} {
		call("r", "vip_remove", D{"name": name}, alice)
	}
	call("r", "vip_list", D{}, alice)
}
