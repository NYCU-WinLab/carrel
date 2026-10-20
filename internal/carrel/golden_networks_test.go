package carrel

import "testing"

// TestGoldenNetworks covers private networks, NICs and snapshots: previews,
// reuse and conflicts, deployments that attach, rollbacks, quotas and the
// cleanup that machine deletion does.
func TestGoldenNetworks(t *testing.T) { runGolden(t, "networks.txt", networkScenario, false) }

func networkScenario(g *goldenRun) {
	alice := person("alice", false)
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoldenGoldenGoldenGoldenGoldenGoldenGold golden"
	call := g.call
	call("s", "ssh_key_add", D{"key": key}, alice)
	call("s", "machine_create", D{"name": "web"}, alice)
	call("s", "machine_create", D{"name": "db"}, alice)
	call("s", "machine_create", D{"name": "box", "kind": "ct"}, alice)

	// Networks: preview, create, duplicate, raw and addressed segments.
	call("n", "network_create", D{"name": "lab", "dry_run": true}, alice)
	call("n", "network_create", D{"name": "lab", "detail": "full"}, alice)
	call("n", "network_create", D{"name": "lab"}, alice)
	call("n", "network_create", D{"name": "raw", "mode": "raw_l2"}, alice)
	call("n", "network_create", D{"name": "small", "cidr": "10.80.1.0/25"}, alice)
	call("n", "network_create", D{"name": "public", "cidr": "8.8.8.0/24"}, alice)
	call("n", "network_list", D{}, alice)

	// NICs: preview, attach, duplicate, containers, detach.
	call("i", "machine_nic_attach", D{"machine": "web", "network": "lab", "dry_run": true}, alice)
	call("i", "machine_nic_attach", D{"machine": "web", "network": "lab", "detail": "full"}, alice)
	call("i", "machine_nic_attach", D{"machine": "web", "network": "lab"}, alice)
	call("i", "machine_nic_attach", D{"machine": "web", "network": "raw"}, alice)
	call("i", "machine_nic_attach", D{"machine": "box", "network": "lab"}, alice)
	call("i", "machine_nic_attach", D{"machine": "db", "network": "missing"}, alice)
	call("i", "machine_get", D{"machine": "web", "detail": "full"}, alice)
	call("i", "network_delete", D{"network": "lab", "confirm": "lab"}, alice)
	call("i", "network_delete", D{"network": "raw", "confirm": "wrong"}, alice)
	call("i", "machine_nic_detach", D{"machine": "web", "nic": 2, "dry_run": true}, alice)
	call("i", "machine_nic_detach", D{"machine": "web", "nic": 7}, alice)
	call("i", "machine_nic_detach", D{"machine": "web", "nic": 2, "detail": "full"}, alice)
	call("i", "network_delete", D{"network": "raw", "confirm": "raw", "dry_run": true}, alice)
	call("i", "network_delete", D{"network": "raw", "confirm": "raw"}, alice)

	// Deployments: a new network with attachments, then the same again.
	spec := D{"networks": []any{D{"name": "dep"}}, "attachments": []any{D{"machine": "db", "network": "dep"}, D{"machine": "db", "network": "lab"}}}
	call("d", "deployment_plan", obj(copyValue(spec)), alice)
	applied := call("d", "deployment_apply", obj(copyValue(spec)), alice)
	call("d", "operation_get", D{"id": obj(applied["operation"])["id"], "detail": "full"}, alice)
	call("d", "deployment_apply", obj(copyValue(spec)), alice)
	call("d", "network_list", D{}, alice)
	call("d", "machine_list", D{"detail": "full"}, alice)

	// Snapshots: preview, create, duplicate, list, rollback, delete.
	call("p", "snapshot_create", D{"machine": "web", "name": "s1", "dry_run": true}, alice)
	call("p", "snapshot_create", D{"machine": "web", "name": "s1", "detail": "full"}, alice)
	call("p", "snapshot_create", D{"machine": "web", "name": "s1"}, alice)
	call("p", "snapshot_create", D{"machine": "web", "name": "s2"}, alice)
	call("p", "snapshot_list", D{"machine": "web"}, alice)
	call("p", "snapshot_rollback", D{"machine": "web", "name": "s1", "confirm": "s2"}, alice)
	call("p", "snapshot_rollback", D{"machine": "web", "name": "s1", "confirm": "s1", "dry_run": true}, alice)
	call("p", "snapshot_rollback", D{"machine": "web", "name": "s1", "confirm": "s1", "detail": "full"}, alice)
	call("p", "snapshot_delete", D{"machine": "web", "name": "s2", "dry_run": true}, alice)
	call("p", "snapshot_delete", D{"machine": "web", "name": "s2", "detail": "full"}, alice)
	call("p", "snapshot_delete", D{"machine": "web", "name": "missing"}, alice)
	call("p", "snapshot_create", D{"machine": "db", "name": "a"}, alice)
	call("p", "snapshot_create", D{"machine": "db", "name": "b"}, alice)
	call("p", "snapshot_create", D{"machine": "db", "name": "c"}, alice)
	call("p", "snapshot_create", D{"machine": "db", "name": "d"}, alice)
	call("p", "quota_get", D{}, alice)
	call("p", "machine_resize", D{"machine": "web", "cpu": 2}, alice)
	call("p", "snapshot_rollback", D{"machine": "web", "name": "s1", "confirm": "s1"}, alice)

	// Deleting machines drops their NICs and snapshots; then the networks go.
	call("x", "machine_delete", D{"machine": "db", "confirm": "db"}, alice)
	call("x", "machine_delete", D{"machine": "web", "confirm": "web"}, alice)
	call("x", "machine_delete", D{"machine": "box", "confirm": "box"}, alice)
	for _, network := range g.p.Store.Objects("networks", 1) {
		call("x", "network_delete", D{"network": network["name"], "confirm": network["name"]}, alice)
	}
	call("x", "network_list", D{}, alice)
	call("x", "quota_get", D{}, alice)
}
