package carrel

import (
	"context"
	"strings"
	"testing"
)

// TestGoldenPublishVIP covers public ports and domains at a virtual address
// (issue #146): previews, idempotent repeats, bad targets, the removal guard
// and the holders' firewall input.
func TestGoldenPublishVIP(t *testing.T) { runGolden(t, "publish-vip.txt", publishVIPScenario, false) }

func publishVIPScenario(g *goldenRun) {
	alice, bob := person("alice", false), person("bob", false)
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoldenGoldenGoldenGoldenGoldenGoldenGold golden"
	call := g.call
	call("s", "ssh_key_add", D{"key": key}, alice)
	call("s", "machine_create", D{"name": "cp1"}, alice)
	call("s", "machine_create", D{"name": "cp2"}, alice)
	call("s", "machine_create", D{"name": "lone"}, alice)
	call("s", "vip_add", D{"name": "api", "machines": []any{"cp1", "cp2"}}, alice)
	call("s", "vip_add", D{"name": "empty", "machines": []any{"lone"}}, alice)
	call("s", "machine_delete", D{"machine": "lone", "confirm": "lone"}, alice)

	// A port at the address: preview, open, repeat, list.
	call("p", "port_open", D{"vip": "api", "port": 6443, "proto": "tcp", "dry_run": true}, alice)
	call("p", "port_open", D{"vip": "api", "port": 6443, "proto": "tcp", "detail": "full"}, alice)
	call("p", "port_open", D{"vip": "api", "port": 6443, "proto": "tcp"}, alice)
	call("p", "port_list", D{}, alice)

	// Bad targets: both, neither, unknown, another tenant's view, no holder.
	call("b", "port_open", D{"machine": "cp1", "vip": "api", "port": 80, "proto": "tcp"}, alice)
	call("b", "port_open", D{"port": 80, "proto": "tcp"}, alice)
	call("b", "port_open", D{"vip": "nope", "port": 80, "proto": "tcp"}, alice)
	call("b", "port_open", D{"vip": "api", "port": 80, "proto": "tcp"}, bob)
	call("b", "port_open", D{"vip": "empty", "port": 80, "proto": "tcp"}, alice)

	// A domain at the address: preview, add, a different target is refused.
	call("d", "domain_add", D{"vip": "api", "sub": "k8s", "target_port": 443, "dry_run": true}, alice)
	call("d", "domain_add", D{"vip": "api", "sub": "k8s", "target_port": 443}, alice)
	call("d", "domain_add", D{"machine": "cp1", "sub": "k8s", "target_port": 443}, alice)
	call("d", "domain_list", D{}, alice)

	// The address stays while something points at it.
	call("r", "vip_remove", D{"name": "api"}, alice)
	call("r", "vip_add", D{"name": "api", "machines": []any{"cp2"}}, alice)
	for _, p := range g.p.execution(context.Background()).ports(1) {
		if p.VIP != "" {
			call("r", "port_close", D{"id": p.ID}, alice)
		}
	}
	call("r", "vip_remove", D{"name": "api"}, alice)
	call("r", "domain_remove", D{"name": "k8s.alice.winlab.tw"}, alice)
	call("r", "vip_remove", D{"name": "api"}, alice)
}

// The gateway forwards a domain at a virtual address to that address.
func TestGatewayForwardsADomainToItsVirtualAddress(t *testing.T) {
	state, origin := gatewayState(t)
	state["vips"] = []any{D{"id": "v1", "tenant_n": 3, "name": "api", "address": "10.200.3.251", "vmids": []any{10300}}}
	state["domains"] = append(arr(state["domains"]), D{"id": "8", "vmid": 0, "vip": "v1", "tenant_n": 3, "sub": "k8s", "name": "k8s.zyx1121.winlab.tw", "target_port": 443, "state": "ready"})
	caddy, _, _ := gatewayConfig(state, "carrel.winlab.tw", origin, dicts(state["certificates"]))
	if !strings.Contains(caddy, "@d8 host k8s.zyx1121.winlab.tw\n handle @d8 {\n  reverse_proxy 10.200.3.251:443\n") {
		t.Fatal(caddy)
	}
	// Another tenant's address is refused.
	state["vips"] = []any{D{"id": "v1", "tenant_n": 4, "name": "api", "address": "10.200.4.251", "vmids": []any{}}}
	if f := attempt(func() { gatewayConfig(state, "carrel.winlab.tw", origin, dicts(state["certificates"])) }); f == nil {
		t.Fatal("a domain reached another tenant's virtual address")
	}
}
