package carrel

import (
	"context"
	"strings"
	"testing"
)

// TestGoldenPublicIPs covers public addresses (issue #91): approval takes the
// pool's first free address, one machine holds at most one, a rebind moves
// it, and deleting the machine unbinds it so a later machine with its VMID
// does not inherit it.
func TestGoldenPublicIPs(t *testing.T) { runGolden(t, "public-ips.txt", publicIPScenario, false) }

func publicIPScenario(g *goldenRun) {
	alice, admin := person("alice", false), person("root", true)
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoldenGoldenGoldenGoldenGoldenGoldenGold golden"
	call := g.call
	g.p.Store.SitePut("public_pool", "netbox", D{"ranges": []any{D{"start": "203.0.113.10/24", "end": "203.0.113.11/24"}}})
	call("s", "ssh_key_add", D{"key": key}, alice)
	call("s", "machine_create", D{"name": "mail"}, alice)
	call("s", "machine_create", D{"name": "dns"}, alice)
	for range 2 {
		r := call("r", "public_ip_request", D{"reason": "a service on a standard port"}, alice)
		call("r", "request_approve", D{"id": obj(r["request"])["id"]}, admin)
	}
	r := call("r", "public_ip_request", D{"reason": "a third one"}, alice)
	call("r", "request_approve", D{"id": obj(r["request"])["id"]}, admin)
	call("b", "public_ip_bind", D{"machine": "mail"}, alice)
	call("b", "public_ip_bind", D{"address": "203.0.113.10", "machine": "mail", "ports": []any{"tcp/25"}}, alice)
	call("b", "public_ip_bind", D{"address": "203.0.113.11", "machine": "mail"}, alice)
	call("b", "public_ip_bind", D{"address": "203.0.113.11", "machine": "dns", "ports": []any{"all"}}, alice)
	call("b", "public_ip_list", D{}, alice)
	call("d", "machine_delete", D{"machine": "mail", "confirm": "mail"}, alice)
	call("d", "public_ip_list", D{}, alice)
	call("d", "machine_create", D{"name": "mail2"}, alice)
	call("d", "public_ip_list", D{}, alice)
	p := g.p
	for _, b := range p.execution(context.Background()).publicIPs() {
		if b.Address == "203.0.113.10" && b.VMID != 0 {
			g.t.Fatalf("a deleted machine's binding survived: %+v", b)
		}
	}
}

// A release whose reconcile failed is finished by releasing again, and an
// address NetBox no longer assigns to carrel is not bound again (#91).
func TestPublicIPReleaseRetriesAndPoolRevocation(t *testing.T) {
	p, _ := fixture(t)
	ctx := context.Background()
	p.Store.SitePut("public_pool", "netbox", D{"ranges": []any{D{"start": "203.0.113.10/24", "end": "203.0.113.10/24"}}})
	seedMachine(p, "web", 10100)
	p.Store.Put("public_ips", "b", 1, publicIP{ID: "b", TenantN: 1, Address: "203.0.113.10", RequestID: "r", State: "deleting"}.D())
	t1 := p.Store.TenantN(1)
	e := p.execution(ctx)
	if f := attempt(func() { e.PublicIPAction("public_ip_bind", D{"machine": "web"}, t1) }); f == nil {
		t.Fatal("bound an address being released")
	}
	e.PublicIPAction("public_ip_release", D{}, t1)
	if len(e.publicIPs()) != 0 {
		t.Fatal("a second release did not finish", e.publicIPs())
	}
	p.Store.Put("public_ips", "c", 1, publicIP{ID: "c", TenantN: 1, Address: "203.0.113.10", RequestID: "r"}.D())
	p.Store.SitePut("public_pool", "netbox", D{"ranges": []any{}})
	f := attempt(func() { e.PublicIPAction("public_ip_bind", D{"machine": "web"}, t1) })
	if f == nil || !strings.Contains(describe(f), "no longer assigns") {
		t.Fatal("bound an address NetBox took back", f)
	}
}
