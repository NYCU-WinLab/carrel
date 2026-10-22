package carrel

import (
	"context"
	"testing"
)

// A client past its time leaves the desired state at once and its record at
// the next maintenance pass (issue #103).
func TestVPNClientsExpire(t *testing.T) {
	p, _ := fixture(t)
	e := p.execution(context.Background())
	key := "x3Fh2Y0pB0Hq9gYc0vXo4m1kQfN6aT8rW5sLdJ2eCzU="
	p.Store.Put("vpn_clients", "a", 1, vpnClient{ID: "a", TenantN: 1, Name: "laptop", Address: "10.201.1.2", PublicKey: key, State: "ready", ExpiresAt: now() + 3600}.D())
	p.Store.Put("vpn_clients", "b", 1, vpnClient{ID: "b", TenantN: 1, Name: "agent", Address: "10.201.1.3", PublicKey: key, State: "ready", ExpiresAt: now() - 1}.D())
	clients := dicts(p.Store.Desired()["vpn_clients"])
	if len(clients) != 1 || clients[0]["name"] != "laptop" {
		t.Fatal("an expired client is still desired", clients)
	}
	e.ExpireVPNClients()
	if p.Store.Get("vpn_clients", "b") != nil || p.Store.Get("vpn_clients", "a") == nil {
		t.Fatal("expiry removed the wrong client")
	}
	if n := len(p.Store.Rows("SELECT * FROM audit WHERE tool='vpn_client_expired'")); n != 1 {
		t.Fatal("expiry not audited", n)
	}
}
