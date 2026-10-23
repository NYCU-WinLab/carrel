package carrel

import (
	"fmt"
	"regexp"
	"time"
)

// Client VPN (issue #103, PLAN 6.11): WireGuard on the first exit node, one
// interface per tenant in the tenants' VRF. A member's device or agent makes
// its own key pair and sends only the public key, so carrel never holds a
// client private key. A client reaches its tenant's /24 and nothing else, and
// it expires: an agent that opens one for a task does not leave it behind.

// vpnClient is one device's peer on its tenant's interface.
type vpnClient struct {
	Address     string  `json:"address"`
	CreatedAt   float64 `json:"created_at"`
	ExpiresAt   float64 `json:"expires_at"`
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	OperationID string  `json:"operation_id,omitempty"`
	PublicKey   string  `json:"public_key"`
	State       string  `json:"state,omitempty"`
	TenantN     int     `json:"tenant_n"`
}

// vpnServer is a tenant's interface as the exit node reported it.
type vpnServer struct {
	ID        string `json:"id"`
	Port      int    `json:"port"`
	PublicKey string `json:"public_key"`
	TenantN   int    `json:"tenant_n"`
}

func (c vpnClient) D() D { return decode(string(encoded(c))) }

func (e *Execution) vpnClients(n ...int) []vpnClient {
	return rowsOf[vpnClient](e.S, "vpn_clients", n...)
}

const (
	vpnClientLimit = 8   // per tenant
	vpnHours       = 8   // a working day, unless asked
	vpnMaxHours    = 168 // a week
	vpnClientMTU   = 1380
)

// A WireGuard public key: 32 bytes in base64.
var wgKey = regexp.MustCompile(`^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$`)

func (e *Execution) VPNAction(tool string, a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	var client vpnClient
	found := false
	for _, c := range e.vpnClients(n) {
		if c.Name == a["name"] {
			client, found = c, true
		}
	}
	switch tool {
	case "vpn_client_list":
		out := []D{}
		for _, c := range e.vpnClients(n) {
			out = append(out, e.publicVPNClient(c, t))
		}
		return D{"vpn_clients": out}
	case "vpn_client_remove":
		if !found {
			fail("not_found", "VPN client not found")
		}
		if !dry {
			// The peer leaves the interface before the record goes, so a
			// failed reconcile leaves it visible and retryable.
			client.State = "deleting"
			e.Put("vpn_clients", client.ID, n, client)
			e.Reconcile()
			e.S.Remove("vpn_clients", client.ID)
		}
		client.State = "deleted"
		return D{"vpn_client": e.publicVPNClient(client, t), "dry_run": dry}
	}
	if str(e.P.Config["public_address"]) == "" {
		fail("conflict", "This site has no public address for a VPN endpoint")
	}
	key := str(a["public_key"])
	if !wgKey.MatchString(key) {
		fail("invalid", "public_key is a WireGuard public key (wg pubkey): 44 characters of base64", D{"recovery": "revise_request"})
	}
	if found && client.State == "deleting" {
		fail("conflict", "Finish removing this VPN client before reusing its name", D{"recovery": "finish_cleanup"})
	}
	for _, c := range e.vpnClients(n) {
		if c.PublicKey == key && c.Name != a["name"] {
			fail("conflict", "Another VPN client of this tenant already uses this key", D{"recovery": "revise_request"})
		}
	}
	hours := vpnHours
	if a["hours"] != nil {
		hours = integer(a["hours"])
	}
	if hours < 1 || hours > vpnMaxHours {
		fail("invalid", fmt.Sprintf("hours is 1 to %d", vpnMaxHours), D{"recovery": "revise_request"})
	}
	if !found {
		if len(e.vpnClients(n)) >= vpnClientLimit {
			fail("quota_exceeded", fmt.Sprintf("A tenant keeps at most %d VPN clients; remove one first", vpnClientLimit), D{"recovery": "revise_request"})
		}
		used := map[string]bool{}
		for _, c := range e.vpnClients(n) {
			used[c.Address] = true
		}
		for host := 2; host <= 254 && client.Address == ""; host++ {
			if address := fmt.Sprintf("10.201.%d.%d", n, host); !used[address] {
				client = vpnClient{ID: randomID()[:16], TenantN: n, Name: str(a["name"]), Address: address, CreatedAt: now()}
			}
		}
	}
	// Adding an existing name again renews it, with the key it is given.
	client.PublicKey, client.ExpiresAt, client.State = key, now()+float64(hours*3600), "ready"
	if dry {
		client.State = "planned"
		return D{"vpn_client": e.publicVPNClient(client, t), "dry_run": true}
	}
	e.Put("vpn_clients", client.ID, n, client)
	result := e.Reconcile()
	tunnels := obj(obj(result["node"])["vpn"])
	server := obj(tunnels[str(n)])
	if server["public_key"] == nil {
		fail("backend_unavailable", "The exit node did not bring up the tenant's VPN interface", D{"component": "carrel-node", "backend_code": "vpn_unavailable", "detail": tunnels["error"], "recovery": "retry_infrastructure"})
	}
	e.Put("vpn_servers", n, n, vpnServer{ID: str(n), TenantN: n, Port: integer(server["port"]), PublicKey: str(server["public_key"])})
	return D{"vpn_client": e.publicVPNClient(client, t), "dry_run": false}
}

// publicVPNClient is a client as members see it, with the WireGuard
// configuration to use once the tenant's interface exists.
func (e *Execution) publicVPNClient(c vpnClient, t D) D {
	n := integer(t["n"])
	out := D{"name": c.Name, "address": c.Address, "state": c.State, "reaches": fmt.Sprintf("10.200.%d.0/24", n)}
	if c.ExpiresAt > 0 {
		out["expires_at"] = time.Unix(int64(c.ExpiresAt), 0).UTC().Format(time.RFC3339)
	}
	if s, ok := rowOf[vpnServer](e.S, "vpn_servers", str(n)); ok && c.State == "ready" {
		// The address, not the origin's name: that name may one day sit
		// behind a proxy that carries no UDP.
		endpoint := fmt.Sprintf("%s:%d", str(e.P.Config["public_address"]), s.Port)
		out["endpoint"], out["server_public_key"] = endpoint, s.PublicKey
		out["config"] = fmt.Sprintf("[Interface]\nPrivateKey = <the private key of %s>\nAddress = %s/32\nMTU = %d\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = 10.200.%d.0/24\nPersistentKeepalive = 25\n",
			c.Name, c.Address, vpnClientMTU, s.PublicKey, endpoint, n)
	}
	return out
}

// ExpireVPNClients drops clients past their time. The caller holds the
// writer and reconciles afterwards.
func (e *Execution) ExpireVPNClients() {
	for _, c := range e.vpnClients() {
		if c.ExpiresAt > 0 && c.ExpiresAt <= now() {
			e.S.Remove("vpn_clients", c.ID)
			e.S.Log("system", c.TenantN, "vpn_client_expired", D{"name": c.Name}, "ok")
		}
	}
}
