package carrel

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// A site with its own zone (#569): tenant names and SSH hints use it, and
// winlab.tw appears nowhere.
func TestASiteUsesItsOwnDomain(t *testing.T) {
	t.Cleanup(func() { specialZone, publicHost = defaultDomain, "carrel."+defaultDomain })
	p, _ := fixture(t)
	NewPlatform(p.Store, p.Backend, Config{Domain: "stg.example.org"}.WithDefaults())
	if specialZone != "stg.example.org" || publicHost != "carrel.stg.example.org" {
		t.Fatalf("zone %q host %q", specialZone, publicHost)
	}
	seedMachine(p, "dev", 10100)
	m := p.execution(context.Background()).PublicMachine(p.Store.Get("machines", "10100"), []portGrant{{VMID: 10100, Port: 22, Proto: "tcp", PublicPort: 20010}})
	if str(m["ssh"]) != "ssh -p 20010 user@carrel.stg.example.org" || !strings.Contains(str(m["ssh_config"]), "Host dev.alice dev.alice.stg.example.org\n  HostName carrel.stg.example.org\n") {
		t.Fatalf("machine %s", encoded(m))
	}
	var doc D
	_ = json.Unmarshal(servedOpenAPI("https://carrel.stg.example.org"), &doc)
	if url := obj(arr(doc["servers"])[0])["url"]; url != "https://carrel.stg.example.org" {
		t.Fatalf("openapi server %v", url)
	}
	if got := previewHost(p.Store.TenantN(1), "pr-1"); got != "pr-1.alice.stg.example.org" {
		t.Fatalf("preview host %s", got)
	}
	bad := p.Config
	bad.Domain = "Not A Zone"
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "domain") {
		t.Fatalf("validate: %v", err)
	}
}

// The gateway serves an origin and tenant sites in the site's own zone,
// and refuses an origin outside it.
func TestGatewayServesASiteInItsOwnDomain(t *testing.T) {
	t.Cleanup(func() { specialZone, publicHost = defaultDomain, "carrel."+defaultDomain })
	specialZone, publicHost = "stg.example.org", "carrel.stg.example.org"
	crt, key := testPair(t, "*.alice.stg.example.org")
	originCrt, originKey := testPair(t, "carrel.stg.example.org")
	state := D{
		"tenants":      []any{D{"n": 1, "slug": "alice"}},
		"machines":     []any{D{"vmid": 10100, "tenant_n": 1, "name": "web", "ip": "10.200.1.10"}},
		"domains":      []any{D{"id": "1", "vmid": 10100, "sub": "web", "name": "web.alice.stg.example.org", "target_port": 3000, "state": "ready"}},
		"certificates": []any{D{"slug": "alice", "fullchain": string(crt), "privkey": string(key)}},
	}
	origin := D{"fullchain": string(originCrt), "privkey": string(originKey)}
	caddy, _, certificates := gatewayConfig(state, "carrel.stg.example.org", origin, dicts(state["certificates"]))
	if certificates["_origin"] == nil || !strings.Contains(caddy, "https://*.alice.stg.example.org {") || strings.Contains(caddy, "winlab.tw") {
		t.Fatalf("caddy:\n%s", caddy)
	}
	if attempt(func() { gatewayConfig(state, "carrel.winlab.tw", origin, dicts(state["certificates"])) }) == nil {
		t.Fatal("an origin outside the site's zone was accepted")
	}
}
