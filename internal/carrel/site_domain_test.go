package carrel

import (
	"context"
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
	if got := previewHost(p.Store.TenantN(1), "pr-1"); got != "pr-1.alice.stg.example.org" {
		t.Fatalf("preview host %s", got)
	}
	bad := p.Config
	bad.Domain = "Not A Zone"
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "domain") {
		t.Fatalf("validate: %v", err)
	}
}
