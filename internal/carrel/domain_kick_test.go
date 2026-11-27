package carrel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A tenant whose wildcard certificate is late: the waiting pass arms a timer
// and the domain loop publishes the domain without the 300 s pass (#780).
func TestDomainRetriesWhenCertificateIsLate(t *testing.T) {
	p, _ := fixture(t)
	m := seedMachine(p, "web", 10100)
	cf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"result":[]}`))
	}))
	defer cf.Close()
	p.Config.CloudflareAPI, p.Config.CloudflareZone, p.Config.CertificateDir = cf.URL, "test", t.TempDir()
	// Origin issuance in the full pass must fail fast against the fake, never
	// reach real Let's Encrypt while holding the certificate lock.
	p.Config.ACMEDirectory = cf.URL
	crt, key := testPair(t, "*.alice.winlab.tw")
	p.execution(context.Background()).storeCertificate("alice", crt, key)
	p.Store.Put("certificates", "1", 1, D{"id": "1", "tenant_n": 1, "slug": "alice"})
	p.domainMinDelay = 50 * time.Millisecond
	var ready atomic.Bool
	p.certificatePrepare = func(D) D {
		if ready.Load() {
			return D{"state": "ready"}
		}
		return D{"state": "preparing", "ready_at": now() + 0.2}
	}
	runQueue(p)
	p.Start()
	p.Store.Put("domains", "late000000000001", 1, D{"id": "late000000000001", "tenant_n": 1, "vmid": m["vmid"], "sub": "late", "slug": "alice", "name": "late.alice.winlab.tw", "target_port": 8080, "state": "queued", "ready_at": 1})
	p.kickDomains()
	time.Sleep(100 * time.Millisecond)
	if d := p.Store.Get("domains", "late000000000001"); d["state"] == "ready" {
		t.Fatal("published before the certificate was ready")
	}
	ready.Store(true)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if d := p.Store.Get("domains", "late000000000001"); d["state"] == "ready" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the domain was not published after the certificate became ready")
}
