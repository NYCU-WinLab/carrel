package carrel

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type fakeDNS struct {
	mu      sync.Mutex
	records map[string][]D
	writes  []D
}

func (f *fakeDNS) server(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var body D
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.Method != "GET" {
			f.writes = append(f.writes, D{"method": r.Method, "path": r.URL.Path, "body": body})
		}
		result := any(D{})
		if r.Method == "GET" {
			result = f.records[r.URL.Query().Get("name")]
			if result == nil {
				result = []D{}
			}
		}
		_ = json.NewEncoder(w).Encode(D{"success": true, "result": result})
	}))
	t.Cleanup(s.Close)
	return s
}

func originFixture(t *testing.T) (*Platform, *fakeBackend, *fakeDNS) {
	p, b := fixture(t)
	dns := &fakeDNS{records: map[string][]D{}}
	cf := dns.server(t)
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(tlsServer.Close)
	pair := tlsServer.TLS.Certificates[0]
	keyDER, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	must(err)
	base := t.TempDir()
	live := filepath.Join(base, "config", "live", "origin")
	must(os.MkdirAll(live, 0700))
	must(os.WriteFile(filepath.Join(live, "fullchain.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0600))
	must(os.WriteFile(filepath.Join(live, "privkey.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600))
	for k, v := range map[string]any{"cloudflare_api": cf.URL, "cloudflare_zone": "test", "certificate_dir": base, "certbot": "/bin/true",
		"ingress": "exit", "public_address": "140.113.60.184", "origin": "https://carrel.test"} {
		p.Config[k] = v
	}
	return p, b, dns
}

func TestDomainRecordsFollowTheSitesAddress(t *testing.T) {
	p, _, dns := originFixture(t)
	tenant := p.Store.TenantN(1)
	name := "*." + str(tenant["slug"]) + ".winlab.tw"
	dns.records[name] = []D{{"id": "r1", "content": "140.113.194.229", "comment": "carrel:b09:tenant:1"}}
	e := p.execution(context.Background())
	delete(p.Config, "public_address")
	e.DomainRecord(tenant, false)
	if len(dns.writes) != 0 {
		t.Fatalf("a control plane without public_address rewrote a record: %v", dns.writes)
	}
	p.Config["public_address"] = "140.113.60.184"
	e.DomainRecord(tenant, false)
	if len(dns.writes) != 1 || dns.writes[0]["method"] != "PATCH" || obj(dns.writes[0]["body"])["content"] != "140.113.60.184" {
		t.Fatal(encoded(dns.writes))
	}
	dns.records[name] = nil
	e.DomainRecord(tenant, false)
	if last := dns.writes[len(dns.writes)-1]; last["method"] != "POST" || obj(last["body"])["content"] != "140.113.60.184" {
		t.Fatal(encoded(last))
	}
}

func TestOriginRecordMovesOnlyAfterTheGatewayHasTheCertificate(t *testing.T) {
	p, b, dns := originFixture(t)
	dns.records["carrel.test"] = []D{{"id": "o1", "content": "140.113.194.229", "comment": edgeOriginOwner}}
	sent := D{}
	b.call = func(r D, target string) (any, error) {
		if r["op"] == "reconcile" && target == "carrel-node" {
			sent = obj(r["state"])
		}
		return D{}, nil
	}
	// Start without a lineage: the first pass issues (certbot is /bin/true here,
	// so the test puts the files back as certbot would).
	live := filepath.Join(str(p.Config["certificate_dir"]), "config", "live", "origin")
	moved := live + ".issued"
	must(os.Rename(live, moved))
	p.Config["certbot"] = writeCertbot(t, moved, live)
	e := p.execution(context.Background())
	e.MaintainOrigin()
	if _, err := os.Stat(live); err != nil || len(dns.writes) != 0 {
		t.Fatalf("first pass must only issue: %v %v", err, dns.writes)
	}
	e.MaintainOrigin()
	if len(dns.writes) != 0 {
		t.Fatal("moved the record before the gateway received the certificate")
	}
	e.Reconcile()
	if obj(sent["origin_certificate"])["privkey"] == nil {
		t.Fatal("the gateway did not receive the origin pair")
	}
	e.MaintainOrigin()
	if len(dns.writes) != 1 || dns.writes[0]["method"] != "PATCH" || obj(dns.writes[0]["body"])["content"] != "140.113.60.184" || obj(dns.writes[0]["body"])["comment"] != originOwner {
		t.Fatal(encoded(dns.writes))
	}
	dns.records["carrel.test"] = []D{{"id": "o1", "content": "1.2.3.4", "comment": "someone else"}}
	if err := attempt(func() { e.MaintainOrigin() }); err == nil {
		t.Fatal("rewrote a record owned outside carrel")
	}
}

func TestOriginIsLeftAloneOnEdgeSites(t *testing.T) {
	p, _, dns := originFixture(t)
	p.Config["ingress"] = "edge"
	p.execution(context.Background()).MaintainOrigin()
	if len(dns.writes) != 0 {
		t.Fatal("an edge site touched the origin")
	}
}

// writeCertbot returns a stand-in certbot that moves a prepared lineage into place.
func writeCertbot(t *testing.T, from, to string) string {
	path := filepath.Join(t.TempDir(), "certbot")
	must(os.WriteFile(path, []byte("#!/bin/sh\nmv "+from+" "+to+"\n"), 0700))
	return path
}
