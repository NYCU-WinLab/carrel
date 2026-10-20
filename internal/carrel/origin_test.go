package carrel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
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

// testPair returns a certificate and its key as PEM.
func testPair(t *testing.T) ([]byte, []byte) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(tlsServer.Close)
	pair := tlsServer.TLS.Certificates[0]
	keyDER, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	must(err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func originFixture(t *testing.T) (*Platform, *fakeBackend, *fakeDNS) {
	p, b := fixture(t)
	dns := &fakeDNS{records: map[string][]D{}}
	cf := dns.server(t)
	for k, v := range map[string]any{"cloudflare_api": cf.URL, "cloudflare_zone": "test", "certificate_dir": t.TempDir(),
		"origin": "https://carrel.test"} {
		p.Config[k] = v
	}
	crt, key := testPair(t)
	p.issue = func(context.Context, string) ([]byte, []byte, error) { return crt, key, nil }
	p.execution(context.Background()).storeCertificate(originLineage, crt, key)
	return p, b, dns
}

func TestDomainRecordsFollowTheSitesAddress(t *testing.T) {
	p, _, dns := originFixture(t)
	tenant := p.Store.TenantN(1)
	name := "*." + str(tenant["slug"]) + ".winlab.tw"
	dns.records[name] = []D{{"id": "r1", "content": "140.113.194.229", "comment": "carrel:b09:tenant:1"}}
	chain, key := testPair(t)
	p.Store.Put("certificates", "1", 1, D{"id": "1", "tenant_n": 1, "slug": tenant["slug"]})
	e := p.execution(context.Background())
	e.storeCertificate(str(tenant["slug"]), chain, key)
	e.DomainRecord(tenant, false)
	if len(dns.writes) != 0 {
		t.Fatal("moved a tenant record before the gateway confirmed its certificate")
	}
	p.delivered.Store(map[string]any{str(tenant["slug"]): fingerprint(string(chain))})
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
	dns.records["carrel.test"] = []D{{"id": "o1", "content": "140.113.194.229", "comment": originOwner}}
	sent := D{}
	confirm := true
	b.call = func(r D, target string) (any, error) {
		if r["op"] == "reconcile" && target == "carrel-node" {
			sent = obj(r["state"])
			if pair := obj(sent["origin_certificate"]); confirm && pair["fullchain"] != nil {
				return D{"certificates": D{"_origin": fingerprint(pair["fullchain"])}}, nil
			}
		}
		return D{}, nil
	}
	// Start without a pair: the first pass issues.
	live := filepath.Join(str(p.Config["certificate_dir"]), "live", originLineage)
	must(os.Remove(live))
	e := p.execution(context.Background())
	e.MaintainOrigin()
	if _, err := os.Stat(live); err != nil || len(dns.writes) != 0 {
		t.Fatalf("first pass must only issue: %v %v", err, dns.writes)
	}
	e.MaintainOrigin()
	if len(dns.writes) != 0 {
		t.Fatal("moved the record before the gateway received the certificate")
	}
	// A node without the gateway reconciles fine but confirms nothing.
	confirm = false
	e.Reconcile()
	e.MaintainOrigin()
	if len(dns.writes) != 0 {
		t.Fatal("moved the record although the gateway did not confirm the pair")
	}
	confirm = true
	e.Reconcile()
	if obj(sent["origin_certificate"])["privkey"] == nil {
		t.Fatal("the gateway did not receive the origin pair")
	}
	e.MaintainOrigin()
	if len(dns.writes) != 1 || dns.writes[0]["method"] != "PATCH" || obj(dns.writes[0]["body"])["content"] != "140.113.60.184" {
		t.Fatal(encoded(dns.writes))
	}
	dns.records["carrel.test"] = []D{{"id": "o1", "content": "1.2.3.4", "comment": "someone else"}}
	if err := attempt(func() { e.MaintainOrigin() }); err == nil {
		t.Fatal("rewrote a record owned outside carrel")
	}
}

func TestATenantNamedOriginCannotTakeCarrelsLineage(t *testing.T) {
	p, _, _ := originFixture(t)
	e := p.execution(context.Background())
	ours, _, _ := e.originFiles()
	chain, key := testPair(t)
	e.storeCertificate("origin", chain, key)
	crt, _, ok := e.originFiles()
	if !ok || crt != ours {
		t.Fatalf("origin read %s", crt)
	}
}

func TestARenewedPairReplacesTheLiveOneWhole(t *testing.T) {
	p, _, _ := originFixture(t)
	e := p.execution(context.Background())
	before, beforeKey, _ := e.originFiles()
	for range 4 {
		chain, key := testPair(t)
		e.storeCertificate(originLineage, chain, key)
	}
	crt, key, ok := e.originFiles()
	if !ok || crt == before {
		t.Fatal("renewal did not move the live pair")
	}
	if _, err := tls.LoadX509KeyPair(crt, key); err != nil {
		t.Fatal("the live pair does not match")
	}
	generations, err := os.ReadDir(filepath.Join(str(p.Config["certificate_dir"]), "archive", originLineage))
	if err != nil || len(generations) != 3 {
		t.Fatalf("kept %d generations", len(generations))
	}
	if _, err := os.Stat(before); !os.IsNotExist(err) || beforeKey == key {
		t.Fatal("kept the oldest generation")
	}
	link, err := os.Readlink(filepath.Join(str(p.Config["certificate_dir"]), "live", originLineage))
	if err != nil || filepath.IsAbs(link) {
		t.Fatalf("live link %q must be relative for restored backups", link)
	}
	chain, _ := testPair(t)
	if f := attempt(func() { e.storeCertificate(originLineage, chain, []byte("other key")) }); f == nil {
		t.Fatal("stored a mismatched pair")
	}
}

func TestACurrentOriginIsNotOrderedAgain(t *testing.T) {
	p, _, _ := originFixture(t)
	orders := 0
	p.issue = func(context.Context, string) ([]byte, []byte, error) {
		orders++
		return nil, nil, errors.New("unexpected order")
	}
	e := p.execution(context.Background())
	if e.EnsureOriginCertificate()["state"] != "ready" || orders != 0 {
		t.Fatal("ordered a certificate that is not due")
	}
}

func TestChallengeWaitsUntilTheResolverServesIt(t *testing.T) {
	p, _, _ := originFixture(t)
	answers := [][]string{nil, {"old"}, {"old", "value"}}
	p.lookupTXT = func(_ context.Context, name string) ([]string, error) {
		if name != "_acme-challenge.carrel.test." {
			t.Fatalf("looked up %s", name)
		}
		a := answers[0]
		if len(answers) > 1 {
			answers = answers[1:]
		}
		return a, nil
	}
	e := p.execution(context.Background())
	if err := e.waitTXT(context.Background(), "_acme-challenge.carrel.test", "value"); err != nil || len(answers) != 1 {
		t.Fatal("did not wait for the value", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := e.waitTXT(ctx, "_acme-challenge.carrel.test", "missing"); err == nil {
		t.Fatal("accepted a record the resolver never served")
	}
}

func TestRenewalIsDueWithAThirdOfTheLifetimeLeft(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	for _, c := range []struct {
		left, lifetime time.Duration
		due            bool
	}{{50 * 24 * time.Hour, 90 * 24 * time.Hour, false}, {29 * 24 * time.Hour, 90 * 24 * time.Hour, true}, {7 * 24 * time.Hour, 20 * 24 * time.Hour, false}, {6 * 24 * time.Hour, 20 * 24 * time.Hour, true}} {
		end := time.Now().Add(c.left)
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: end.Add(-c.lifetime), NotAfter: end}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
		must(err)
		path := filepath.Join(t.TempDir(), "fullchain.pem")
		must(os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
		if renewalDue(path) != c.due {
			t.Fatalf("%v left of %v: due %v", c.left, c.lifetime, !c.due)
		}
	}
	if !renewalDue(filepath.Join(t.TempDir(), "missing.pem")) {
		t.Fatal("a missing certificate must be renewed")
	}
}
