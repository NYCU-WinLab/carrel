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

// testPair returns a self-signed certificate for names (carrel.winlab.tw by
// default) and its key, as PEM.
func testPair(t *testing.T, names ...string) ([]byte, []byte) {
	t.Helper()
	if len(names) == 0 {
		names = []string{"carrel.winlab.tw"}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	must(err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	must(err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func originFixture(t *testing.T) (*Platform, *fakeBackend, *fakeDNS) {
	p, b := fixture(t)
	dns := &fakeDNS{records: map[string][]D{}}
	cf := dns.server(t)
	p.Config.CloudflareAPI, p.Config.CloudflareZone, p.Config.CertificateDir = cf.URL, "test", t.TempDir()
	p.Config.Origin = "https://carrel.winlab.tw"
	crt, key := testPair(t)
	p.issue = func(context.Context, string) ([]byte, []byte, error) { return crt, key, nil }
	p.execution(context.Background()).storeCertificate(originLineage, crt, key)
	return p, b, dns
}

func TestDomainRecordsFollowTheSitesAddress(t *testing.T) {
	p, b, dns := originFixture(t)
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
	b.call = func(r D, _ string) (any, error) {
		return D{"certificates": D{str(tenant["slug"]): fingerprint(string(chain))}}, nil
	}
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
	dns.records["carrel.winlab.tw"] = []D{{"id": "o1", "content": "140.113.194.229", "comment": originOwner}}
	sent := D{}
	confirm := true
	// What the fake gateway serves: the fingerprints of the last pairs it took.
	served := D{}
	b.call = func(r D, target string) (any, error) {
		if r["op"] == "sync" && target == "carrel-gateway" {
			sent = r
			if !confirm {
				return nil, Failure{D{"ok": false, "error": D{"code": "backend_unavailable"}}}
			}
			served = D{}
			for name, pair := range obj(r["certificates"]) {
				served[name] = fingerprint(obj(pair)["fullchain"])
			}
		}
		if r["op"] == "status" && target == "carrel-gateway" {
			return D{"certificates": served}, nil
		}
		return D{}, nil
	}
	// Start without a pair: the first pass issues.
	live := filepath.Join(p.Config.CertificateDir, "live", originLineage)
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
	// A gateway that refuses the pair holds nothing.
	confirm = false
	fastGatewayRetries(t)
	e.Reconcile()
	settleGateway(t, p)
	if p.gateway.Status().Err == nil {
		t.Fatal("a failed gateway sync passed")
	}
	e.MaintainOrigin()
	if len(dns.writes) != 0 {
		t.Fatal("moved the record although the gateway did not confirm the pair")
	}
	confirm = true
	e.Reconcile()
	settleGateway(t, p)
	if obj(obj(sent["certificates"])["_origin"])["privkey"] == nil {
		t.Fatal("the gateway did not receive the origin pair")
	}
	e.MaintainOrigin()
	if len(dns.writes) != 1 || dns.writes[0]["method"] != "PATCH" || obj(dns.writes[0]["body"])["content"] != "140.113.60.184" {
		t.Fatal(encoded(dns.writes))
	}
	// A gateway restored from an older snapshot no longer serves the pair,
	// although the acknowledgement kept in memory still matches (issue #801).
	dns.records["carrel.winlab.tw"] = []D{{"id": "o1", "content": "140.113.194.229", "comment": originOwner}}
	served = D{}
	before := len(dns.writes)
	e.MaintainOrigin()
	if len(dns.writes) != before {
		t.Fatal("moved the record although the gateway no longer serves the pair")
	}
	e.Reconcile()
	settleGateway(t, p)
	e.MaintainOrigin()
	if len(dns.writes) != before+1 {
		t.Fatal("did not move the record once the gateway served the pair again")
	}
	dns.records["carrel.winlab.tw"] = []D{{"id": "o1", "content": "1.2.3.4", "comment": "someone else"}}
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
	generations, err := os.ReadDir(filepath.Join(p.Config.CertificateDir, "archive", originLineage))
	if err != nil || len(generations) != 3 {
		t.Fatalf("kept %d generations", len(generations))
	}
	if _, err := os.Stat(before); !os.IsNotExist(err) || beforeKey == key {
		t.Fatal("kept the oldest generation")
	}
	link, err := os.Readlink(filepath.Join(p.Config.CertificateDir, "live", originLineage))
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
		if name != "_acme-challenge.carrel.winlab.tw." {
			t.Fatalf("looked up %s", name)
		}
		a := answers[0]
		if len(answers) > 1 {
			answers = answers[1:]
		}
		return a, nil
	}
	e := p.execution(context.Background())
	if err := e.waitTXT(context.Background(), "_acme-challenge.carrel.winlab.tw", "value"); err != nil || len(answers) != 1 {
		t.Fatal("did not wait for the value", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := e.waitTXT(ctx, "_acme-challenge.carrel.winlab.tw", "missing"); err == nil {
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

// Issue #51: a failing origin issuance is retried later each time.
func TestOriginRetriesBackOff(t *testing.T) {
	var b backoff
	calls := 0
	failing := func() { calls++; fail("backend_unavailable", "acme down") }
	start := time.Now()
	for i, at := range []time.Duration{0, 5 * time.Minute, 10 * time.Minute, 25 * time.Minute, 30 * time.Minute} {
		b.try(start.Add(at), failing)
		if want := []int{1, 1, 2, 2, 3}[i]; calls != want {
			t.Fatalf("at %v: %d attempts, want %d", at, calls, want)
		}
	}
	if b.wait != 40*time.Minute {
		t.Fatal(b.wait)
	}
	for range 20 {
		b.try(b.next, failing)
	}
	if b.wait != 6*time.Hour {
		t.Fatal("no cap", b.wait)
	}
	if b.try(b.next, func() {}) != nil || b.wait != 0 {
		t.Fatal("a success did not reset")
	}
}

// An unreadable certificate is an infrastructure failure, so the post-delete
// reconcile tolerates it instead of treating it as a bug (#316).
func TestOriginPairReportsAnUnreadableCertificateAsFailure(t *testing.T) {
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	for _, present := range []string{"", crt} {
		if present != "" {
			must(os.WriteFile(present, []byte("pem"), 0o600))
		}
		f, ok := attempt(func() { originPair(crt, key) }).(Failure)
		if !ok {
			t.Fatalf("a missing file was not a Failure (present=%q)", present)
		}
		if e := obj(f.Result["error"]); e["code"] != "backend_unavailable" || e["recovery"] != "retry_infrastructure" {
			t.Fatalf("unexpected failure: %v", f.Result)
		}
	}
}

// A store read failure is an infrastructure Failure for every caller of Rows (#319).
func TestStoreRowsReportsReadFailureAsFailure(t *testing.T) {
	s, e := OpenStore(":memory:")
	must(e)
	f, ok := attempt(func() { s.Rows("SELECT * FROM no_such_table") }).(Failure)
	if !ok {
		t.Fatal("a failed read was not a Failure")
	}
	if e := obj(f.Result["error"]); e["code"] != "backend_unavailable" || e["recovery"] != "retry_infrastructure" || str(e["message"]) != "The store could not be read" {
		t.Fatalf("unexpected failure: %v", f.Result)
	}
}

// A site with no tenant reconciles only to send the gateway its origin pair,
// and never over nodes that another database configured (#569).
func TestASiteWithoutTenantsReconcilesOnlyForItsOrigin(t *testing.T) {
	p, b, _ := originFixture(t)
	e := p.execution(context.Background())
	if !e.maintenanceReconciles() || b.count("inventory") != 0 {
		t.Fatal("a site with tenants reconciles without asking the node")
	}
	p.Store.Exec("DELETE FROM objects")
	p.Store.Exec("DELETE FROM tenants")
	if len(p.Store.Tenants()) != 0 {
		t.Fatal("tenants left")
	}
	held := any(nil)
	// What the fake gateway serves: the fingerprints of the last pairs it took.
	served := D{}
	b.call = func(r D, target string) (any, error) {
		if r["op"] == "inventory" {
			return D{"desired": D{"revision": held}}, nil
		}
		if r["op"] == "sync" && target == "carrel-gateway" {
			served = D{}
			for name, pair := range obj(r["certificates"]) {
				served[name] = fingerprint(obj(pair)["fullchain"])
			}
		}
		if r["op"] == "status" && target == "carrel-gateway" {
			return D{"certificates": served}, nil
		}
		return D{}, nil
	}
	// A new site: the node holds nothing yet.
	if !e.maintenanceReconciles() {
		t.Fatal("a new site must reconcile to send the gateway its origin pair")
	}
	// An empty database in front of nodes another database configured.
	held = "f00d"
	if e.maintenanceReconciles() {
		t.Fatal("reconciled over nodes this database did not configure")
	}
	// The node holds what this database sent: safe again.
	held = nil
	e.Reconcile()
	settleGateway(t, p)
	if e.maintenanceReconciles() {
		t.Fatal("the gateway holds the pair: nothing to do")
	}
	held = obj(p.Store.SiteGet("reconcile", "sent"))["revision"]
	if held == nil {
		t.Fatal("reconcile did not record the revision it sent")
	}
	// A renewed pair on the same site goes out again.
	crt, key := testPair(t)
	e.storeCertificate(originLineage, crt, key)
	if !e.maintenanceReconciles() {
		t.Fatal("a renewed pair must reach the gateway")
	}
	// No origin host: the gateway never gets an origin site.
	p.Config.Origin = ""
	if e.maintenanceReconciles() {
		t.Fatal("reconciled for an origin that is not configured")
	}
}

// On a site with no tenant, a failed send and a lost reply both leave the
// node at a revision the gate accepts, while a revision this database never
// sent stays refused (#806).
func TestReconcileGateAcceptsTheAcknowledgedAndThePendingRevision(t *testing.T) {
	p, b, _ := originFixture(t)
	p.Store.Exec("DELETE FROM objects")
	p.Store.Exec("DELETE FROM tenants")
	e := p.execution(context.Background())
	held := any(nil)
	// How the node answers a reconcile: apply then reply, fail before
	// applying, or apply and lose the reply.
	mode := "ok"
	b.call = func(r D, target string) (any, error) {
		switch {
		case r["op"] == "inventory":
			return D{"desired": D{"revision": held}}, nil
		case r["op"] == "reconcile" && target == p.Nodes()[0].Target:
			if mode == "refused" {
				return nil, errors.New("connection refused")
			}
			held = r["revision"]
			if mode == "lost" {
				return nil, errors.New("reply lost")
			}
		}
		// The gateway never confirms the pair, so the origin always awaits it.
		return D{}, nil
	}
	sent := func() D { return obj(p.Store.SiteGet("reconcile", "sent")) }
	e.Reconcile()
	a := held
	if a == nil || sent()["revision"] != a || sent()["previous"] != nil {
		t.Fatal("an acknowledged reconcile must record only its revision: " + string(encoded(sent())))
	}
	// (a) The state changes and the send fails before the node applies it.
	p.Config.Fetch = true
	mode = "refused"
	attempt(func() { e.Reconcile() })
	if held != a || sent()["revision"] == a || sent()["previous"] != a {
		t.Fatal("a failed send must keep the acknowledged revision: " + string(encoded(sent())))
	}
	if !e.maintenanceReconciles() {
		t.Fatal("a failed send blocked the gate")
	}
	// A second failed send keeps the revision the node acknowledged.
	p.Config.Fetch = false
	attempt(func() { e.Reconcile() })
	p.Config.Fetch = true
	attempt(func() { e.Reconcile() })
	if sent()["previous"] != a || !e.maintenanceReconciles() {
		t.Fatal("repeated failed sends lost the acknowledged revision: " + string(encoded(sent())))
	}
	// (b) The node applies the new state and the reply is lost.
	mode = "lost"
	attempt(func() { e.Reconcile() })
	if held == a || held != sent()["revision"] {
		t.Fatal("the node did not apply the new state")
	}
	if !e.maintenanceReconciles() {
		t.Fatal("a lost reply blocked the gate")
	}
	// (c) A revision this database never sent stays refused.
	held = "f00d"
	if e.maintenanceReconciles() {
		t.Fatal("reconciled over nodes this database did not configure")
	}
	// A later acknowledged reconcile drops the pending marker.
	mode = "ok"
	e.Reconcile()
	if _, pending := sent()["previous"]; pending || sent()["revision"] != held {
		t.Fatal("an acknowledged reconcile kept the previous revision: " + string(encoded(sent())))
	}
}
