package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NYCU-WinLab/carrel/internal/carrel"
)

const (
	testName = "pve1.b09.agent.carrel.winlab.tw"
	testKid  = "carrel-agents-kid"
)

// testCA stands in for the lab step-ca: it signs client certificates with
// the step provisioner extension, as step-ca does, for a name it is told.
type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	// name is the name it puts in certificates; life is how long they last.
	name   string
	life   time.Duration
	serial atomic.Int64
	renews atomic.Int32
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	ca := &testCA{key: key, cert: cert, name: testName, life: 7 * 24 * time.Hour}
	ca.serial.Store(1)
	return ca
}

func (ca *testCA) pem() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}))
}

func (ca *testCA) sign(t *testing.T, pub any, notBefore time.Time) string {
	t.Helper()
	ext, _ := asn1.Marshal(struct {
		Type         int
		Name         []byte
		CredentialID []byte
	}{1, []byte("carrel-agents"), []byte(testKid)})
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(ca.serial.Add(1)), Subject: pkix.Name{CommonName: ca.name},
		DNSNames: []string{ca.name}, NotBefore: notBefore, NotAfter: notBefore.Add(ca.life),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37476, 9000, 64, 1}, Value: ext}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// server is the CA's HTTPS API: /1.0/sign takes a CSR and the token "ott",
// /1.0/renew a client certificate it issued.
func (ca *testCA) server(t *testing.T) *httptest.Server {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/1.0/sign":
			var in struct{ CSR, OTT string }
			_ = json.NewDecoder(r.Body).Decode(&in)
			block, _ := pem.Decode([]byte(in.CSR))
			if in.OTT != "ott" || block == nil {
				http.Error(w, `{"message":"unauthorized"}`, 401)
				return
			}
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil || csr.CheckSignature() != nil {
				http.Error(w, `{"message":"bad csr"}`, 400)
				return
			}
			_ = json.NewEncoder(w).Encode(caAnswer{Certificate: ca.sign(t, csr.PublicKey, time.Now().Add(-time.Minute)), CA: ca.pem()})
		case "/1.0/renew":
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, `{"message":"no certificate"}`, 401)
				return
			}
			ca.renews.Add(1)
			leaf := r.TLS.PeerCertificates[0]
			_ = json.NewEncoder(w).Encode(caAnswer{Certificate: ca.sign(t, leaf.PublicKey, time.Now().Add(-time.Minute)), CA: ca.pem()})
		default:
			http.NotFound(w, r)
		}
	}))
	s.TLS = &tls.Config{ClientCAs: pool, ClientAuth: tls.VerifyClientCertIfGiven}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func certificateAgent(t *testing.T, dir, control, controlCA, caURL, labRoot string, token bool) *agent {
	t.Helper()
	c := config{Control: control, CAFile: controlCA, TokenFile: filepath.Join(dir, "token"), Node: "pve1",
		CertFile: filepath.Join(dir, "agent.crt"), KeyFile: filepath.Join(dir, "agent.key"),
		CertificateName: testName, CAURL: caURL, LabRootFile: labRoot}
	if token {
		writeFile(t, dir, "token", "agent-token\n")
	}
	conf, _ := json.Marshal(c)
	a, err := load(writeFile(t, dir, "agent.json", string(conf)))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// Enrolling writes a new key and the chain; renewing keeps the key and
// replaces the chain; neither takes a certificate for another name.
func TestEnrollAndRenew(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	server := ca.server(t)
	// The CA's HTTPS certificate is httptest's own, so its root is the lab
	// root the agent trusts for the CA.
	labRoot := writeFile(t, dir, "lab-root.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})))
	a := certificateAgent(t, dir, "https://127.0.0.1:1", labRoot, server.URL, labRoot, false)
	if a.cert.Load() != nil || a.token != "" {
		t.Fatal("an agent with no certificate and no token yet has one")
	}
	if err := a.enroll(context.Background(), "wrong"); err == nil {
		t.Fatal("enrolled with a wrong token")
	}
	if _, err := os.Stat(a.cfg.KeyFile); !os.IsNotExist(err) {
		t.Fatal("a refused enrolment left a key behind")
	}
	if err := a.enroll(context.Background(), "ott"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(a.cfg.KeyFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", info, err)
	}
	first := a.cert.Load()
	if first == nil || first.Leaf.DNSNames[0] != testName || len(first.Certificate) != 2 {
		t.Fatalf("enrolled certificate: %+v", first)
	}
	key, _ := os.ReadFile(a.cfg.KeyFile)

	time.Sleep(10 * time.Millisecond)
	if err := a.renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := a.cert.Load()
	if second.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) == 0 || ca.renews.Load() != 1 {
		t.Fatal("renewing kept the old certificate")
	}
	if after, _ := os.ReadFile(a.cfg.KeyFile); string(after) != string(key) {
		t.Fatal("renewing replaced the key")
	}
	// A restarted agent loads what it saved.
	again := certificateAgent(t, dir, "https://127.0.0.1:1", labRoot, server.URL, labRoot, false)
	if c := again.cert.Load(); c == nil || c.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) != 0 {
		t.Fatal("a restarted agent did not load its certificate")
	}

	ca.name = "pve2.b09.agent.carrel.winlab.tw"
	if err := a.renew(context.Background()); err == nil || !strings.Contains(err.Error(), "not "+testName) {
		t.Fatalf("took a certificate for another name: %v", err)
	}
	if a.cert.Load() != second {
		t.Fatal("a refused renewal replaced the certificate")
	}
}

func TestRenewDue(t *testing.T) {
	start := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{NotBefore: start, NotAfter: start.Add(168 * time.Hour)}
	for at, want := range map[time.Duration]bool{0: false, 55 * time.Hour: false, 57 * time.Hour: true, 200 * time.Hour: true} {
		if got := renewDue(leaf, start.Add(at)); got != want {
			t.Errorf("%v: %v", at, got)
		}
	}
}

// A real platform on certificate sign-in, and an agent with a certificate
// and no token: a node call runs through the agent.
func TestAgentSignsInWithItsCertificate(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	labRoot := writeFile(t, dir, "ca-root.pem", ca.pem())
	store, err := carrel.OpenStore(filepath.Join(dir, "carrel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	cfg := carrel.Config{AgentClientCAFile: labRoot, AgentProvisioner: testKid, Nodes: []carrel.NodeConfig{
		{Name: "pve1", Target: "carrel-node", Transport: "agent", AgentSource: "127.0.0.1", AgentCertificate: testName},
	}}
	p := carrel.NewPlatform(store, sshOnly{}, cfg)
	p.UseAgents()
	server := httptest.NewUnstartedServer(p.AgentHandler())
	// As cmd/carrel sets it: the handshake asks, the handler checks.
	server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	defer server.Close()
	controlCA := writeFile(t, dir, "control-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})))

	// The certificate is made here, not enrolled: enrolment has its own test.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	writeFile(t, dir, "agent.key", string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})))
	writeFile(t, dir, "agent.crt", ca.sign(t, &key.PublicKey, time.Now().Add(-time.Minute)))
	a := certificateAgent(t, dir, server.URL, controlCA, "https://127.0.0.1:1", labRoot, false)
	a.session = "s1"
	a.run = func(context.Context, []byte) ([]byte, bool) {
		return []byte(`{"ok":true,"result":{"via":"agent"}}`), false
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.loop(ctx); close(done) }()
	defer func() { stop(); <-done }()

	call, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	v, err := p.Backend.Call(call, carrel.D{"op": "status"}, "carrel-node")
	if err != nil || v.(map[string]any)["via"] != "agent" {
		t.Fatalf("agent node: %v %v", v, err)
	}
	if st := p.Hub.Status("pve1", time.Now()); st["certificate_expires"] == nil || st["certificate_expiring"] != false {
		t.Fatalf("status: %v", st)
	}
}

// A node still on its token signs in even when its agent presents a
// certificate the control plane would refuse: the handshake does not check
// it, so going back to the token never depends on the certificate.
func TestATokenNodeIgnoresAForeignCertificate(t *testing.T) {
	dir := t.TempDir()
	labRoot := writeFile(t, dir, "ca-root.pem", newTestCA(t).pem())
	store, err := carrel.OpenStore(filepath.Join(dir, "carrel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	sum := sha256.Sum256([]byte("agent-token"))
	cfg := carrel.Config{AgentClientCAFile: labRoot, AgentProvisioner: testKid, Nodes: []carrel.NodeConfig{
		{Name: "pve1", Target: "carrel-node", Transport: "agent", AgentSource: "127.0.0.1", AgentTokenSHA256: hex.EncodeToString(sum[:])},
	}}
	p := carrel.NewPlatform(store, sshOnly{}, cfg)
	p.UseAgents()
	server := httptest.NewUnstartedServer(p.AgentHandler())
	server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	defer server.Close()
	controlCA := writeFile(t, dir, "control-ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})))
	// Signed by a CA the control plane does not trust.
	foreign := newTestCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	writeFile(t, dir, "agent.key", string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})))
	writeFile(t, dir, "agent.crt", foreign.sign(t, &key.PublicKey, time.Now().Add(-time.Minute)))
	a := certificateAgent(t, dir, server.URL, controlCA, "https://127.0.0.1:1", labRoot, true)
	if a.cert.Load() == nil {
		t.Fatal("the foreign certificate was not loaded, so the test proves nothing")
	}
	a.session = "s1"
	a.run = func(context.Context, []byte) ([]byte, bool) {
		return []byte(`{"ok":true,"result":{"via":"agent"}}`), false
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.loop(ctx); close(done) }()
	defer func() { stop(); <-done }()
	call, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if v, err := p.Backend.Call(call, carrel.D{"op": "status"}, "carrel-node"); err != nil || v.(map[string]any)["via"] != "agent" {
		t.Fatalf("token node with a foreign certificate: %v %v", v, err)
	}
}

// A key and certificate that do not match (an enrolment cut short) leave the
// agent on its token rather than stopping it, and enrolling again fixes them.
func TestABrokenPairDoesNotStopTheAgent(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	server := ca.server(t)
	labRoot := writeFile(t, dir, "lab-root.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})))
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	writeFile(t, dir, "agent.key", string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})))
	writeFile(t, dir, "agent.crt", ca.sign(t, &other.PublicKey, time.Now().Add(-time.Minute)))
	a := certificateAgent(t, dir, "https://127.0.0.1:1", labRoot, server.URL, labRoot, true)
	if a.cert.Load() != nil || a.token != "agent-token" {
		t.Fatal("a broken pair was taken into use, or the token was lost")
	}
	if err := a.enroll(context.Background(), "ott"); err != nil || a.cert.Load() == nil {
		t.Fatalf("enrolling again: %v", err)
	}
	if again := certificateAgent(t, dir, "https://127.0.0.1:1", labRoot, server.URL, labRoot, true); again.cert.Load() == nil {
		t.Fatal("the new pair does not load")
	}
	if _, err := os.Stat(a.cfg.KeyFile + ".next"); !os.IsNotExist(err) {
		t.Fatal("a staged file was left behind")
	}
}

// An expired certificate is not presented.
func TestAnExpiredCertificateIsNotPresented(t *testing.T) {
	a := &agent{}
	a.cert.Store(&tls.Certificate{Certificate: [][]byte{{1}}, Leaf: &x509.Certificate{NotAfter: time.Now().Add(-time.Minute)}})
	if c, _ := a.clientCertificate(nil); len(c.Certificate) != 0 {
		t.Fatal("presented an expired certificate")
	}
}
