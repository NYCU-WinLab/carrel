package carrel

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// The certificates in testdata/agent-certificates come from a real step-ca
// 0.30: root.crt and int.crt are its chain, carrel01.crt (leaf and
// intermediate) is from the carrel-agents JWK provisioner, admin.crt from
// another one.
const (
	agentDir         = "testdata/agent-certificates/"
	agentProvisioner = "5Ys6ZRy1hvsI-FHi_831uQptxvkKQ3vtGxyz-TzbwGw"
	agentNameB09     = "carrel01.b09.agent.carrel.winlab.tw"
)

func readChain(t *testing.T, name string) []*x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(agentDir + name)
	if err != nil {
		t.Fatal(err)
	}
	var out []*x509.Certificate
	for {
		var block *pem.Block
		if block, data = pem.Decode(data); block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		t.Fatalf("%s holds no certificate", name)
	}
	return out
}

func agentIdentityFixture(t *testing.T) (*Platform, NodeConfig) {
	t.Helper()
	p, _, _ := originFixture(t)
	p.Config.AgentClientCAFile, p.Config.AgentProvisioner = agentDir+"root.crt", agentProvisioner
	n := NodeConfig{Name: "carrel01", Target: "carrel01", Transport: "agent", AgentTokenSHA256: digest("cat_good"),
		AgentSource: "10.200.0.1", AgentCertificate: agentNameB09}
	p.Config.Nodes = []NodeConfig{n}
	return p, n
}

func TestStepProvisionerIsReadFromARealCertificate(t *testing.T) {
	if got := stepProvisionerOf(readChain(t, "carrel01.crt")[0]); got != agentProvisioner {
		t.Fatalf("carrel01: %q", got)
	}
	if got := stepProvisionerOf(readChain(t, "admin.crt")[0]); got == "" || got == agentProvisioner {
		t.Fatalf("admin: %q", got)
	}
	if got := stepProvisionerOf(readChain(t, "root.crt")[0]); got != "" {
		t.Fatalf("root names a provisioner: %q", got)
	}
}

// The certificate is checked at the request's time, for the node's name, the
// lab root and the agents' provisioner.
func TestAgentCertificateChecks(t *testing.T) {
	p, n := agentIdentityFixture(t)
	chain := readChain(t, "carrel01.crt")
	leaf := chain[0]
	during := leaf.NotBefore.Add(time.Hour)
	state := &tls.ConnectionState{PeerCertificates: chain}
	if expires, ok := p.agentCertificate(n, state, during); !ok || !expires.Equal(leaf.NotAfter) {
		t.Fatalf("valid certificate: %v %v", expires, ok)
	}
	other := n
	other.AgentCertificate = "carrel02.b09.agent.carrel.winlab.tw"
	admin := readChain(t, "admin.crt")
	for name, c := range map[string]struct {
		node  NodeConfig
		state *tls.ConnectionState
		at    time.Time
	}{
		"another node's name": {other, state, during},
		"expired":             {n, state, leaf.NotAfter.Add(time.Minute)},
		"not yet valid":       {n, state, leaf.NotBefore.Add(-time.Hour)},
		"no intermediate":     {n, &tls.ConnectionState{PeerCertificates: chain[:1]}, during},
		"no certificate":      {n, &tls.ConnectionState{}, during},
		"no TLS":              {n, nil, during},
		"other provisioner":   {n, &tls.ConnectionState{PeerCertificates: admin}, during},
	} {
		if _, ok := p.agentCertificate(c.node, c.state, c.at); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	p2, _ := agentIdentityFixture(t)
	p2.Config.AgentProvisioner = "another-kid"
	if _, ok := p2.agentCertificate(n, state, during); ok {
		t.Error("accepted a certificate from a provisioner it was not told to trust")
	}
}

func certificateRequest(p *Platform, token, from string, state *tls.ConnectionState) int {
	req := httptest.NewRequest("POST", "https://10.200.0.3:8443/sites/v1/agent/claim?node=carrel01",
		strings.NewReader(`{"session":"s","seq":1,"held":[]}`))
	req.RemoteAddr = from + ":40000"
	req.TLS = state
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	p.AgentHandler().ServeHTTP(w, req)
	return w.Code
}

// A node on certificate sign-in is refused with its token alone, and from
// another address even with its certificate. The real certificate has a
// fixed validity window, so the route test only checks refusals; the
// acceptance path is TestAgentCertificateChecks at a chosen time.
func TestCertificateModeRefusesTheToken(t *testing.T) {
	p, _ := agentIdentityFixture(t)
	chain := readChain(t, "carrel01.crt")
	for name, c := range map[string]struct {
		token, from string
		state       *tls.ConnectionState
	}{
		"token only":                {"cat_good", "10.200.0.1", &tls.ConnectionState{}},
		"token, no TLS":             {"cat_good", "10.200.0.1", nil},
		"certificate, wrong source": {"", "10.200.0.9", &tls.ConnectionState{PeerCertificates: chain}},
		"admin certificate":         {"cat_good", "10.200.0.1", &tls.ConnectionState{PeerCertificates: readChain(t, "admin.crt")}},
	} {
		if code := certificateRequest(p, c.token, c.from, c.state); code != 403 {
			t.Errorf("%s: %d", name, code)
		}
	}
	if len(p.Hub.nodes) != 0 {
		t.Fatalf("refused requests reached the hub: %v", p.Hub.nodes)
	}
}

func TestAgentCertificateConfig(t *testing.T) {
	base := func(mut func(*Config, *NodeConfig)) error {
		n := NodeConfig{Name: "carrel01", Target: "carrel01", Transport: "agent", AgentSource: "10.200.0.1", AgentCertificate: agentNameB09}
		c := Config{PublicAddress: "192.0.2.1", Origin: "https://carrel.test", Database: "x",
			AgentListen: "10.200.0.3:8443", AgentCertFile: "/c", AgentKeyFile: "/k",
			AgentClientCAFile: agentDir + "root.crt", AgentProvisioner: agentProvisioner}
		mut(&c, &n)
		c.Nodes = []NodeConfig{n}
		return c.WithDefaults().Validate()
	}
	if err := base(func(*Config, *NodeConfig) {}); err != nil {
		t.Fatalf("certificate mode without a token: %v", err)
	}
	for want, mut := range map[string]func(*Config, *NodeConfig){
		"agent_certificate must":      func(_ *Config, n *NodeConfig) { n.AgentCertificate = "Carrel01" },
		"needs agent_client_ca_file":  func(c *Config, _ *NodeConfig) { c.AgentClientCAFile = "" },
		"needs agent_client_ca_file ": func(c *Config, _ *NodeConfig) { c.AgentProvisioner = "" },
		"agent_client_ca_file:":       func(c *Config, _ *NodeConfig) { c.AgentClientCAFile = agentDir + "missing.crt" },
		"agent_token_sha256":          func(_ *Config, n *NodeConfig) { n.AgentTokenSHA256 = "short" },
	} {
		if err := base(mut); err == nil || !strings.Contains(err.Error(), strings.TrimSpace(want)) {
			t.Errorf("%s: %v", want, err)
		}
	}
}

// The hub reports when a node's certificate expires, and flags one that
// expires within agentCertificateWarn.
func TestHubReportsCertificateExpiry(t *testing.T) {
	p, _ := agentIdentityFixture(t)
	p.Hub.Heartbeat("carrel01", "s", 1, nil)
	p.Hub.Certificate("carrel01", time.Now().Add(time.Hour))
	st := p.Hub.Status("carrel01", time.Now())
	if st["certificate_expiring"] != true || st["certificate_expires"] == nil {
		t.Fatalf("status: %v", st)
	}
	p.Hub.Certificate("carrel01", time.Now().Add(7*24*time.Hour))
	if st := p.Hub.Status("carrel01", time.Now()); st["certificate_expiring"] != false {
		t.Fatalf("status: %v", st)
	}
}
