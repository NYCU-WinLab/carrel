package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NYCU-WinLab/carrel/internal/carrel"
)

type sshOnly struct{}

func (sshOnly) Call(context.Context, carrel.D, string) (any, error) {
	return carrel.D{"via": "ssh"}, nil
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A real platform and its agent listener over TLS, and the agent against
// it: a call to the node runs through the agent; a call to the other node
// stays on SSH.
func TestAgentRunsANodeCallEndToEnd(t *testing.T) {
	dir := t.TempDir()
	store, err := carrel.OpenStore(filepath.Join(dir, "carrel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	token := "agent-token"
	sum := sha256.Sum256([]byte(token))
	cfg := carrel.Config{Nodes: []carrel.NodeConfig{
		{Name: "pve1", Target: "carrel-node", Transport: "agent", AgentTokenSHA256: hex.EncodeToString(sum[:]), AgentSource: "127.0.0.1"},
		{Name: "pve2", Target: "carrel02"},
	}}
	p := carrel.NewPlatform(store, sshOnly{}, cfg)
	server := httptest.NewTLSServer(p.AgentHandler())
	defer server.Close()
	ca := writeFile(t, dir, "ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})))
	conf, _ := json.Marshal(config{Control: server.URL, CAFile: ca, TokenFile: writeFile(t, dir, "token", token+"\n"), Node: "pve1"})
	a, err := load(writeFile(t, dir, "agent.json", string(conf)))
	if err != nil {
		t.Fatal(err)
	}
	a.session = "s1"
	var got string
	a.run = func(_ context.Context, request []byte) ([]byte, bool) {
		got = string(request)
		return []byte(`{"ok":true,"result":{"via":"agent"}}`), false
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.loop(ctx); close(done) }()
	defer func() { stop(); <-done }()

	call, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	v, err := p.Backend.Call(call, carrel.D{"op": "status", "machine": carrel.D{"vmid": 101}}, "carrel-node")
	if err != nil || v.(map[string]any)["via"] != "agent" {
		t.Fatalf("agent node: %v %v", v, err)
	}
	if !strings.Contains(got, `"op":"status"`) {
		t.Fatalf("node-agent got %q", got)
	}
	if v, err := p.Backend.Call(call, carrel.D{"op": "status"}, "carrel02"); err != nil || v.(map[string]any)["via"] != "ssh" {
		t.Fatalf("ssh node: %v %v", v, err)
	}
	// A node failure comes back as the same Failure SSH gives.
	a.run = func(context.Context, []byte) ([]byte, bool) {
		return []byte(`{"ok":false,"error_code":"command_failed","error":"Node action failed"}`), true
	}
	_, err = p.Backend.Call(call, carrel.D{"op": "status"}, "carrel-node")
	f, ok := err.(carrel.Failure)
	if !ok || f.Result["error"].(map[string]any)["backend_code"] != "command_failed" {
		t.Fatalf("failure: %v", err)
	}
}

func TestAgentRefusesPlainHTTPAndOtherCAs(t *testing.T) {
	dir := t.TempDir()
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	// httptest servers share one certificate, so the other CA is made here.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := writeFile(t, dir, "ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	token := writeFile(t, dir, "token", "x")
	plain, _ := json.Marshal(config{Control: "http://10.200.0.3:8443", CAFile: ca, TokenFile: token, Node: "pve1"})
	if _, err := load(writeFile(t, dir, "plain.json", string(plain))); err == nil {
		t.Fatal("plain HTTP accepted")
	}
	conf, _ := json.Marshal(config{Control: server.URL, CAFile: ca, TokenFile: token, Node: "pve1"})
	a, err := load(writeFile(t, dir, "agent.json", string(conf)))
	if err != nil {
		t.Fatal(err)
	}
	a.session = "s1"
	if _, err := a.claim(context.Background()); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a certificate under another CA was trusted: %v", err)
	}
}
