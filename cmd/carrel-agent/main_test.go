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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
	p.UseAgents()
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
	if _, err := a.claim(context.Background(), false); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a certificate under another CA was trusted: %v", err)
	}
}

// The same job handed out twice (its first poll's answer failed after it
// arrived) runs once.
func TestAgentRunsAJobHandedOutTwiceOnce(t *testing.T) {
	dir := t.TempDir()
	var mu sync.Mutex
	claims, answers := 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/claim") {
			claims++
			if claims <= 2 {
				_, _ = w.Write([]byte(`{"jobs":[{"id":"j1","request":{"op":"freeze"}}]}`))
				return
			}
			time.Sleep(20 * time.Millisecond)
			_, _ = w.Write([]byte(`{"jobs":[]}`))
			return
		}
		answers++
		_, _ = w.Write([]byte(`{"ok":true,"taken":true}`))
	}))
	defer server.Close()
	ca := writeFile(t, dir, "ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})))
	conf, _ := json.Marshal(config{Control: server.URL, CAFile: ca, TokenFile: writeFile(t, dir, "token", "x"), Node: "pve1"})
	a, err := load(writeFile(t, dir, "agent.json", string(conf)))
	if err != nil {
		t.Fatal(err)
	}
	a.session = "s1"
	release := make(chan struct{})
	var runs atomic.Int32
	a.run = func(context.Context, []byte) ([]byte, bool) {
		runs.Add(1)
		<-release // still running when the second copy arrives
		return []byte(`{"ok":true,"result":{}}`), false
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.loop(ctx); close(done) }()
	for {
		mu.Lock()
		c := claims
		mu.Unlock()
		if c >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
	time.Sleep(50 * time.Millisecond)
	stop()
	<-done
	if runs.Load() != 1 || answers != 1 {
		t.Fatalf("runs %d answers %d", runs.Load(), answers)
	}
}

// A stop signal while a job runs neither drops nor loses its answer: the
// agent sends drain heartbeats until the job ends, then answers it.
func TestAgentAnswersAJobThatEndsAfterStop(t *testing.T) {
	dir := t.TempDir()
	store, err := carrel.OpenStore(filepath.Join(dir, "carrel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	sum := sha256.Sum256([]byte("agent-token"))
	cfg := carrel.Config{Nodes: []carrel.NodeConfig{
		{Name: "pve1", Target: "carrel-node", Transport: "agent", AgentTokenSHA256: hex.EncodeToString(sum[:]), AgentSource: "127.0.0.1"},
	}}
	p := carrel.NewPlatform(store, sshOnly{}, cfg)
	p.UseAgents()
	server := httptest.NewTLSServer(p.AgentHandler())
	defer server.Close()
	ca := writeFile(t, dir, "ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})))
	conf, _ := json.Marshal(config{Control: server.URL, CAFile: ca, TokenFile: writeFile(t, dir, "token", "agent-token"), Node: "pve1"})
	a, err := load(writeFile(t, dir, "agent.json", string(conf)))
	if err != nil {
		t.Fatal(err)
	}
	a.session = "s1"
	heartbeat = 20 * time.Millisecond
	started, release := make(chan struct{}), make(chan struct{})
	a.run = func(context.Context, []byte) ([]byte, bool) {
		close(started)
		<-release
		return []byte(`{"ok":true,"result":{"via":"agent"}}`), false
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.loop(ctx); close(done) }()
	type reply struct {
		v   any
		err error
	}
	got := make(chan reply, 1)
	go func() {
		call, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		v, err := p.Backend.Call(call, carrel.D{"op": "freeze"}, "carrel-node")
		got <- reply{v, err}
	}()
	<-started
	stop()
	// Several drain heartbeats pass while the job still runs.
	time.Sleep(100 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("the agent exited with a job running")
	default:
	}
	close(release)
	r := <-got
	if r.err != nil || r.v.(map[string]any)["via"] != "agent" {
		t.Fatalf("answer after stop: %v %v", r.v, r.err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the agent did not exit after its last answer")
	}
}

// The agent reports its protocol and the release beside node-agent.py, and
// a refusal's message reaches its log (#561).
func TestAgentReportsItsProtocolAndRelease(t *testing.T) {
	dir := t.TempDir()
	var got map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(426)
		_, _ = w.Write([]byte(`{"ok":false,"error":{"code":"protocol_unsupported","message":"Install carrel-agent from release 9.9.9."}}`))
	}))
	defer server.Close()
	ca := writeFile(t, dir, "ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})))
	writeFile(t, dir, "release.json", `{"version":"0.12.0","sha256":{}}`)
	conf, _ := json.Marshal(config{Control: server.URL, CAFile: ca, TokenFile: writeFile(t, dir, "token", "x"), Node: "pve1", NodeAgent: filepath.Join(dir, "node-agent.py")})
	a, err := load(writeFile(t, dir, "agent.json", string(conf)))
	if err != nil {
		t.Fatal(err)
	}
	a.session = "s1"
	_, err = a.claim(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "release 9.9.9") {
		t.Fatalf("refusal: %v", err)
	}
	if got["protocol"] != protocol || got["release"] != "0.12.0" {
		t.Fatalf("hello %v", got)
	}
}
