package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/NYCU-WinLab/carrel/internal/carrel"
)

// The previous release's agent against this control plane (#561), so the
// control plane can be upgraded before the agents. CI sets
// CARREL_PREVIOUS_AGENT to the carrel-agent of the latest release.
func TestThePreviousReleaseAgentRunsANodeCall(t *testing.T) {
	bin := os.Getenv("CARREL_PREVIOUS_AGENT")
	if bin == "" {
		t.Skip("CARREL_PREVIOUS_AGENT is not set")
	}
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
	}}
	p := carrel.NewPlatform(store, sshOnly{}, cfg)
	p.UseAgents()
	server := httptest.NewTLSServer(p.AgentHandler())
	defer server.Close()

	// A stand-in for node-agent.py: it keeps the request and answers.
	nodeAgent := filepath.Join(dir, "node-agent.py")
	script := "#!/bin/sh\ncat > \"$0.request\"\necho '{\"ok\":true,\"result\":{\"via\":\"previous\"}}'\n"
	if err := os.WriteFile(nodeAgent, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	// Only the keys every released agent reads.
	conf, _ := json.Marshal(map[string]string{
		"control":    server.URL,
		"ca_file":    writeFile(t, dir, "ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))),
		"token_file": writeFile(t, dir, "token", token+"\n"),
		"node":       "pve1",
		"node_agent": nodeAgent,
		"lock":       filepath.Join(dir, "agent.lock"),
	})
	var logs strings.Builder
	cmd := exec.Command(bin, "-config", writeFile(t, dir, "agent.json", string(conf)))
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("previous agent:\n%s", logs.String())
		}
	}()

	call, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	v, err := p.Backend.Call(call, carrel.D{"op": "status", "machine": carrel.D{"vmid": 101}}, "carrel-node")
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if v.(map[string]any)["via"] != "previous" {
		t.Fatalf("answer: %v", v)
	}
	got, err := os.ReadFile(nodeAgent + ".request")
	if err != nil || !strings.Contains(string(got), `"op":"status"`) {
		t.Fatalf("node-agent got %q (%v)", got, err)
	}
}
