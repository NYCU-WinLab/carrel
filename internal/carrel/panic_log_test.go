package carrel

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return buf
}

func TestUnknownPanicInToolReturnsInternalAndLogsStack(t *testing.T) {
	p, b := fixture(t)
	seedMachine(p, "web", 10100)
	b.call = func(r D, _ string) (any, error) {
		var m map[string]int
		m["bug"] = 1
		return nil, nil
	}
	logs := captureLog(t)
	r := p.Execute(context.Background(), "machine_get", D{"machine": "web"}, person("alice", false))
	assertCode(t, r, "internal")
	if out := logs.String(); !strings.Contains(out, "unexpected_panic") || !strings.Contains(out, "assignment to entry in nil map") || !strings.Contains(out, "runtime/debug.Stack") {
		t.Fatalf("panic and stack not logged: %s", out)
	}
}

func TestUnknownPanicInOperationReturnsInternalAndLogsStack(t *testing.T) {
	p, b := fixture(t)
	b.call = func(r D, _ string) (any, error) {
		if r["op"] == "create" {
			var m map[string]int
			m["bug"] = 1
		}
		switch r["op"] {
		case "inventory":
			return baseInventory(), nil
		case "storage_usage":
			return []D{}, nil
		}
		return D{"status": "running"}, nil
	}
	logs := captureLog(t)
	runQueue(p)
	r := p.Execute(context.Background(), "machine_create", D{"name": "bang", "ssh_keys": []any{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAliceAliceAliceAliceAliceAliceAliceAlic laptop"}, "wait_seconds": 0}, person("alice", false))
	assertOK(t, r)
	op := awaitState(t, p, str(obj(r["operation"])["id"]), "failed")
	if code := obj(op["error"])["code"]; code != "internal" {
		t.Fatalf("expected internal: %s", encoded(op))
	}
	if out := logs.String(); !strings.Contains(out, "unexpected_panic") || !strings.Contains(out, "runtime/debug.Stack") || !strings.Contains(out, "assignment to entry in nil map") {
		t.Fatalf("panic and stack not logged: %s", out)
	}
}

func TestKnownPanicsAreNotLoggedAsBugs(t *testing.T) {
	logs := captureLog(t)
	_ = attemptLogged("test", func() { fail("invalid", "nope") })
	_ = attemptLogged("test", func() { panic(Waiting{"w", 1}) })
	if logs.String() != "" {
		t.Fatalf("logged a refusal: %s", logs.String())
	}
}
