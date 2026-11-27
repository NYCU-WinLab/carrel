package carrel

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// agentServesLogs plays carrel-deployd: it long-polls once for a log
// request and answers it with reply.
func agentServesLogs(t *testing.T, a *App, token string, reply func(req D) D) chan D {
	t.Helper()
	seen := make(chan D, 1)
	go func() {
		for i := 0; i < 20; i++ {
			_, out := do(t, a, "POST", "/apps/v1/agent/next", token, nil)
			for _, r := range arr(out["logs"]) {
				req := obj(r)
				seen <- req
				body, _ := json.Marshal(merge(reply(req), D{"id": req["id"]}))
				do(t, a, "POST", "/apps/v1/agent/logs", token, bytes.NewReader(body))
				return
			}
		}
	}()
	return seen
}

func TestAppLogsReadTheAgentsJournal(t *testing.T) {
	_, a, token := appFixture(t)
	alice := person("alice", false)
	seen := agentServesLogs(t, a, token, func(D) D {
		return D{"lines": []any{
			D{"time": "2026-11-27T10:00:00Z", "release": "r1", "text": "old"},
			D{"time": "2026-11-27T10:00:01Z", "release": "r2", "text": "listening on 8000"},
		}}
	})
	r := a.Call(context.Background(), "app_logs", D{"app": "site", "lines": 1, "since_seconds": 60}, alice)
	assertOK(t, r)
	if !equal(r["lines"], []any{D{"time": "2026-11-27T10:00:01Z", "release": "r2", "text": "listening on 8000"}}) || r["truncated"] != false {
		t.Fatalf("logs: %s", encoded(r))
	}
	req := <-seen
	if integer(req["lines"]) != 1 || num(req["since"]) < float64(time.Now().Unix()-70) {
		t.Fatalf("request: %s", encoded(req))
	}
}

func TestAppLogsStayInTheirTenant(t *testing.T) {
	p, a, token := appFixture(t)
	logWait := functionLogWait
	functionLogWait = 1500 * time.Millisecond
	t.Cleanup(func() { functionLogWait = logWait })
	// Another tenant cannot name the app.
	r := a.Call(context.Background(), "app_logs", D{"app": "site"}, person("bob", false))
	if boolean(r["ok"]) {
		t.Fatalf("bob read alice's logs: %s", encoded(r))
	}
	// Another app's agent cannot answer alice's request.
	seedMachine(p, "other", 10101)
	o := a.Call(context.Background(), "app_link", D{"machine": "other", "name": "other", "repo": "alice/other", "start": "x", "port": 8001}, person("alice", false))
	assertOK(t, o)
	wrong := str(o["agent_token"])
	go func() {
		for i := 0; i < 10; i++ {
			_, out := do(t, a, "POST", "/apps/v1/agent/next", token, nil)
			for _, req := range arr(out["logs"]) {
				body, _ := json.Marshal(D{"id": obj(req)["id"], "lines": []any{D{"text": "forged"}}})
				do(t, a, "POST", "/apps/v1/agent/logs", wrong, bytes.NewReader(body))
				return
			}
		}
	}()
	r = a.Call(context.Background(), "app_logs", D{"app": "site"}, person("alice", false))
	if boolean(r["ok"]) || strings.Contains(string(encoded(r)), "forged") {
		t.Fatalf("another app's agent answered: %s", encoded(r))
	}
}

func TestAppLogsKeepTheirCaps(t *testing.T) {
	_, a, token := appFixture(t)
	big := strings.Repeat("x", 20<<10)
	agentServesLogs(t, a, token, func(D) D {
		lines := []any{}
		for i := 0; i < 100; i++ {
			lines = append(lines, D{"time": "t", "release": strings.Repeat("r", 100), "text": big})
		}
		return D{"lines": lines}
	})
	r := a.Call(context.Background(), "app_logs", D{"app": "site", "lines": 5000}, person("alice", false))
	assertOK(t, r)
	size := 0
	for _, l := range arr(r["lines"]) {
		size += len(str(obj(l)["text"]))
		if len(str(obj(l)["text"])) > appLogMaxText || len(str(obj(l)["release"])) > 64 {
			t.Fatal("a line is past its caps")
		}
	}
	if size > appLogMaxBytes || r["truncated"] != true || len(arr(r["lines"])) == 0 {
		t.Fatalf("%d lines, %d bytes, truncated %v", len(arr(r["lines"])), size, r["truncated"])
	}
}
