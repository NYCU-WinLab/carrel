package carrel

import (
	"log/slog"
	"strings"
	"time"
)

// app_logs asks an app's agent (carrel-deployd) for the end of its unit's
// journal, the way function_logs asks a function host (#640). The agent
// collects the request with its next long poll (AgentNext) and posts the
// answer to /apps/v1/agent/logs. Nothing is stored here.

const (
	appLogDefaultLines = 200
	appLogMaxLines     = 5000
	appLogMaxBytes     = 1 << 20
	appLogMaxText      = 16 << 10
	// The agent's answer: 5000 lines of 16 KiB, JSON-escaped, is far
	// above what is kept, so the body is cut at this size instead.
	maxAppLogReply = 8 << 20
)

func appLogKey(app D) string { return "app:" + str(app["id"]) }

func (e *Execution) appLogs(app D, a D) D {
	lines := intAt(a, "lines", appLogDefaultLines)
	if lines < 1 || lines > appLogMaxLines {
		fail("invalid", "lines must be between 1 and 5000")
	}
	req := D{"id": randomID(), "lines": lines}
	if s := intAt(a, "since_seconds", 0); s > 0 {
		req["since"] = time.Now().Unix() - int64(s)
	}
	answer, ok := e.P.appLogs.ask(e.Ctx, appLogKey(app), req)
	if !ok {
		fail("unavailable", "The app's agent did not answer. An agent installed before app_logs existed does not serve logs: run the app's install line on the machine again", D{"retryable": true})
	}
	if msg := str(answer["error"]); msg != "" {
		slog.Warn("app_log_read_failed", "app", app["id"], "detail", truncate(msg, 300))
		fail("unavailable", "The app's agent could not read the journal")
	}
	// Keep the newest lines within appLogMaxBytes.
	entries := arr(answer["lines"])
	out := []any{}
	size := 0
	truncated := boolean(answer["truncated"])
	for i := len(entries) - 1; i >= 0 && len(out) < lines; i-- {
		l := obj(entries[i])
		text := str(l["text"])
		if len(text) > appLogMaxText {
			text, truncated = strings.ToValidUTF8(text[:appLogMaxText], ""), true
		}
		if size += len(text); size > appLogMaxBytes {
			truncated = true
			break
		}
		out = append(out, D{"time": truncate(str(l["time"]), 40), "release": truncate(str(l["release"]), 64), "text": text})
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return D{"app": app["name"], "lines": out, "truncated": truncated}
}

// AppLogAnswer takes an agent's reply to one of its app's log requests.
func (p *Platform) AppLogAnswer(token string, reply D) D {
	app := p.agentApp(token)
	p.appLogs.answer(appLogKey(app), reply)
	return D{}
}
