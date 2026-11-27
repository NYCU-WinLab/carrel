package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// app_logs (#640): carrel hands a log request to this agent with its next
// long poll, and the agent posts the end of its unit's journal back. Each
// line names the release that wrote it, through the unit's invocation IDs:
// the agent remembers which release each invocation ran.

const (
	logMaxLines    = 5000
	logMaxLineText = 16 << 10
	logMaxOutput   = 8 << 20
	keptInvocation = 50
)

type logRequest struct {
	ID    string `json:"id"`
	Lines int    `json:"lines"`
	Since int64  `json:"since"`
}

type logLine struct {
	Time    string `json:"time"`
	Release string `json:"release"`
	Text    string `json:"text"`
}

type invocation struct {
	ID      string `json:"id"`
	Release string `json:"release"`
}

// invocations guards the file that maps the unit's invocations to
// releases. deploying is held while the current link and the running
// process may disagree, so nothing is recorded then.
type invocations struct {
	mu        sync.Mutex
	deploying sync.Mutex
}

func (a *agent) invocationFile() string { return filepath.Join(a.state, "invocations.json") }

func (a *agent) loadInvocations() []invocation {
	var out []invocation
	if b, err := os.ReadFile(a.invocationFile()); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

// remember records which release the unit's running invocation belongs to:
// the release current points at. Call it only when the running process
// started from current.
func (a *agent) remember(ctx context.Context) {
	out, err := exec.CommandContext(ctx, "systemctl", "show", "-p", "InvocationID", "--value", a.unit()).Output()
	id := strings.TrimSpace(string(out))
	target, lerr := os.Readlink(filepath.Join(a.root, "current"))
	if err != nil || lerr != nil || id == "" {
		return
	}
	a.inv.mu.Lock()
	defer a.inv.mu.Unlock()
	list := a.loadInvocations()
	for _, i := range list {
		if i.ID == id {
			return
		}
	}
	list = append(list, invocation{ID: id, Release: filepath.Base(target)})
	if len(list) > keptInvocation {
		list = list[len(list)-keptInvocation:]
	}
	b, _ := json.Marshal(list)
	if err := os.MkdirAll(a.state, 0o700); err == nil {
		tmp := a.invocationFile() + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil {
			_ = os.Rename(tmp, a.invocationFile())
		}
	}
}

// serveLogs reads the journal for one request and posts the answer.
func (a *agent) serveLogs(ctx context.Context, req logRequest) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// The running invocation is current's, unless a deploy is switching.
	if a.inv.deploying.TryLock() {
		a.remember(ctx)
		a.inv.deploying.Unlock()
	}
	answer := map[string]any{"id": req.ID}
	lines, truncated, err := a.readJournal(ctx, req)
	if err != nil {
		answer["error"] = err.Error()
	} else {
		answer["lines"], answer["truncated"] = lines, truncated
	}
	resp, err := a.request(ctx, "POST", "/apps/v1/agent/logs", answer)
	if err != nil {
		slog.Warn("log_answer_failed", "error", err)
		return
	}
	resp.Body.Close()
}

func (a *agent) readJournal(ctx context.Context, req logRequest) ([]logLine, bool, error) {
	n := min(max(req.Lines, 1), logMaxLines)
	args := []string{"-u", a.unit(), "--no-pager", "-o", "json", "--output-fields=MESSAGE,_SYSTEMD_INVOCATION_ID", "-n", strconv.Itoa(n)}
	if req.Since > 0 {
		args = append(args, "--since", "@"+strconv.FormatInt(req.Since, 10))
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, false, err
	}
	if err := cmd.Start(); err != nil {
		return nil, false, err
	}
	a.inv.mu.Lock()
	known := a.loadInvocations()
	a.inv.mu.Unlock()
	lines, truncated := parseJournal(io.LimitReader(out, logMaxOutput), known)
	_, _ = io.Copy(io.Discard, out)
	if err := cmd.Wait(); err != nil {
		return nil, false, err
	}
	return lines, truncated, nil
}

// parseJournal turns journalctl -o json output into lines, each with the
// release its invocation ran. A line from an invocation the agent never
// recorded has no release.
func parseJournal(r io.Reader, known []invocation) ([]logLine, bool) {
	release := map[string]string{}
	for _, i := range known {
		release[i.ID] = i.Release
	}
	lines := []logLine{}
	truncated := false
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 64<<10), 4<<20)
	for scan.Scan() {
		var e map[string]any
		if json.Unmarshal(scan.Bytes(), &e) != nil {
			continue
		}
		text := message(e["MESSAGE"])
		if len(text) > logMaxLineText {
			text, truncated = strings.ToValidUTF8(text[:logMaxLineText], ""), true
		}
		line := logLine{Text: text, Release: release[str(e["_SYSTEMD_INVOCATION_ID"])]}
		if us, err := strconv.ParseInt(str(e["__REALTIME_TIMESTAMP"]), 10, 64); err == nil {
			line.Time = time.UnixMicro(us).UTC().Format(time.RFC3339Nano)
		}
		lines = append(lines, line)
	}
	// A line longer than the buffer, or output past logMaxOutput, ends the
	// read early.
	if scan.Err() != nil {
		truncated = true
	}
	return lines, truncated
}

// message is a journal MESSAGE: a string, or an array of bytes when the
// program wrote something that is not UTF-8.
func message(v any) string {
	switch m := v.(type) {
	case string:
		return m
	case []any:
		b := make([]byte, 0, len(m))
		for _, x := range m {
			if f, ok := x.(float64); ok {
				b = append(b, byte(f))
			}
		}
		if !utf8.Valid(b) {
			return strings.ToValidUTF8(string(b), "�")
		}
		return string(b)
	}
	return ""
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
