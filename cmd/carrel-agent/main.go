// carrel-agent runs on a node whose transport is agent (PLAN 8.6). It
// connects out to the control plane's agent listener, claims jobs with a
// long poll, runs each through node-agent.py exactly as the SSH forced
// command does, and posts what it printed. It never logs a job's request
// or output: they carry cloud-init files and keys.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// config is /etc/carrel/agent.json.
type config struct {
	// Control is the agent listener, such as https://10.200.0.3:8443.
	Control string `json:"control"`
	// CAFile holds the CA the listener's certificate must chain to; no
	// other CA is trusted.
	CAFile    string `json:"ca_file"`
	TokenFile string `json:"token_file"`
	Node      string `json:"node"`
	NodeAgent string `json:"node_agent"`
	Lock      string `json:"lock"`
}

const (
	// maxClaim bounds a claim's answer: node-agent.py reads up to 8 MB
	// per request, and a claim may carry several.
	maxClaim = 64 << 20
	// maxOutput matches the control plane's cap on an adapter's reply.
	maxOutput = 32 << 20
	retry     = 5 * time.Second
)

type job struct {
	ID      string          `json:"id"`
	Request json.RawMessage `json:"request"`
}

type agent struct {
	cfg     config
	token   string
	client  *http.Client
	session string
	seq     uint64
	mu      sync.Mutex
	// held are the jobs taken and not yet acknowledged: running, or
	// answered with the POST not yet accepted.
	held map[string]bool
	// run runs one request line through node-agent.py; a variable so tests
	// can stand in for it.
	run func(ctx context.Context, request []byte) (out []byte, failed bool)
}

func load(path string) (*agent, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c config
	if err := json.Unmarshal(content, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.NodeAgent == "" {
		c.NodeAgent = "/usr/local/lib/carrel/node-agent.py"
	}
	if c.Lock == "" {
		c.Lock = "/run/carrel-agent.lock"
	}
	u, err := url.Parse(c.Control)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		// Jobs are root ops: never take them over plain HTTP.
		return nil, errors.New("control must be an https URL")
	}
	if c.Node == "" {
		return nil, errors.New("node is required")
	}
	pem, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("ca_file holds no certificate")
	}
	token, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("token_file: %w", err)
	}
	a := &agent{cfg: c, token: strings.TrimSpace(string(token)), held: map[string]bool{},
		client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}},
			// A redirect would carry the token elsewhere: never follow one.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	a.run = a.nodeAgent
	return a, nil
}

// nodeAgent runs one request the way the SSH forced command does: one JSON
// line on stdin, the answer on stdout.
func (a *agent) nodeAgent(ctx context.Context, request []byte) ([]byte, bool) {
	cmd := exec.Command(a.cfg.NodeAgent)
	cmd.Stdin = bytes.NewReader(append(bytes.TrimSpace(request), '\n'))
	var out bytes.Buffer
	cmd.Stdout = &limited{w: &out, n: maxOutput}
	err := cmd.Run()
	return out.Bytes(), err != nil
}

// limited keeps the first n bytes and drops the rest, so a runaway op cannot
// fill the agent's memory; the control plane rejects a cut answer.
type limited struct {
	w io.Writer
	n int
}

func (l *limited) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := min(len(p), l.n)
		_, _ = l.w.Write(p[:k])
		l.n -= k
	}
	return len(p), nil
}

// loop claims jobs until stop ends. A failed claim waits and tries again
// with the next number, so the control plane ignores any poll still open.
// After stop it takes no new job, but keeps answering and sends heartbeats
// with what it holds until the last running job is answered: a root op
// that finishes during a restart is reported, not swept as lost.
func (a *agent) loop(stop context.Context) {
	var wg sync.WaitGroup
	for stop.Err() == nil {
		jobs, err := a.claim(stop, false)
		if err != nil {
			if stop.Err() == nil {
				slog.Warn("claim_failed", "error", err)
				sleep(stop, retry)
			}
			continue
		}
		for _, j := range jobs {
			a.mu.Lock()
			if a.held[j.ID] {
				// Handed out again after a poll's answer failed, though it
				// reached us: it runs once.
				a.mu.Unlock()
				continue
			}
			a.held[j.ID] = true
			a.mu.Unlock()
			wg.Add(1)
			go func(j job) {
				defer wg.Done()
				a.do(j)
			}(j)
		}
	}
	for a.holding() > 0 {
		if _, err := a.claim(context.Background(), true); err != nil {
			slog.Warn("heartbeat_failed", "error", err)
		}
		a.wait(heartbeat)
	}
	wg.Wait()
}

// heartbeat is the pause between heartbeats while shutting down, well
// inside the control plane's 90 second silence limit.
var heartbeat = 10 * time.Second

func (a *agent) holding() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.held)
}

// wait sleeps up to d, or until the last held job is answered.
func (a *agent) wait(d time.Duration) {
	end := time.Now().Add(d)
	for time.Now().Before(end) && a.holding() > 0 {
		time.Sleep(50 * time.Millisecond)
	}
}

// claim polls for jobs; with drain it only reports what the agent holds.
func (a *agent) claim(ctx context.Context, drain bool) ([]job, error) {
	a.mu.Lock()
	a.seq++
	seq := a.seq
	held := make([]string, 0, len(a.held))
	for id := range a.held {
		held = append(held, id)
	}
	a.mu.Unlock()
	body, _ := json.Marshal(map[string]any{"session": a.session, "seq": seq, "held": held, "drain": drain})
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	target := strings.TrimRight(a.cfg.Control, "/") + "/sites/v1/agent/claim?node=" + url.QueryEscape(a.cfg.Node)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("claim answered %s", resp.Status)
	}
	var answer struct {
		Jobs []job `json:"jobs"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxClaim)).Decode(&answer); err != nil {
		return nil, err
	}
	return answer.Jobs, nil
}

// do runs a job and posts its output until the control plane takes the
// answer, also while the agent shuts down. The job stays held until then,
// so no claim reports it lost.
func (a *agent) do(j job) {
	started := time.Now()
	out, failed := a.run(context.Background(), j.Request)
	slog.Info("job_done", "job", j.ID, "failed", failed, "seconds", time.Since(started).Seconds())
	for {
		err := a.answer(context.Background(), j.ID, out, failed)
		if err == nil {
			break
		}
		slog.Warn("answer_failed", "job", j.ID, "error", err)
		time.Sleep(retry)
	}
	a.mu.Lock()
	delete(a.held, j.ID)
	a.mu.Unlock()
}

func (a *agent) answer(ctx context.Context, id string, out []byte, failed bool) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	target := strings.TrimRight(a.cfg.Control, "/") + "/sites/v1/agent/jobs/" + url.PathEscape(id) + "?node=" + url.QueryEscape(a.cfg.Node)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(out))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/octet-stream")
	exit := "0"
	if failed {
		exit = "1"
	}
	req.Header.Set("X-Carrel-Exit", exit)
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("answer got %s", resp.Status)
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func main() {
	path := flag.String("config", "/etc/carrel/agent.json", "Agent configuration")
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	a, err := load(*path)
	if err != nil {
		slog.Error("configuration", "error", err)
		os.Exit(1)
	}
	// One agent per node: a second one would let the control plane fail the
	// first one's jobs while they still run.
	lock, err := os.OpenFile(a.cfg.Lock, os.O_CREATE|os.O_RDWR, 0o600)
	if err == nil {
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	}
	if err != nil {
		slog.Error("another carrel-agent runs on this node", "lock", a.cfg.Lock, "error", err)
		os.Exit(1)
	}
	// A new session per process: the control plane fails what an earlier
	// process held, and ignores its later polls.
	a.session = rand.Text()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	slog.Info("agent_started", "node", a.cfg.Node, "control", a.cfg.Control)
	a.loop(ctx)
}
