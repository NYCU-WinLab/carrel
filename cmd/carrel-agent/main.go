// carrel-agent runs on a node whose transport is agent (PLAN 8.6). It
// connects out to the control plane's agent listener, claims jobs with a
// long poll, runs each through node-agent.py exactly as the SSH forced
// command does, and posts what it printed. It never logs a job's request
// or output: they carry cloud-init files and keys.
package main

import (
	"bufio"
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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/NYCU-WinLab/carrel/internal/carrel"
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
	// Certificate sign-in (#601): the agent's key and certificate chain,
	// the name the certificate carries, the lab step-ca and its root.
	CertFile        string `json:"cert_file"`
	KeyFile         string `json:"key_file"`
	CertificateName string `json:"certificate_name"`
	CAURL           string `json:"ca_url"`
	LabRootFile     string `json:"lab_root_file"`
	// PluginDir holds the plugins' unix sockets (#660).
	PluginDir string `json:"plugin_dir"`
}

const (
	// maxClaim bounds a claim's answer: node-agent.py reads up to 8 MB
	// per request, and a claim may carry several.
	maxClaim = 64 << 20
	// maxOutput matches the control plane's cap on an adapter's reply.
	maxOutput = 32 << 20
	retry     = 5 * time.Second
	// protocol is what this agent speaks; the control plane serves the
	// current and the previous one (#561).
	protocol = "v1"
)

type job struct {
	ID      string          `json:"id"`
	Request json.RawMessage `json:"request"`
	// Stream: a console, run on a connection of its own (stream), not a job.
	Stream bool `json:"stream"`
}

type agent struct {
	cfg     config
	token   string
	client  *http.Client
	tls     *tls.Config
	session string
	seq     uint64
	// release is the version in release.json beside node-agent.py: the
	// release these node programs came from, empty when unknown.
	release string
	mu      sync.Mutex
	// held are the jobs taken and not yet acknowledged: running, or
	// answered with the POST not yet accepted.
	held map[string]bool
	// run runs one request line through node-agent.py; a variable so tests
	// can stand in for it.
	run func(ctx context.Context, request []byte) (out []byte, failed bool)
	// console starts node-agent.py for a stream; a variable for tests.
	console func(ctx context.Context) *exec.Cmd
	// stall is how long a console may leave its stdin full before it is
	// stopped; 0 is 30 seconds.
	stall time.Duration
	// cert is the client certificate the agent presents, nil before it is
	// enrolled.
	cert atomic.Pointer[tls.Certificate]
	// plugins is the latest plugin report, made at pluginsAt.
	plugins   []carrel.PluginInfo
	pluginsAt time.Time
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
	if c.PluginDir == "" {
		c.PluginDir = defaultPluginDir
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
	// The token stays until certificate sign-in replaces it; a node that
	// signs in with a certificate needs none.
	token, err := os.ReadFile(c.TokenFile)
	if err != nil && (c.CertFile == "" || !errors.Is(err, os.ErrNotExist)) {
		return nil, fmt.Errorf("token_file: %w", err)
	}
	if c.CertFile != "" && (c.KeyFile == "" || c.CertificateName == "" || c.CAURL == "" || c.LabRootFile == "") {
		return nil, errors.New("cert_file needs key_file, certificate_name, ca_url and lab_root_file")
	}
	trust := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	a := &agent{cfg: c, token: strings.TrimSpace(string(token)), held: map[string]bool{}, tls: trust}
	if c.CertFile != "" {
		trust.GetClientCertificate = a.clientCertificate
		if err := a.loadCertificate(); err != nil {
			slog.Error("certificate_unreadable", "error", err)
		}
	}
	a.client = &http.Client{Transport: &http.Transport{TLSClientConfig: trust.Clone()},
		// A redirect would carry the token elsewhere: never follow one.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	a.run = a.dispatch
	a.console = func(ctx context.Context) *exec.Cmd { return exec.CommandContext(ctx, a.cfg.NodeAgent) }
	var record struct {
		Version string `json:"version"`
	}
	if content, err := os.ReadFile(filepath.Join(filepath.Dir(c.NodeAgent), "release.json")); err == nil && json.Unmarshal(content, &record) == nil {
		a.release = record.Version
	}
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
	connected := false
	a.refreshPlugins(stop)
	for stop.Err() == nil {
		jobs, err := a.claim(stop, false)
		if err != nil {
			connected = false
			if stop.Err() == nil {
				slog.Warn("claim_failed", "error", err)
				sleep(stop, retry)
			}
			continue
		}
		if !connected {
			// The control plane took a claim: the installer waits for this.
			slog.Info("agent_connected", "node", a.cfg.Node)
			connected = true
		}
		for _, j := range jobs {
			if j.Stream {
				// A console is cut when the agent stops, as an SSH session
				// would be, so it is not held.
				go a.stream(stop, j)
				continue
			}
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
	plugins := a.pluginReport()
	a.mu.Lock()
	a.seq++
	seq := a.seq
	held := make([]string, 0, len(a.held))
	for id := range a.held {
		held = append(held, id)
	}
	a.mu.Unlock()
	claim := map[string]any{"protocol": protocol, "release": a.release, "session": a.session, "seq": seq, "held": held, "drain": drain, "capabilities": []string{"stream"}, "plugins": plugins}
	body, err := json.Marshal(claim)
	if err != nil {
		// No plugin report may cost the node its jobs.
		delete(claim, "plugins")
		body, _ = json.Marshal(claim)
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	target := strings.TrimRight(a.cfg.Control, "/") + "/sites/v1/agent/claim?node=" + url.QueryEscape(a.cfg.Node)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	a.authorize(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// The control plane's message says what to do, such as which release
		// to install when it no longer serves this protocol.
		var refusal struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&refusal)
		return nil, fmt.Errorf("claim answered %s: %s", resp.Status, refusal.Error.Message)
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
	a.authorize(req)
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

// stream runs a console: it connects back to the control plane with the
// stream's id, and node-agent.py's stdin and stdout run over that
// connection, as they do over SSH. Nothing of the stream is logged.
func (a *agent) stream(ctx context.Context, j job) {
	if err := a.streamOnce(ctx, j); err != nil {
		slog.Warn("stream_failed", "stream", j.ID, "error", err)
	}
}

// streamKeepAlive bounds a silent network loss on a console stream to about
// 30 seconds; the control plane sets the same on its end.
var streamKeepAlive = net.KeepAliveConfig{Enable: true, Idle: 15 * time.Second, Interval: 5 * time.Second, Count: 3}

func (a *agent) streamOnce(ctx context.Context, j job) error {
	u, err := url.Parse(strings.TrimRight(a.cfg.Control, "/") + "/sites/v1/agent/streams/" + url.PathEscape(j.ID) + "?node=" + url.QueryEscape(a.cfg.Node))
	if err != nil {
		return err
	}
	address := u.Host
	if u.Port() == "" {
		address = net.JoinHostPort(u.Hostname(), "443")
	}
	dial, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c, err := (&tls.Dialer{NetDialer: &net.Dialer{KeepAliveConfig: streamKeepAlive}, Config: a.tls.Clone()}).DialContext(dial, "tcp", address)
	if err != nil {
		return err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	a.authorize(req)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "carrel-stream")
	if err := req.Write(c); err != nil {
		return err
	}
	reader := bufio.NewReader(c)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		resp.Body.Close()
		return fmt.Errorf("stream answered %s", resp.Status)
	}
	_ = c.SetDeadline(time.Time{})
	run, end := context.WithCancel(ctx)
	defer end()
	cmd := a.console(run)
	// A child that keeps stdout open does not hold the stream once the
	// process is gone.
	cmd.WaitDelay = 5 * time.Second
	// A pipe of our own: its writes can have a deadline.
	in, stdin, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd.Stdin = in
	cmd.Stdout = c
	err = cmd.Start()
	in.Close()
	if err != nil {
		stdin.Close()
		return err
	}
	// The request first, then what the control plane sends. When the
	// connection ends, the process is stopped: qm and socat may outlive their
	// stdin. A console that leaves its stdin full for longer than stall is
	// stopped too, so it cannot hold the serial port for a closed stream.
	stall := a.stall
	if stall == 0 {
		stall = 30 * time.Second
	}
	input := make(chan []byte)
	go func() {
		defer close(input)
		defer end()
		for {
			buf := make([]byte, 32<<10)
			n, err := reader.Read(buf)
			if n > 0 {
				select {
				case input <- buf[:n]:
				case <-run.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer stdin.Close()
		defer end()
		write := func(b []byte) error {
			_ = stdin.SetWriteDeadline(time.Now().Add(stall))
			_, err := stdin.Write(b)
			return err
		}
		if write(append(bytes.TrimSpace(j.Request), '\n')) != nil {
			return
		}
		for b := range input {
			if write(b) != nil {
				return
			}
		}
	}()
	_ = cmd.Wait()
	return nil
}

// authorize adds the token, while the agent has one.
func (a *agent) authorize(req *http.Request) {
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func main() {
	path := flag.String("config", "/etc/carrel/agent.json", "Agent configuration")
	enrol := flag.Bool("enroll", false, "Read a one-time step-ca token on stdin, make a key and get the agent's certificate")
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	a, err := load(*path)
	if err != nil {
		slog.Error("configuration", "error", err)
		os.Exit(1)
	}
	if *enrol {
		token, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
		if err == nil {
			err = a.enroll(context.Background(), strings.TrimSpace(string(token)))
		}
		if err != nil {
			slog.Error("enroll_failed", "error", err)
			os.Exit(1)
		}
		slog.Info("enrolled", "name", a.cfg.CertificateName, "expires", a.cert.Load().Leaf.NotAfter.UTC().Format(time.RFC3339))
		return
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
	slog.Info("agent_started", "node", a.cfg.Node, "control", a.cfg.Control, "certificate", a.cert.Load() != nil)
	if a.cfg.CertFile != "" {
		go a.renewLoop(ctx)
	}
	a.loop(ctx)
}
