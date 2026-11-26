package carrel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// agentPoll is how long one claim waits for a job.
const agentPoll = 30 * time.Second

// AgentProtocol is the protocol this control plane speaks with node agents.
// agentProtocols are the ones it serves: the current and the previous one,
// so a node's agent and the control plane can be upgraded one at a time
// (#561). An agent speaking anything else is refused with the release to
// install.
const AgentProtocol = "v1"

var agentProtocols = []string{AgentProtocol}

// maxAgentClaim bounds a claim's body: a session, a number and the ids the
// agent holds.
const maxAgentClaim = 1 << 20

// AgentHandler serves node agents (PLAN 8.6), on their own TLS listener
// (agent_listen), never through the gateway: a job is a root op on a node.
// Authentication reads the configuration only, before the hub is touched.
func (p *Platform) AgentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /sites/v1/agent/claim", func(w http.ResponseWriter, r *http.Request) {
		// The node is in the query, so the token is checked before the
		// body is read.
		node := r.URL.Query().Get("node")
		if !p.agentAllowed(r, node) {
			jsonResponse(w, 403, D{"ok": false, "error": D{"code": "forbidden", "message": "Invalid agent token"}})
			return
		}
		var in struct {
			Protocol string   `json:"protocol"`
			Release  string   `json:"release"`
			Session  string   `json:"session"`
			Seq      uint64   `json:"seq"`
			Held     []string `json:"held"`
			// Drain: the agent is shutting down and takes no job.
			Drain bool `json:"drain"`
			// Capabilities: what this agent can do beyond jobs, such as
			// "stream" for consoles.
			Capabilities []string `json:"capabilities"`
			// Plugins: the plugins the agent found on the node (#660).
			Plugins []PluginInfo `json:"plugins"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, maxAgentClaim)).Decode(&in) != nil || in.Session == "" || in.Seq == 0 {
			jsonResponse(w, 400, D{"ok": false, "error": D{"code": "invalid", "message": "The body must be JSON with session and seq"}})
			return
		}
		if !slices.Contains(agentProtocols, in.Protocol) {
			jsonResponse(w, 426, D{"ok": false, "error": D{"code": "protocol_unsupported",
				"message": fmt.Sprintf("This control plane serves agent protocols %s, not %q. Install carrel-agent from release %s.", strings.Join(agentProtocols, ", "), in.Protocol, Version)}})
			return
		}
		if msg := CheckPlugins(in.Plugins); msg != "" {
			// A bad plugin report costs the node its plugins, never its jobs.
			slog.Warn("agent plugin report refused", "node", node, "reason", msg)
			in.Plugins = nil
		}
		capabilities := in.Capabilities
		if in.Drain {
			// An agent shutting down claims nothing, so it takes no console:
			// consoles go back to SSH until its successor polls.
			capabilities = nil
		}
		p.Hub.Hello(node, in.Session, in.Protocol, in.Release, in.Plugins, capabilities...)
		if in.Drain {
			p.Hub.Heartbeat(node, in.Session, in.Seq, in.Held)
			jsonResponse(w, 200, D{"jobs": []AgentJob{}})
			return
		}
		jobs := p.Hub.Claim(r.Context(), node, in.Session, in.Seq, in.Held, agentPoll)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := json.NewEncoder(w).Encode(D{"jobs": jobs}); err != nil && len(jobs) > 0 {
			// The answer did not reach the agent: its jobs never ran.
			p.Hub.Release(node, in.Session, jobs)
		}
	})
	mux.HandleFunc("POST /sites/v1/agent/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		node := r.URL.Query().Get("node")
		if !p.agentAllowed(r, node) {
			jsonResponse(w, 403, D{"ok": false, "error": D{"code": "forbidden", "message": "Invalid agent token"}})
			return
		}
		out, err := io.ReadAll(io.LimitReader(r.Body, maxAdapterReply+1))
		if err != nil {
			jsonResponse(w, 400, D{"ok": false, "error": D{"code": "invalid", "message": "The output could not be read"}})
			return
		}
		// Taken or not, the answer is settled: a job the hub no longer
		// waits for (timed out, swept) has nobody to answer.
		taken := p.Hub.Complete(node, r.PathValue("id"), out, r.Header.Get("X-Carrel-Exit") != "0")
		jsonResponse(w, 200, D{"ok": true, "taken": taken})
	})
	// A console stream: the agent connects back with the id a claim gave it,
	// and the connection then carries node-agent.py's stdin and stdout.
	mux.HandleFunc("GET /sites/v1/agent/streams/{id}", func(w http.ResponseWriter, r *http.Request) {
		node := r.URL.Query().Get("node")
		if !p.agentAllowed(r, node) {
			jsonResponse(w, 403, D{"ok": false, "error": D{"code": "forbidden", "message": "Invalid agent token"}})
			return
		}
		if !strings.EqualFold(r.Header.Get("Upgrade"), agentStreamUpgrade) {
			jsonResponse(w, 400, D{"ok": false, "error": D{"code": "invalid", "message": "Upgrade must be " + agentStreamUpgrade}})
			return
		}
		to, ok := p.Hub.Attach(node, r.PathValue("id"))
		if !ok {
			jsonResponse(w, 404, D{"ok": false, "error": D{"code": "not_found", "message": "No console waits for this stream"}})
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			// HTTP/2 cannot be taken over; the agent speaks HTTP/1.1.
			to <- nil
			jsonResponse(w, 500, D{"ok": false, "error": D{"code": "internal", "message": "This connection cannot carry a stream"}})
			return
		}
		c, buffered, err := hijacker.Hijack()
		if err != nil {
			to <- nil
			return
		}
		// A node that drops off the network ends the stream in about 30
		// seconds, not the 2.5 minutes of the system's keepalive.
		_ = SetStreamKeepAlive(c)
		// The answer has 10 seconds, so the console waiting on it always hears
		// back; then the listener's request deadlines go, as a console runs up
		// to an hour.
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		_, err = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + agentStreamUpgrade + "\r\n\r\n")
		if err == nil {
			err = buffered.Flush()
		}
		if err == nil {
			err = c.SetDeadline(time.Time{})
		}
		if err != nil {
			c.Close()
			to <- nil
			return
		}
		to <- &bufferedConn{Conn: c, r: buffered.Reader}
	})
	return mux
}

// agentStreamUpgrade names the protocol of a console stream's connection:
// raw bytes both ways.
const agentStreamUpgrade = "carrel-stream"

// StreamKeepAlive bounds how long a console stream holds on to a peer that
// vanished: idle 15s, then 3 probes 5s apart, so about 30 seconds. The stream
// carries raw bytes with no framing, so there is no in-band ping.
var StreamKeepAlive = net.KeepAliveConfig{Enable: true, Idle: 15 * time.Second, Interval: 5 * time.Second, Count: 3}

// SetStreamKeepAlive applies StreamKeepAlive to the TCP connection under c,
// looking through TLS.
func SetStreamKeepAlive(c net.Conn) error {
	if t, ok := c.(*tls.Conn); ok {
		c = t.NetConn()
	}
	t, ok := c.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("keepalive: %T is not a TCP connection", c)
	}
	return t.SetKeepAliveConfig(StreamKeepAlive)
}

// bufferedConn reads what the server buffered before the takeover first.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// agentAllowed checks a request against the node's entry: the source
// address always, then the client certificate for a node on certificate
// sign-in (its token is refused), or the bearer token for the others.
func (p *Platform) agentAllowed(r *http.Request, node string) bool {
	from, err := netip.ParseAddr(remoteIP(r))
	for _, n := range p.Config.Nodes {
		if n.Name != node || n.Transport != "agent" {
			continue
		}
		source, serr := netip.ParseAddr(n.AgentSource)
		if err != nil || serr != nil || from.Unmap() != source.Unmap() {
			return false
		}
		if n.AgentCertificate != "" {
			expires, ok := p.agentCertificate(n, r.TLS, time.Now())
			if ok {
				p.Hub.Certificate(node, expires)
			}
			return ok
		}
		var token string
		_ = attempt(func() { token = bearer(r) }) // no token: refused below
		return token != "" && secureEqual(digest(token), n.AgentTokenSHA256)
	}
	return false
}

// onAgent reports whether a node uses the agent transport.
func (p *Platform) onAgent(name string) bool {
	for _, n := range p.Config.Nodes {
		if n.Name == name {
			return n.Transport == "agent"
		}
	}
	return false
}

// UseAgents sends calls for nodes on the agent transport through the hub.
// Only the serving process calls it, before Start: a one-shot run such as
// -backup has no agent listener, so its calls stay on SSH (#606).
func (p *Platform) UseAgents() {
	p.Backend = agentBackend(p.Backend, p.Hub, p.Config.Nodes)
}

// agentBackend wraps b so nodes on the agent transport go through the hub.
func agentBackend(b Backend, hub *AgentHub, nodes []NodeConfig) Backend {
	agents := map[string]string{}
	for _, n := range nodes {
		if n.Transport == "agent" {
			agents[n.Target] = n.Name
		}
	}
	if len(agents) == 0 {
		return b
	}
	return &RoutedBackend{SSH: b, Hub: hub, Agents: agents}
}

// sweepAgents fails the jobs of agents that went silent, until ctx ends.
func (p *Platform) sweepAgents(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			p.Hub.Sweep(now)
		}
	}
}
