package carrel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"time"
)

// agentPoll is how long one claim waits for a job.
const agentPoll = 30 * time.Second

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
			Session string   `json:"session"`
			Seq     uint64   `json:"seq"`
			Held    []string `json:"held"`
			// Drain: the agent is shutting down and takes no job.
			Drain bool `json:"drain"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, maxAgentClaim)).Decode(&in) != nil || in.Session == "" || in.Seq == 0 {
			jsonResponse(w, 400, D{"ok": false, "error": D{"code": "invalid", "message": "The body must be JSON with session and seq"}})
			return
		}
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
	return mux
}

// agentAllowed checks the bearer token and the source address against the
// node's configuration. A node on the SSH transport has no agent.
func (p *Platform) agentAllowed(r *http.Request, node string) bool {
	var token string
	_ = attempt(func() { token = bearer(r) }) // no token: refused below
	from, err := netip.ParseAddr(remoteIP(r))
	for _, n := range p.Config.Nodes {
		if n.Name != node || n.Transport != "agent" {
			continue
		}
		source, serr := netip.ParseAddr(n.AgentSource)
		return token != "" && err == nil && serr == nil && from.Unmap() == source.Unmap() && secureEqual(digest(token), n.AgentTokenSHA256)
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
