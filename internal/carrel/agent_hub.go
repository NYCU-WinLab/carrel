package carrel

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"time"
)

// AgentHub carries node requests to agents that connect out (PLAN 8.6), in
// place of SSH. A call becomes a job queued for its node; the node's agent
// claims jobs with a long poll and posts each one's output. The hub has its
// own lock and never takes the writer or the store: Execution.Call runs
// while an operation holds the writer, so anything the agent's requests
// wait on must not need it.
type AgentHub struct {
	mu    sync.Mutex
	nodes map[string]*agentNode
}

type agentNode struct {
	jobs map[string]*agentJob
	// wake is closed and replaced when a job is queued, so a waiting claim
	// answers at once instead of on its next tick.
	wake chan struct{}
}

type agentJob struct {
	id      string
	request D
	taken   bool
	done    chan agentOutput
}

type agentOutput struct {
	out    []byte
	failed error
}

// AgentJob is what an agent receives: the id to answer with and the request
// line for node-agent.py.
type AgentJob struct {
	ID      string `json:"id"`
	Request D      `json:"request"`
}

var errAgentLostJob = errors.New("the agent no longer holds the job")

func NewAgentHub() *AgentHub { return &AgentHub{nodes: map[string]*agentNode{}} }

func (h *AgentHub) node(name string) *agentNode {
	n := h.nodes[name]
	if n == nil {
		n = &agentNode{jobs: map[string]*agentJob{}, wake: make(chan struct{})}
		h.nodes[name] = n
	}
	return n
}

// Call queues a request for a node's agent and waits for its output, within
// the same timeout an SSH call has. The answer goes through adapterReply, so
// a caller sees the same results and failures on both transports.
func (h *AgentHub) Call(ctx context.Context, request D, node, target string) (any, error) {
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, callTimeout(request, target))
	defer cancel()
	started := time.Now()
	h.mu.Lock()
	// Unique per dispatch and across restarts: a job sent again is a new job,
	// and an agent's held result never matches a job of another run.
	job := &agentJob{id: rand.Text(), request: request, done: make(chan agentOutput, 1)}
	n := h.node(node)
	n.jobs[job.id] = job
	close(n.wake)
	n.wake = make(chan struct{})
	h.mu.Unlock()
	var got agentOutput
	select {
	case got = <-job.done:
	case <-ctx.Done():
		h.mu.Lock()
		delete(n.jobs, job.id)
		h.mu.Unlock()
		got = agentOutput{failed: ctx.Err()}
	}
	return adapterReply(parent, ctx, request, target, started, got.out, got.failed)
}

// Claim hands a node's agent the jobs it has not taken, waiting up to wait
// for one. held lists every job the agent took and has not had acknowledged:
// running, or answered with the POST still in flight. A job it took and no
// longer holds was lost with the agent (a restart mid-job) and fails, as a
// dropped SSH session does. Only a job no agent took is handed out again.
func (h *AgentHub) Claim(ctx context.Context, node string, held []string, wait time.Duration) []AgentJob {
	holding := map[string]bool{}
	for _, id := range held {
		holding[id] = true
	}
	h.mu.Lock()
	n := h.node(node)
	for id, job := range n.jobs {
		if job.taken && !holding[id] {
			delete(n.jobs, id)
			job.done <- agentOutput{failed: errAgentLostJob}
		}
	}
	h.mu.Unlock()
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		h.mu.Lock()
		n := h.node(node)
		out := []AgentJob{}
		for id, job := range n.jobs {
			if !job.taken {
				job.taken = true
				out = append(out, AgentJob{ID: id, Request: job.request})
			}
		}
		wake := n.wake
		h.mu.Unlock()
		if len(out) > 0 {
			return out
		}
		select {
		case <-wake:
		case <-ctx.Done():
			return out
		case <-deadline.C:
			return out
		}
	}
}

// Complete takes a job's output: what node-agent.py printed, and whether it
// exited non-zero. A job the hub no longer waits for (timed out, or never
// sent) is ignored, so a late answer changes nothing.
func (h *AgentHub) Complete(node, id string, out []byte, exitFailed bool) bool {
	if len(out) > maxAdapterReply {
		out, exitFailed = nil, true
	}
	h.mu.Lock()
	n := h.node(node)
	job := n.jobs[id]
	if job == nil || !job.taken {
		h.mu.Unlock()
		return false
	}
	delete(n.jobs, id)
	h.mu.Unlock()
	var failed error
	if exitFailed {
		failed = errors.New("node-agent.py exited with an error")
	}
	job.done <- agentOutput{out: out, failed: failed}
	return true
}

// RoutedBackend sends requests for nodes on the agent transport through the
// hub and everything else, the gateway, the jump host, the off-site backup
// and console streams, over SSH (#606).
type RoutedBackend struct {
	SSH Backend
	Hub *AgentHub
	// Agents maps a node's SSH target to its name, for nodes whose
	// transport is agent.
	Agents map[string]string
}

func (b *RoutedBackend) Call(ctx context.Context, request D, target string) (any, error) {
	if node, ok := b.Agents[target]; ok {
		return b.Hub.Call(ctx, request, node, target)
	}
	return b.SSH.Call(ctx, request, target)
}

// Stream keeps consoles on SSH.
func (b *RoutedBackend) Stream(ctx context.Context, request D, target string) (io.ReadWriteCloser, error) {
	s, ok := b.SSH.(Streamer)
	if !ok {
		return nil, errors.New("console streams are not available")
	}
	return s.Stream(ctx, request, target)
}
