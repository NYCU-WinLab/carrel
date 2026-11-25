package carrel

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"slices"
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
	// streamWait is how long a console waits for the agent to connect
	// back, and then for node-agent.py's first line; 0 is 30 seconds.
	streamWait time.Duration
}

type agentNode struct {
	jobs map[string]*agentJob
	// session is the agent process polling now, and seq the number of its
	// latest poll. A poll from another process means the agent restarted:
	// the old one's jobs are lost and its later polls get nothing. A poll
	// older than the latest (a retry overlapping a slow one) gets nothing
	// and judges nothing.
	session string
	seq     uint64
	retired map[string]bool
	// seen is when the node's agent last polled.
	seen time.Time
	// protocol, release and capabilities are what the agent reported in its
	// latest poll.
	protocol, release string
	capabilities      []string
	// streams are console streams waiting for the agent to connect back.
	streams map[string]*agentStream
	// wake is closed and replaced when a job is queued, so a waiting claim
	// answers at once instead of on its next tick.
	wake chan struct{}
}

type agentJob struct {
	id      string
	request D
	taken   bool
	session string
	seq     uint64
	at      time.Time
	done    chan agentOutput
}

// agentStream is a console the agent opens with a connection of its own
// (#606): the claim hands it out, and the agent dials back with its id.
type agentStream struct {
	request D
	taken   bool
	session string
	// conn receives the agent's connection, or nil when it could not be
	// taken over; it holds one, so the sender never waits.
	conn chan net.Conn
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
	// Stream: run the request with stdin and stdout on a connection to
	// /sites/v1/agent/streams/{id}, not as a job with one answer.
	Stream bool `json:"stream,omitempty"`
}

var errAgentLostJob = errors.New("the agent no longer holds the job")

func NewAgentHub() *AgentHub { return &AgentHub{nodes: map[string]*agentNode{}} }

func (h *AgentHub) node(name string) *agentNode {
	n := h.nodes[name]
	if n == nil {
		n = &agentNode{jobs: map[string]*agentJob{}, wake: make(chan struct{}), retired: map[string]bool{}, streams: map[string]*agentStream{}}
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
	// A copy made now: the caller's map may change after Call returns, while
	// the agent's poll still encodes it.
	job := &agentJob{id: rand.Text(), request: copyValue(request).(map[string]any), at: time.Now(), done: make(chan agentOutput, 1)}
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
		_, waiting := n.jobs[job.id]
		delete(n.jobs, job.id)
		h.mu.Unlock()
		got = agentOutput{failed: ctx.Err()}
		if !waiting {
			// An answer or a loss was taken just before the deadline: its
			// sender removed the job and is about to send. The node did
			// the work, so the caller hears what it did.
			got = <-job.done
		}
	}
	return adapterReply(parent, ctx, request, target, started, got.out, got.failed)
}

// Claim hands a node's agent the jobs nobody has taken, waiting up to wait
// for one. session names the agent process and seq numbers its polls,
// rising by one each time. held lists every job the agent took and has not
// had acknowledged: running, or answered with the POST still in flight. A
// job this session took in an earlier poll and no longer holds was lost (a
// crash inside the agent) and fails, as a dropped SSH session does; so do
// all jobs of a process that was replaced. Only a job nobody took is handed
// out again.
func (h *AgentHub) Claim(ctx context.Context, node, session string, seq uint64, held []string, wait time.Duration) []AgentJob {
	if !h.accept(node, session, seq, held) {
		return []AgentJob{}
	}
	h.mu.Lock()
	n := h.node(node) // accept made it; the map is read under the lock
	h.mu.Unlock()
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		h.mu.Lock()
		out := []AgentJob{}
		if n.session != session || n.seq != seq {
			// A newer poll took over: this one hands out nothing.
			h.mu.Unlock()
			return out
		}
		for id, job := range n.jobs {
			if !job.taken {
				job.taken, job.session, job.seq = true, session, seq
				out = append(out, AgentJob{ID: id, Request: job.request})
			}
		}
		for id, s := range n.streams {
			if !s.taken {
				s.taken, s.session = true, session
				out = append(out, AgentJob{ID: id, Request: s.request, Stream: true})
			}
		}
		wake := n.wake
		h.mu.Unlock()
		if len(out) > 0 {
			if ctx.Err() != nil {
				// The poll is gone: nobody will receive these.
				h.Release(node, session, out)
				return []AgentJob{}
			}
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

// accept records a poll: it is from the current process and newer than its
// last one, or it is refused. It fails what the agent lost and marks the
// agent alive.
func (h *AgentHub) accept(node, session string, seq uint64, held []string) bool {
	holding := map[string]bool{}
	for _, id := range held {
		holding[id] = true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	n := h.node(node)
	if session == "" || n.retired[session] || (session == n.session && seq <= n.seq) {
		return false
	}
	if session != n.session && n.session != "" {
		n.retired[n.session] = true
	}
	n.session, n.seq, n.seen = session, seq, time.Now()
	for id, job := range n.jobs {
		if job.taken && (job.session != session || !holding[id]) {
			delete(n.jobs, id)
			job.done <- agentOutput{failed: errAgentLostJob}
		}
	}
	return true
}

// Hello records the protocol and release a node's agent reported. A process
// already replaced by a newer one does not overwrite them.
func (h *AgentHub) Hello(node, session, protocol, release string, capabilities ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := h.node(node)
	if !n.retired[session] {
		n.protocol, n.release, n.capabilities = protocol, release, slices.Clone(capabilities)
	}
}

// Capable reports whether a node's agent polls now and said it can do
// something, such as "stream".
func (h *AgentHub) Capable(node, capability string, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := h.nodes[node]
	return n != nil && !n.seen.IsZero() && now.Sub(n.seen) < agentSilence && slices.Contains(n.capabilities, capability)
}

// Status is what node_list shows for a node on the agent transport: whether
// its agent polls, and the protocol and release it reported.
func (h *AgentHub) Status(node string, now time.Time) D {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := h.nodes[node]
	if n == nil || n.seen.IsZero() {
		return D{"connected": false}
	}
	return D{"connected": now.Sub(n.seen) < agentSilence, "protocol": n.protocol, "release": n.release,
		"capabilities": append([]string{}, n.capabilities...), "last_poll": n.seen.UTC().Format(time.RFC3339)}
}

// Heartbeat is a poll that takes no job: an agent shutting down sends it
// while its last jobs finish, so they are not swept as lost.
func (h *AgentHub) Heartbeat(node, session string, seq uint64, held []string) {
	h.accept(node, session, seq, held)
}

// Release puts back jobs a poll took but could not deliver (its answer
// failed to reach the agent), so the next poll hands them out instead of
// failing them as lost. They never ran.
func (h *AgentHub) Release(node, session string, jobs []AgentJob) {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := h.node(node)
	for _, j := range jobs {
		if job := n.jobs[j.ID]; job != nil && job.taken && job.session == session {
			job.taken, job.session, job.seq = false, "", 0
		}
		if s := n.streams[j.ID]; s != nil && s.taken && s.session == session {
			s.taken, s.session = false, ""
		}
	}
	close(n.wake)
	n.wake = make(chan struct{})
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
	// A job released after a poll's answer failed may still have reached
	// the agent and run: its answer counts all the same, so it is never
	// handed out again.
	job := n.jobs[id]
	if job == nil {
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

// agentSilence is how long a node's agent may go without polling before its
// jobs fail: three missed long polls. SSH gives up on a silent node after
// about 45 seconds; without this a job would wait its whole timeout, up to
// 4 hours, while the operation holds the writer.
const agentSilence = 90 * time.Second

// Sweep fails the jobs no agent will answer: those taken by an agent that
// stopped polling, and those nobody took within agentSilence.
func (h *AgentHub) Sweep(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, n := range h.nodes {
		silent := now.Sub(n.seen) > agentSilence
		for id, job := range n.jobs {
			if (job.taken && silent) || (!job.taken && now.Sub(job.at) > agentSilence) {
				delete(n.jobs, id)
				job.done <- agentOutput{failed: errAgentLostJob}
			}
		}
	}
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

// Stream opens a console through the node's agent when it can stream, and
// over SSH otherwise: an agent from before streams, or a node on SSH.
func (b *RoutedBackend) Stream(ctx context.Context, request D, target string) (io.ReadWriteCloser, error) {
	if node, ok := b.Agents[target]; ok && b.Hub.Capable(node, "stream", time.Now()) {
		return b.Hub.Stream(ctx, request, node)
	}
	s, ok := b.SSH.(Streamer)
	if !ok {
		return nil, errors.New("console streams are not available")
	}
	return s.Stream(ctx, request, target)
}

// Stream asks a node's agent for a console: the next claim hands it out, the
// agent connects back to the agent listener, and node-agent.py's stdin and
// stdout run over that connection, as they do over SSH. The stream ends with
// ctx. It is not a job: a restart of the agent cuts it, as it would cut an
// SSH session, and nothing is retried.
func (h *AgentHub) Stream(ctx context.Context, request D, node string) (io.ReadWriteCloser, error) {
	id := rand.Text()
	s := &agentStream{request: copyValue(request).(map[string]any), conn: make(chan net.Conn, 1)}
	h.mu.Lock()
	n := h.node(node)
	n.streams[id] = s
	close(n.wake)
	n.wake = make(chan struct{})
	h.mu.Unlock()
	limit := h.streamWait
	if limit == 0 {
		limit = 30 * time.Second
	}
	wait := time.NewTimer(limit)
	defer wait.Stop()
	var c net.Conn
	received := false
	select {
	case c = <-s.conn:
		received = true
	case <-ctx.Done():
	case <-wait.C:
	}
	if !received {
		h.mu.Lock()
		_, waiting := n.streams[id]
		delete(n.streams, id)
		h.mu.Unlock()
		if !waiting {
			// The agent connected just now: its connection is on its way,
			// within the 10 seconds the listener gives its answer.
			if late := <-s.conn; late != nil {
				late.Close()
			}
		}
	}
	if c == nil {
		return nil, errors.New("the node's agent did not open the console")
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	_ = c.SetReadDeadline(time.Now().Add(limit))
	reader := bufio.NewReaderSize(c, 4096)
	line, err := reader.ReadSlice('\n')
	var reply D
	if err != nil || json.Unmarshal(line, &reply) != nil || reply["ok"] != true {
		stop()
		c.Close()
		return nil, errors.New("the node did not open the console")
	}
	_ = c.SetReadDeadline(time.Time{})
	return &stream{Reader: reader, Writer: c, stop: func() { stop(); c.Close() }}, nil
}

// Attach takes the stream an agent connects back for. Only a stream handed
// to this node's current agent process is taken, and only once.
func (h *AgentHub) Attach(node, id string) (chan<- net.Conn, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := h.nodes[node]
	if n == nil {
		return nil, false
	}
	s := n.streams[id]
	if s == nil || !s.taken || s.session != n.session {
		return nil, false
	}
	delete(n.streams, id)
	return s.conn, true
}
