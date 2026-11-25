package carrel

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func hubFailure(t *testing.T, err error) D {
	t.Helper()
	f, ok := err.(Failure)
	if !ok {
		t.Fatalf("not a Failure: %v", err)
	}
	return obj(f.Result["error"])
}

// An operation holds the writer while it calls a node: the agent's side of
// the hub must not need it.
func TestAgentHubAnswersWhileTheWriterIsHeld(t *testing.T) {
	p, _, _ := originFixture(t)
	hub := NewAgentHub()
	p.writer.Lock()
	defer p.writer.Unlock()
	got := make(chan any, 1)
	go func() {
		v, err := hub.Call(context.Background(), D{"op": "status"}, "pve1", "pve1")
		if err != nil {
			t.Error(err)
		}
		got <- v
	}()
	jobs := hub.Claim(context.Background(), "pve1", "a", 1, nil, 5*time.Second)
	if len(jobs) != 1 || jobs[0].Request["op"] != "status" {
		t.Fatalf("jobs %v", jobs)
	}
	if !hub.Complete("pve1", jobs[0].ID, []byte(`{"ok":true,"result":{"status":"running"}}`), false) {
		t.Fatal("answer refused")
	}
	if v := obj(<-got); v["status"] != "running" {
		t.Fatalf("result %v", v)
	}
}

// A queued job wakes a waiting claim at once.
func TestAgentHubWakesAWaitingClaim(t *testing.T) {
	hub := NewAgentHub()
	claimed := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		hub.Claim(context.Background(), "pve1", "a", 1, nil, 30*time.Second)
		claimed <- time.Since(start)
	}()
	time.Sleep(50 * time.Millisecond)
	go func() { _, _ = hub.Call(context.Background(), D{"op": "inventory"}, "pve1", "pve1") }()
	select {
	case d := <-claimed:
		if d > 2*time.Second {
			t.Fatalf("claim took %v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the claim did not wake")
	}
}

// A job the agent took and no longer holds fails like a dropped SSH session;
// a job nobody took waits for the next claim.
func TestAgentHubFailsALostJobAndKeepsAnUntakenOne(t *testing.T) {
	hub := NewAgentHub()
	results := make(chan error, 2)
	call := func(op string) {
		_, err := hub.Call(context.Background(), D{"op": op}, "pve1", "pve1")
		results <- err
	}
	go call("status")
	first := hub.Claim(context.Background(), "pve1", "a", 1, nil, 5*time.Second)
	if len(first) != 1 {
		t.Fatalf("first claim %v", first)
	}
	go call("metrics")
	// The agent restarted: a new process that holds nothing.
	second := hub.Claim(context.Background(), "pve1", "b", 1, nil, 5*time.Second)
	if len(second) != 1 || second[0].Request["op"] != "metrics" {
		t.Fatalf("second claim %v", second)
	}
	e := hubFailure(t, <-results)
	if e["code"] != "backend_unavailable" || e["backend_code"] != "adapter_process_failed" {
		t.Fatalf("lost job %v", e)
	}
	// The job still held is answered normally, and twice is refused.
	if !hub.Complete("pve1", second[0].ID, []byte(`{"ok":false,"error_code":"command_failed"}`), true) {
		t.Fatal("answer refused")
	}
	if e := hubFailure(t, <-results); e["backend_code"] != "command_failed" {
		t.Fatalf("node failure %v", e)
	}
	if hub.Complete("pve1", second[0].ID, []byte(`{"ok":true,"result":{}}`), false) {
		t.Fatal("a second answer was taken")
	}
	// The old process's late poll gets nothing.
	go call("status")
	if late := hub.Claim(context.Background(), "pve1", "a", 2, nil, 50*time.Millisecond); len(late) != 0 {
		t.Fatalf("a replaced process got %v", late)
	}
}

// A retry that overlaps a slow poll, or arrives after a newer one, neither
// takes jobs nor fails the ones the agent holds.
func TestAgentHubIgnoresAnOverlappingPoll(t *testing.T) {
	hub := NewAgentHub()
	results := make(chan error, 1)
	go func() {
		_, err := hub.Call(context.Background(), D{"op": "status"}, "pve1", "pve1")
		results <- err
	}()
	taken := hub.Claim(context.Background(), "pve1", "a", 2, nil, 5*time.Second)
	if len(taken) != 1 {
		t.Fatalf("claim %v", taken)
	}
	// Poll 1 arrives late and poll 2 again: both stale, neither judges.
	for _, seq := range []uint64{1, 2} {
		if got := hub.Claim(context.Background(), "pve1", "a", seq, nil, 10*time.Millisecond); len(got) != 0 {
			t.Fatalf("stale poll %d got %v", seq, got)
		}
	}
	// A slow poll superseded while it waits hands out nothing.
	slow := make(chan []AgentJob, 1)
	go func() { slow <- hub.Claim(context.Background(), "pve1", "a", 3, []string{taken[0].ID}, 5*time.Second) }()
	time.Sleep(50 * time.Millisecond)
	_ = hub.Claim(context.Background(), "pve1", "a", 4, []string{taken[0].ID}, 10*time.Millisecond)
	go func() { _, _ = hub.Call(context.Background(), D{"op": "metrics"}, "pve1", "pve1") }()
	if got := <-slow; len(got) != 0 {
		t.Fatalf("a superseded poll got %v", got)
	}
	if !hub.Complete("pve1", taken[0].ID, []byte(`{"ok":true,"result":{}}`), false) {
		t.Fatal("the held job was lost")
	}
	if err := <-results; err != nil {
		t.Fatal(err)
	}
}

// A call that times out leaves nothing behind, and a late answer is ignored.
func TestAgentHubIgnoresALateAnswer(t *testing.T) {
	hub := NewAgentHub()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	var err error
	go func() {
		defer wg.Done()
		_, err = hub.Call(ctx, D{"op": "status"}, "pve1", "pve1")
	}()
	jobs := hub.Claim(context.Background(), "pve1", "a", 1, nil, 5*time.Second)
	wg.Wait()
	if e := hubFailure(t, err); e["backend_code"] != "adapter_timeout" {
		t.Fatalf("timeout %v", e)
	}
	if hub.Complete("pve1", jobs[0].ID, []byte(`{"ok":true,"result":{}}`), false) {
		t.Fatal("a late answer was taken")
	}
	if left := hub.Claim(context.Background(), "pve1", "a", 2, []string{jobs[0].ID}, 10*time.Millisecond); len(left) != 0 {
		t.Fatalf("left behind %v", left)
	}
}

// encodeAdapter prints a fake backend's answer the way node-agent.py does.
func encodeAdapter(v any, err error) ([]byte, bool) {
	if err != nil {
		return encoded(D{"ok": false, "error_code": "command_failed"}), true
	}
	return encoded(D{"ok": true, "result": v}), false
}

// adapterBackend runs the recorder and reads its answer through
// adapterReply, as the SSH transport does: the baseline for the agent path.
type adapterBackend struct{ next Backend }

func (b adapterBackend) Call(ctx context.Context, request D, target string) (any, error) {
	started := time.Now()
	out, failed := encodeAdapter(b.next.Call(ctx, request, target))
	var err error
	if failed {
		err = errAgentLostJob
	}
	return adapterReply(ctx, ctx, request, target, started, out, err)
}

// fakeAgents runs one in-process agent per node against next, claiming
// jobs from the hub as carrel-agent will.
func fakeAgents(t *testing.T, p *Platform, next Backend) *RoutedBackend {
	ctx, stop := context.WithCancel(context.Background())
	hub := NewAgentHub()
	routed := &RoutedBackend{SSH: next, Hub: hub, Agents: map[string]string{}}
	var wg sync.WaitGroup
	for _, n := range p.Nodes() {
		routed.Agents[n.Target] = n.Name
		wg.Add(1)
		go func(name, target string) {
			defer wg.Done()
			var mu sync.Mutex
			held := map[string]bool{}
			var seq uint64
			for ctx.Err() == nil {
				seq++
				mu.Lock()
				ids := []string{}
				for id := range held {
					ids = append(ids, id)
				}
				mu.Unlock()
				for _, job := range hub.Claim(ctx, name, "fake-"+name, seq, ids, time.Second) {
					mu.Lock()
					held[job.ID] = true
					mu.Unlock()
					go func(job AgentJob) {
						out, failed := encodeAdapter(next.Call(ctx, job.Request, target))
						hub.Complete(name, job.ID, out, failed)
						mu.Lock()
						delete(held, job.ID)
						mu.Unlock()
					}(job)
				}
			}
		}(n.Name, n.Target)
	}
	t.Cleanup(func() { stop(); wg.Wait() })
	return routed
}

// The whole golden scenario gives the same record through the agent
// transport as through the adapter path SSH uses.
func TestGoldenThroughTheAgent(t *testing.T) {
	baseline := goldenText(t, goldenScenario, true, func(_ *Platform, rec *recorder) Backend { return adapterBackend{rec} })
	agent := goldenText(t, goldenScenario, true, func(p *Platform, rec *recorder) Backend {
		routed := fakeAgents(t, p, rec)
		routed.SSH = adapterBackend{rec}
		return routed
	})
	if baseline != agent {
		a, b := strings.Split(baseline, "\n"), strings.Split(agent, "\n")
		for i := range min(len(a), len(b)) {
			if a[i] != b[i] {
				t.Fatalf("first difference at line %d:\nssh:   %s\nagent: %s", i+1, a[i], b[i])
			}
		}
		t.Fatalf("records differ in length: %d and %d lines", len(a), len(b))
	}
}

// A poll whose answer never reached the agent gives its jobs back: the next
// poll takes them, and they are not failed as lost.
func TestAgentHubReleasesUndeliveredJobs(t *testing.T) {
	hub := NewAgentHub()
	results := make(chan error, 1)
	go func() {
		_, err := hub.Call(context.Background(), D{"op": "status"}, "pve1", "pve1")
		results <- err
	}()
	lost := hub.Claim(context.Background(), "pve1", "a", 1, nil, 5*time.Second)
	hub.Release("pve1", "a", lost)
	again := hub.Claim(context.Background(), "pve1", "a", 2, nil, 5*time.Second)
	if len(again) != 1 || again[0].ID != lost[0].ID {
		t.Fatalf("released job not handed out again: %v", again)
	}
	hub.Complete("pve1", again[0].ID, []byte(`{"ok":true,"result":{}}`), false)
	if err := <-results; err != nil {
		t.Fatal(err)
	}
}
