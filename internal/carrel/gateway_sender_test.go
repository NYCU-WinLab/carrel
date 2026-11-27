package carrel

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fastGatewayRetry(t *testing.T) {
	old := gatewayRetryDelays
	gatewayRetryDelays = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { gatewayRetryDelays = old })
}

func waitSender(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 2000; i++ {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not reached")
}

// idleAtEnd waits for the worker to stop before the test restores shared vars.
func idleAtEnd(t *testing.T, s *gatewaySender) {
	t.Cleanup(func() {
		waitSender(t, func() bool {
			s.mu.Lock()
			defer s.mu.Unlock()
			return !s.running
		})
	})
}

func testSync(name string) gatewaySync {
	return gatewaySync{hosts: name, held: map[string]any{"v": name}}
}

func TestGatewaySenderLatestWinsInOrder(t *testing.T) {
	var delivered atomic.Value
	first, release := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var sent []string
	s := newGatewaySender(func(g gatewaySync) error {
		mu.Lock()
		sent = append(sent, g.hosts)
		n := len(sent)
		mu.Unlock()
		if n == 1 {
			close(first)
			<-release
		}
		return nil
	}, &delivered)
	s.Submit(testSync("a"))
	<-first
	s.Submit(testSync("b"))
	s.Submit(testSync("c"))
	last := s.Submit(testSync("d"))
	close(release)
	waitSender(t, func() bool { return s.Status().Delivered == last })
	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 2 || sent[0] != "a" || sent[1] != "d" {
		t.Fatalf("sent %v, want [a d]", sent)
	}
	if held, _ := delivered.Load().(map[string]any); held["v"] != "d" {
		t.Fatalf("delivered %v", held)
	}
}

func TestGatewaySenderOrderUnderConcurrentSubmit(t *testing.T) {
	var delivered atomic.Value
	var mu sync.Mutex
	var order []string
	s := newGatewaySender(func(g gatewaySync) error {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, g.hosts)
		return nil
	}, &delivered)
	names := map[uint64]string{}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := strconv.Itoa(i)
			// Submit under one lock so the name matches the generation.
			mu.Lock()
			defer mu.Unlock()
			names[s.Submit(testSync(name))] = name
		}()
	}
	wg.Wait()
	waitSender(t, func() bool { return s.Status().Delivered == 50 })
	mu.Lock()
	defer mu.Unlock()
	if held, _ := delivered.Load().(map[string]any); held["v"] != names[50] {
		t.Fatalf("delivered %v, want the newest config %q", held, names[50])
	}
	// Sends rise in generation order: a later send never carries an older one.
	pos := -1
	for gen := uint64(1); gen <= 50; gen++ {
		for i, n := range order {
			if n == names[gen] {
				if i < pos {
					t.Fatalf("generation %d was sent before an older one", gen)
				}
				pos = i
			}
		}
	}
}

func TestGatewaySenderRetryThenSuccess(t *testing.T) {
	fastGatewayRetry(t)
	var delivered atomic.Value
	var calls atomic.Int32
	s := newGatewaySender(func(gatewaySync) error {
		if calls.Add(1) < 3 {
			return errors.New("down")
		}
		return nil
	}, &delivered)
	idleAtEnd(t, s)
	gen := s.Submit(testSync("a"))
	waitSender(t, func() bool { return s.Status().Delivered == gen })
	if st := s.Status(); st.Err != nil || calls.Load() != 3 {
		t.Fatalf("status %+v calls %d", st, calls.Load())
	}
}

func TestGatewaySenderRetryExhausted(t *testing.T) {
	fastGatewayRetry(t)
	var delivered atomic.Value
	var calls atomic.Int32
	s := newGatewaySender(func(gatewaySync) error {
		calls.Add(1)
		return errors.New("down")
	}, &delivered)
	idleAtEnd(t, s)
	s.Submit(testSync("a"))
	waitSender(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return !s.running
	})
	if calls.Load() != 4 {
		t.Fatalf("calls %d, want 4", calls.Load())
	}
	if st := s.Status(); st.Err == nil || st.Delivered != 0 || delivered.Load() != nil {
		t.Fatalf("status %+v", st)
	}
	// The next Submit starts again.
	s.Submit(testSync("b"))
	waitSender(t, func() bool { return calls.Load() == 8 })
}

func TestGatewaySenderNewerReplacesRetry(t *testing.T) {
	old := gatewayRetryDelays
	gatewayRetryDelays = []time.Duration{time.Hour, time.Hour, time.Hour}
	t.Cleanup(func() { gatewayRetryDelays = old })
	var delivered atomic.Value
	failed := make(chan struct{}, 1)
	s := newGatewaySender(func(g gatewaySync) error {
		if g.hosts == "a" {
			failed <- struct{}{}
			return errors.New("down")
		}
		return nil
	}, &delivered)
	idleAtEnd(t, s)
	s.Submit(testSync("a"))
	<-failed
	gen := s.Submit(testSync("b"))
	waitSender(t, func() bool { return s.Status().Delivered == gen })
}

func TestGatewaySenderBlockedSendDoesNotBlockSubmit(t *testing.T) {
	var delivered atomic.Value
	in, release := make(chan struct{}), make(chan struct{})
	s := newGatewaySender(func(g gatewaySync) error {
		if g.hosts == "a" {
			close(in)
			<-release
		}
		return nil
	}, &delivered)
	s.Submit(testSync("a"))
	<-in
	done := make(chan uint64)
	go func() { done <- s.Submit(testSync("b")); _ = s.Status() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Submit blocked behind a send")
	}
	close(release)
	waitSender(t, func() bool { return s.Status().Delivered == 2 })
}

// settleGateway waits until the platform's sender has nothing queued or being
// sent, so a test can look at what Reconcile handed it (#800).
func settleGateway(t *testing.T, p *Platform) {
	t.Helper()
	waitSender(t, func() bool {
		p.gateway.mu.Lock()
		defer p.gateway.mu.Unlock()
		return !p.gateway.running
	})
}

// fastGatewayRetries shrinks the retry waits for a test that makes the gateway fail.
func fastGatewayRetries(t *testing.T) {
	t.Helper()
	old := gatewayRetryDelays
	gatewayRetryDelays = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { gatewayRetryDelays = old })
}

// Reconcile queues the gateway config and returns: a gateway that blocks does
// not hold up the writer (#804).
func TestReconcileDoesNotWaitForASlowGateway(t *testing.T) {
	p, b, _ := freezeSite(t)
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	intercept(b, func(r D) (any, error, bool) {
		if r["op"] == "sync" {
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
		}
		return nil, nil, false
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.execution(context.Background()).Reconcile()
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("Reconcile waited for the gateway")
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("the gateway never received the config")
	}
	close(release)
	settleGateway(t, p)
	if p.gateway.Status().Delivered == 0 {
		t.Fatal("the config was not delivered after the gateway answered")
	}
}
