package carrel

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// gatewayRetryDelays is the wait before each retry of one gateway config: four
// attempts in all. A var so tests can shrink it. The gateway call already times
// out at 240 s, so more tries would only hide a real outage; maintenance
// retries later anyway.
var gatewayRetryDelays = []time.Duration{2 * time.Second, 10 * time.Second, 30 * time.Second}

// gatewaySenderStatus is what Status reports.
type gatewaySenderStatus struct {
	// Err is the last failure, nil after a success.
	Err error
	// Delivered is the newest generation the gateway took, 0 for none.
	Delivered uint64
}

// gatewaySender sends gateway configs in generation order, off the writer
// lock. It has its own mutex, like jumpMu and jumpGen in jump.go. Latest wins:
// a config still queued or being retried is dropped when a newer one arrives.
type gatewaySender struct {
	send func(gatewaySync) error
	// delivered receives the fingerprints of the newest delivered config.
	delivered *atomic.Value

	mu        sync.Mutex
	gen       uint64
	pending   *gatewaySync
	pendingAt uint64
	running   bool
	lastErr   error
	sentGen   uint64
	wake      chan struct{}
}

func newGatewaySender(send func(gatewaySync) error, delivered *atomic.Value) *gatewaySender {
	return &gatewaySender{send: send, delivered: delivered, wake: make(chan struct{}, 1)}
}

// Submit queues g as the newest config and returns its generation. It never
// waits for a send.
func (s *gatewaySender) Submit(g gatewaySync) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gen++
	s.pending, s.pendingAt = &g, s.gen
	if s.running {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	} else {
		s.running = true
		go s.run()
	}
	return s.gen
}

// Status reports the last error and the last delivered generation.
func (s *gatewaySender) Status() gatewaySenderStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return gatewaySenderStatus{Err: s.lastErr, Delivered: s.sentGen}
}

func (s *gatewaySender) run() {
	for {
		s.mu.Lock()
		g, gen := s.pending, s.pendingAt
		s.pending = nil
		if g == nil {
			s.running = false
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
		s.deliver(*g, gen)
	}
}

// newer reports whether a newer config is queued.
func (s *gatewaySender) newer() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending != nil
}

// deliver tries g up to len(gatewayRetryDelays)+1 times. It gives up on g as
// soon as a newer config is queued.
func (s *gatewaySender) deliver(g gatewaySync, gen uint64) {
	for attempt := 0; ; attempt++ {
		err := s.send(g)
		s.mu.Lock()
		s.lastErr = err
		if err == nil {
			if gen > s.sentGen {
				s.sentGen = gen
				s.delivered.Store(g.held)
			}
			s.mu.Unlock()
			return
		}
		replaced := s.pending != nil
		s.mu.Unlock()
		slog.Error("gateway_send_failed", "event", "gateway_send_failed", "generation", gen, "attempt", attempt+1, "error", err.Error())
		if replaced || attempt >= len(gatewayRetryDelays) {
			return
		}
		if !s.pause(gatewayRetryDelays[attempt]) {
			return
		}
	}
}

// pause waits d and reports false when a newer config arrived meanwhile.
func (s *gatewaySender) pause(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			return !s.newer()
		case <-s.wake:
			if s.newer() {
				return false
			}
		}
	}
}
