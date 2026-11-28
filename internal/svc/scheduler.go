package svc

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/NYCU-WinLab/carrel/internal/schedule"
)

// scheduleHeader marks a request the host's scheduler sent (#643). The
// router removes it from every request that arrives from outside, so a
// service can trust it.
const scheduleHeader = "X-Carrel-Schedule"

// Scheduler fires the services' schedules on this host. Each service
// lives on one host, so each schedule fires from one place. A run that is
// still going when its schedule comes round again is skipped, and minutes
// the host missed while it was down are not replayed.
type Scheduler struct {
	Router *Router
	// Note writes a line into a service's log (Firecracker.Note).
	Note func(id, line string)
	now  func() time.Time

	mu      sync.Mutex
	plans   map[string][]schedule.Schedule // by service id
	running map[string]bool                // id/name while a run is in flight
	runs    sync.WaitGroup
}

// Set replaces a service's schedules with the desired ones that check.
func (s *Scheduler) Set(id string, list []schedule.Schedule) {
	kept := []schedule.Schedule{}
	for _, sc := range list {
		if err := sc.Check(); err != nil {
			slog.Warn("schedule_invalid", "service", id, "schedule", sc.Name, "error", err)
			continue
		}
		kept = append(kept, sc)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.plans == nil {
		s.plans = map[string][]schedule.Schedule{}
	}
	if len(kept) == 0 {
		delete(s.plans, id)
		return
	}
	s.plans[id] = kept
}

// Keep drops the schedules of services the desired state no longer names.
func (s *Scheduler) Keep(ids map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.plans {
		if !ids[id] {
			delete(s.plans, id)
		}
	}
}

// Run fires the schedules due at the start of each minute until ctx ends,
// then waits for the runs in flight.
func (s *Scheduler) Run(ctx context.Context) {
	defer s.runs.Wait()
	now := s.now
	if now == nil {
		now = time.Now
	}
	last := time.Time{}
	for {
		next := now().Truncate(time.Minute).Add(time.Minute)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
		}
		minute := now().Truncate(time.Minute)
		// A clock that steps back does not fire a minute twice.
		if !minute.After(last) {
			continue
		}
		last = minute
		s.tick(ctx, minute)
	}
}

// tick starts every schedule due in minute.
func (s *Scheduler) tick(ctx context.Context, minute time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, list := range s.plans {
		for _, sc := range list {
			if !sc.Due(minute) {
				continue
			}
			key := id + "/" + sc.Name
			if s.running == nil {
				s.running = map[string]bool{}
			}
			if s.running[key] {
				s.note(id, fmt.Sprintf("schedule %s skipped at %s: the previous run is still going", sc.Name, minute.UTC().Format(time.RFC3339)))
				continue
			}
			s.running[key] = true
			s.runs.Add(1)
			go func() {
				defer s.runs.Done()
				s.fire(ctx, id, sc)
				s.mu.Lock()
				delete(s.running, key)
				s.mu.Unlock()
			}()
		}
	}
}

func (s *Scheduler) note(id, line string) {
	if s.Note != nil {
		s.Note(id, line)
	}
}

// statusOnly keeps a response's status and throws its body away.
type statusOnly struct {
	header http.Header
	code   int
}

func (w *statusOnly) Header() http.Header { return w.header }
func (w *statusOnly) Write(p []byte) (int, error) {
	if w.code == 0 {
		w.code = 200
	}
	return len(p), nil
}
func (w *statusOnly) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
}

// fire sends one scheduled request through the router, as the gateway
// would, and writes its result into the service's log.
func (s *Scheduler) fire(ctx context.Context, id string, sc schedule.Schedule) {
	method, body := "GET", io.Reader(nil)
	if sc.Body != "" {
		method, body = "POST", strings.NewReader(sc.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+id+".service"+sc.Path, body)
	if err != nil {
		s.note(id, fmt.Sprintf("schedule %s did not run: %v", sc.Name, err))
		return
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Carrel-Service", id)
	req.Header.Set(scheduleHeader, sc.Name)
	req.Header.Set("User-Agent", "carrel-scheduler")
	req.RemoteAddr = "127.0.0.1:0"
	start := time.Now()
	w := &statusOnly{header: http.Header{}}
	s.Router.Scheduled(w, req)
	if w.code == 0 {
		w.code = 200
	}
	s.note(id, fmt.Sprintf("schedule %s: HTTP %d in %d ms", sc.Name, w.code, time.Since(start).Milliseconds()))
}
