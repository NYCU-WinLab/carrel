package fn

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NYCU-WinLab/carrel/internal/schedule"
)

type notes struct {
	mu    sync.Mutex
	lines []string
}

func (n *notes) add(id, line string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.lines = append(n.lines, id+": "+line)
}

func (n *notes) all() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return strings.Join(n.lines, "\n")
}

func TestScheduledRunsReachTheFunctionMarked(t *testing.T) {
	type seen struct{ method, path, mark, body string }
	got := make(chan seen, 4)
	router, _, root := setup(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- seen{r.Method, r.URL.RequestURI(), r.Header.Get(scheduleHeader), string(b)}
		w.WriteHeader(204)
	})
	deploy(t, root, "t1-job", "v1", "")
	n := &notes{}
	s := &Scheduler{Router: router, Note: n.add}
	s.Set("t1-job", []schedule.Schedule{
		{Name: "every", Cron: "* * * * *", TimeZone: "UTC", Path: "/tick?x=1"},
		{Name: "post", Cron: "* * * * *", TimeZone: "UTC", Path: "/hook", Body: `{"a":1}`},
		{Name: "never", Cron: "0 0 1 1 *", TimeZone: "UTC", Path: "/"},
		{Name: "Bad", Cron: "* * * * *", TimeZone: "UTC", Path: "/"},
	})
	s.tick(context.Background(), time.Date(2026, 11, 27, 10, 3, 0, 0, time.UTC))
	s.runs.Wait()
	runs := map[string]seen{}
	for range 2 {
		r := <-got
		runs[r.mark] = r
	}
	if runs["every"] != (seen{"GET", "/tick?x=1", "every", ""}) || runs["post"] != (seen{"POST", "/hook", "post", `{"a":1}`}) || len(got) != 0 {
		t.Fatalf("runs: %+v", runs)
	}
	if log := n.all(); !strings.Contains(log, "t1-job: schedule every: HTTP 204") || !strings.Contains(log, "schedule post: HTTP 204") {
		t.Fatalf("notes: %s", log)
	}
	// Dropped from the desired state, the function's schedules stop.
	s.Keep(map[string]bool{})
	s.tick(context.Background(), time.Date(2026, 11, 27, 10, 4, 0, 0, time.UTC))
	s.runs.Wait()
	if len(got) != 0 {
		t.Fatal("a removed function's schedule ran")
	}
}

func TestOutsideRequestsCannotClaimTheSchedule(t *testing.T) {
	mark := make(chan string, 1)
	router, _, root := setup(t, func(w http.ResponseWriter, r *http.Request) { mark <- r.Header.Get(scheduleHeader) })
	deploy(t, root, "t1-job", "v1", "")
	req := httptest.NewRequest(http.MethodGet, "http://t1-job.example.test/", nil)
	req.Header.Set("X-Carrel-Function", "t1-job")
	req.Header.Set(scheduleHeader, "forged")
	router.ServeHTTP(httptest.NewRecorder(), req)
	if m := <-mark; m != "" {
		t.Fatalf("the function saw %q", m)
	}
}

func TestARunStillGoingIsSkipped(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	router, _, root := setup(t, func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
	})
	deploy(t, root, "t1-job", "v1", `,"timeout_seconds":30`)
	n := &notes{}
	s := &Scheduler{Router: router, Note: n.add}
	s.Set("t1-job", []schedule.Schedule{{Name: "slow", Cron: "* * * * *", TimeZone: "UTC", Path: "/"}})
	minute := time.Date(2026, 11, 27, 10, 3, 0, 0, time.UTC)
	s.tick(context.Background(), minute)
	<-started
	s.tick(context.Background(), minute.Add(time.Minute))
	close(release)
	s.runs.Wait()
	if len(started) != 0 || !strings.Contains(n.all(), "schedule slow skipped") {
		t.Fatalf("notes: %s", n.all())
	}
}
