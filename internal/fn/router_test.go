package fn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRuntime stands in for Firecracker: every instance dials one test server.
type fakeRuntime struct {
	backend *httptest.Server
	wakes   atomic.Int32
	stops   atomic.Int32
	err     error

	mu   sync.Mutex
	last *fakeInstance
}

type fakeInstance struct {
	runtime *fakeRuntime
	done    chan struct{}
	once    sync.Once
}

func (r *fakeRuntime) Wake(context.Context, Function) (Instance, error) {
	if r.err != nil {
		return nil, r.err
	}
	r.wakes.Add(1)
	instance := &fakeInstance{runtime: r, done: make(chan struct{})}
	r.mu.Lock()
	r.last = instance
	r.mu.Unlock()
	return instance, nil
}

func (i *fakeInstance) Dial(ctx context.Context) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", i.runtime.backend.Listener.Addr().String())
}
func (i *fakeInstance) Stop()                 { i.once.Do(func() { i.runtime.stops.Add(1) }) }
func (i *fakeInstance) Done() <-chan struct{} { return i.done }

func deploy(t *testing.T, root, name, version, extra string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf(`{"name":%q,"version":%q%s}`, name, version, extra)
	if err := os.WriteFile(filepath.Join(dir, "function.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func setup(t *testing.T, handler http.HandlerFunc) (*Router, *fakeRuntime, string) {
	t.Helper()
	if handler == nil {
		handler = func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }
	}
	backend := httptest.NewServer(handler)
	t.Cleanup(backend.Close)
	runtime := &fakeRuntime{backend: backend}
	root := t.TempDir()
	return NewRouter(root, runtime), runtime, root
}

func get(router *Router, name string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://"+name+".example.test/", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func TestReuseWakesOnceForConcurrentRequests(t *testing.T) {
	router, runtime, root := setup(t, nil)
	deploy(t, root, "api", "v1", "")
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := get(router, "api"); got.Code != http.StatusOK || got.Body.String() != "ok" {
				t.Errorf("status %d body %q", got.Code, got.Body)
			}
		}()
	}
	wg.Wait()
	if wakes := runtime.wakes.Load(); wakes != 1 {
		t.Fatalf("wakes = %d, want 1", wakes)
	}
}

func TestReuseSleepsWhenIdleAndWakesAgain(t *testing.T) {
	router, runtime, root := setup(t, nil)
	deploy(t, root, "api", "v1", `,"idle_seconds":30`)
	now := time.Unix(1_800_000_000, 0)
	router.now = func() time.Time { return now }

	get(router, "api")
	now = now.Add(29 * time.Second)
	router.Reap()
	if stops := runtime.stops.Load(); stops != 0 {
		t.Fatalf("stopped after 29 s: %d", stops)
	}
	now = now.Add(time.Second)
	router.Reap()
	if stops := runtime.stops.Load(); stops != 1 {
		t.Fatalf("stops after 30 s = %d, want 1", stops)
	}
	if got := get(router, "api"); got.Code != http.StatusOK {
		t.Fatalf("status after sleep = %d", got.Code)
	}
	if wakes := runtime.wakes.Load(); wakes != 2 {
		t.Fatalf("wakes = %d, want 2", wakes)
	}
}

func TestReuseDoesNotSleepDuringARequest(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	router, runtime, root := setup(t, func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
	})
	deploy(t, root, "api", "v1", `,"idle_seconds":1`)
	now := time.Unix(1_800_000_000, 0)
	router.now = func() time.Time { return now }
	finished := make(chan struct{})
	go func() {
		get(router, "api")
		close(finished)
	}()
	<-entered
	router.Reap()
	if stops := runtime.stops.Load(); stops != 0 {
		t.Fatalf("stopped an instance that was serving: %d", stops)
	}
	close(release)
	<-finished
}

func TestReuseReplacesAnInstanceThatDied(t *testing.T) {
	router, runtime, root := setup(t, nil)
	deploy(t, root, "api", "v1", "")
	get(router, "api")
	runtime.mu.Lock()
	close(runtime.last.done)
	runtime.mu.Unlock()
	if got := get(router, "api"); got.Code != http.StatusOK {
		t.Fatalf("status = %d", got.Code)
	}
	if wakes, stops := runtime.wakes.Load(), runtime.stops.Load(); wakes != 2 || stops != 1 {
		t.Fatalf("wakes = %d stops = %d, want 2 and 1", wakes, stops)
	}
}

func TestFreshUsesOneInstancePerRequest(t *testing.T) {
	router, runtime, root := setup(t, nil)
	deploy(t, root, "job", "v1", `,"mode":"fresh"`)
	for range 3 {
		if got := get(router, "job"); got.Code != http.StatusOK {
			t.Fatalf("status = %d", got.Code)
		}
	}
	if wakes, stops := runtime.wakes.Load(), runtime.stops.Load(); wakes != 3 || stops != 3 {
		t.Fatalf("wakes = %d stops = %d, want 3 and 3", wakes, stops)
	}
}

func TestFreshAnswers503AtTheInstanceLimit(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	router, runtime, root := setup(t, func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
	})
	deploy(t, root, "job", "v1", `,"mode":"fresh","max_instances":1`)
	finished := make(chan struct{})
	go func() {
		get(router, "job")
		close(finished)
	}()
	<-entered
	got := get(router, "job")
	if got.Code != http.StatusServiceUnavailable || got.Header().Get("Retry-After") == "" {
		t.Fatalf("status = %d Retry-After = %q", got.Code, got.Header().Get("Retry-After"))
	}
	close(release)
	<-finished
	if wakes := runtime.wakes.Load(); wakes != 1 {
		t.Fatalf("wakes = %d, want 1", wakes)
	}
}

func TestUnknownAndInvalidNamesAre404(t *testing.T) {
	router, runtime, _ := setup(t, nil)
	for _, name := range []string{"missing", "UPPER", "a..b"} {
		req := httptest.NewRequest(http.MethodGet, "http://router.test/", nil)
		req.Header.Set("X-Carrel-Function", name)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusNotFound {
			t.Errorf("%q: status = %d", name, recorder.Code)
		}
	}
	if wakes := runtime.wakes.Load(); wakes != 0 {
		t.Fatalf("wakes = %d", wakes)
	}
}

func TestWakeFailures(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{errors.New("snapshot missing"), http.StatusBadGateway},
		{ErrBusy, http.StatusServiceUnavailable},
		{context.DeadlineExceeded, http.StatusGatewayTimeout},
	} {
		router, runtime, root := setup(t, nil)
		runtime.err = tc.err
		deploy(t, root, "api", "v1", "")
		if got := get(router, "api"); got.Code != tc.want {
			t.Errorf("%v: status = %d, want %d", tc.err, got.Code, tc.want)
		}
	}
}

func TestANewDeployStopsTheOldInstance(t *testing.T) {
	router, runtime, root := setup(t, nil)
	deploy(t, root, "api", "v1", "")
	get(router, "api")
	deploy(t, root, "api", "v2", "")
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(filepath.Join(root, "api", "function.json"), later, later); err != nil {
		t.Fatal(err)
	}
	get(router, "api")
	if wakes, stops := runtime.wakes.Load(), runtime.stops.Load(); wakes != 2 || stops != 1 {
		t.Fatalf("wakes = %d stops = %d, want 2 and 1", wakes, stops)
	}
}

func TestRequestTimeout(t *testing.T) {
	router, _, root := setup(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	})
	deploy(t, root, "slow", "v1", `,"timeout_seconds":1`)
	start := time.Now()
	got := get(router, "slow")
	if got.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", got.Code)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %s", elapsed)
	}
}

func TestNormalizeLimits(t *testing.T) {
	valid := Function{Name: "api"}
	if err := valid.normalize(); err != nil {
		t.Fatal(err)
	}
	if valid.Mode != ModeReuse || valid.MemoryMB != 512 || valid.Port != 8080 ||
		valid.IdleSeconds != 300 || valid.TimeoutSeconds != 300 || valid.MaxInstances != 1 {
		t.Fatalf("defaults = %+v", valid)
	}
	fresh := Function{Name: "job", Mode: ModeFresh}
	if err := fresh.normalize(); err != nil || fresh.MaxInstances != 10 {
		t.Fatalf("fresh = %+v, %v", fresh, err)
	}
	for _, bad := range []Function{
		{Name: "Bad"},
		{Name: "api", Mode: "other"},
		{Name: "api", MemoryMB: 64},
		{Name: "api", MemoryMB: 4096},
		{Name: "api", Port: 1},
		{Name: "api", TimeoutSeconds: 3601},
		{Name: "api", WakePath: "wake"},
		{Name: "job", Mode: ModeFresh, MaxInstances: 11},
	} {
		if err := bad.normalize(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

// Two first requests used to build two states: each woke its own instance,
// and the one whose state was replaced was never stopped.
func TestFirstRequestsShareOneStateAndLeakNoInstance(t *testing.T) {
	for range 200 {
		router, runtime, root := setup(t, nil)
		deploy(t, root, "api", "v1", "")
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				get(router, "api")
			}()
		}
		wg.Wait()
		if wakes := runtime.wakes.Load(); wakes != 1 {
			t.Fatalf("wakes = %d, want 1", wakes)
		}
		router.Forget("api")
		if stops := runtime.stops.Load(); stops != 1 {
			t.Fatalf("stops = %d, want 1: an instance is left awake", stops)
		}
	}
}

func TestARetiredStateIsLookedUpAgain(t *testing.T) {
	router, runtime, root := setup(t, nil)
	deploy(t, root, "api", "v1", "")
	old, err := router.function("api")
	if err != nil {
		t.Fatal(err)
	}
	old.retire() // a deploy or a removal happened after the lookup
	recorder := httptest.NewRecorder()
	if router.serve(recorder, httptest.NewRequest(http.MethodGet, "http://api.example.test/", nil), old) {
		t.Fatal("a retired state served a request")
	}
	if wakes := runtime.wakes.Load(); wakes != 0 {
		t.Fatalf("a retired state woke %d instance(s)", wakes)
	}
}

func TestNoWakeAfterShutdown(t *testing.T) {
	router, runtime, root := setup(t, nil)
	deploy(t, root, "api", "v1", "")
	get(router, "api")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	router.Run(ctx)
	if stops := runtime.stops.Load(); stops != 1 {
		t.Fatalf("stops = %d, want 1", stops)
	}
	if got := get(router, "api"); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("status after shutdown = %d, want 503", got.Code)
	}
	if wakes := runtime.wakes.Load(); wakes != 1 {
		t.Fatalf("wakes = %d, want 1: a request woke an instance after shutdown", wakes)
	}
}
