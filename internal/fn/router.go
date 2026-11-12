// Package fn runs functions on a function host (PLAN 7.11): container
// images that sleep without memory and wake from a microVM snapshot when a
// request arrives.
package fn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Function is one deployed function, read from <root>/<name>/function.json.
type Function struct {
	Name           string `json:"name"`
	MemoryMB       int    `json:"memory_mb"`
	Port           int    `json:"port"`
	Mode           string `json:"mode"` // "reuse" or "fresh"
	IdleSeconds    int    `json:"idle_seconds"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	WakePath       string `json:"wake_path,omitempty"`
	MaxInstances   int    `json:"max_instances"`
	// Image and Digest record what the version was built from.
	Image  string `json:"image,omitempty"`
	Digest string `json:"digest,omitempty"`
	// Version names the directory v/<version> that holds rootfs.ext4,
	// snap.state and snap.mem. A snapshot records the path of its root file
	// system, so a version never moves.
	Version string `json:"version"`
	Dir     string `json:"-"`
}

const (
	ModeReuse = "reuse"
	ModeFresh = "fresh"

	defaultIdle     = 300
	defaultTimeout  = 300
	maxTimeout      = 3600
	defaultFreshMax = 10
)

var (
	// A function on a host is named t<tenant>-<name>: up to 4 characters
	// for the tenant and 32 for the name the tenant chose.
	nameRE    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
	versionRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

// ValidName reports whether name may name a function. Names become
// directory, lock and namespace names, so check before any of those.
func ValidName(name string) bool { return nameRE.MatchString(name) }

// normalize fills defaults and rejects values outside PLAN 7.11's limits.
func (f *Function) normalize() error {
	if !nameRE.MatchString(f.Name) {
		return fmt.Errorf("invalid function name %q", f.Name)
	}
	if f.Mode == "" {
		f.Mode = ModeReuse
	}
	if f.Mode != ModeReuse && f.Mode != ModeFresh {
		return fmt.Errorf("mode must be %q or %q", ModeReuse, ModeFresh)
	}
	if f.MemoryMB == 0 {
		f.MemoryMB = 512
	}
	if f.MemoryMB < 128 || f.MemoryMB > 2048 {
		return errors.New("memory_mb must be 128 to 2048")
	}
	if f.Port == 0 {
		f.Port = 8080
	}
	if f.Port < 2 || f.Port > 65535 {
		return errors.New("port must be 2 to 65535")
	}
	if f.IdleSeconds == 0 {
		f.IdleSeconds = defaultIdle
	}
	if f.TimeoutSeconds == 0 {
		f.TimeoutSeconds = defaultTimeout
	}
	if f.IdleSeconds < 1 || f.TimeoutSeconds < 1 || f.TimeoutSeconds > maxTimeout {
		return fmt.Errorf("idle_seconds must be positive and timeout_seconds 1 to %d", maxTimeout)
	}
	if f.WakePath != "" && !strings.HasPrefix(f.WakePath, "/") {
		return errors.New("wake_path must start with /")
	}
	switch {
	case f.Mode == ModeReuse:
		f.MaxInstances = 1 // version 1: one instance per reuse function
	case f.MaxInstances == 0:
		f.MaxInstances = defaultFreshMax
	case f.MaxInstances < 1 || f.MaxInstances > defaultFreshMax:
		return fmt.Errorf("max_instances must be 1 to %d", defaultFreshMax)
	}
	return nil
}

// LoadFunction reads one function directory.
func LoadFunction(dir string) (Function, error) {
	content, err := os.ReadFile(filepath.Join(dir, "function.json"))
	if err != nil {
		return Function{}, err
	}
	var f Function
	if err := json.Unmarshal(content, &f); err != nil {
		return Function{}, err
	}
	if f.Name != filepath.Base(dir) {
		return Function{}, fmt.Errorf("function.json names %q in directory %q", f.Name, filepath.Base(dir))
	}
	if !versionRE.MatchString(f.Version) {
		return Function{}, fmt.Errorf("invalid version %q", f.Version)
	}
	f.Dir = filepath.Join(dir, "v", f.Version)
	return f, f.normalize()
}

// Instance is one awake microVM.
type Instance interface {
	// Dial opens a connection to the function's port inside the instance.
	Dial(ctx context.Context) (net.Conn, error)
	// Stop ends the instance and releases what it held. It is safe to call twice.
	Stop()
	// Done is closed when the instance ended on its own.
	Done() <-chan struct{}
}

// Runtime wakes functions. The real one restores Firecracker snapshots.
type Runtime interface {
	Wake(ctx context.Context, f Function) (Instance, error)
}

// ErrBusy means the host has no room for another instance right now.
var ErrBusy = errors.New("no free instance slot")

type awake struct {
	instance Instance
	proxy    *httputil.ReverseProxy
	inflight int
	lastUsed time.Time
}

type state struct {
	fn Function
	// loaded is the modification time of function.json when fn was read.
	loaded time.Time
	mu     sync.Mutex
	// reuse mode: the one instance, nil while the function is asleep.
	current *awake
	// fresh mode: one token per running instance, and the instances, so a
	// removal stops them.
	slots chan struct{}
	fresh map[Instance]struct{}
	// wakes counts fresh wakes in progress; retire waits for them.
	wakes sync.WaitGroup
	// retired is set when a newer deploy or a shutdown replaced this state.
	// A request that still holds it must look the function up again, or it
	// would wake an instance that nothing watches.
	retired bool
}

// Router sends each request to its function and wakes the function first
// when it is asleep.
type Router struct {
	root    string
	runtime Runtime
	now     func() time.Time

	mu        sync.Mutex
	functions map[string]*state
	closed    bool
	// retiring counts states a request took out of functions and is
	// retiring; Forget waits for them too.
	retiring int
	retired  *sync.Cond
}

// errClosed means the router is shutting down.
var errClosed = errors.New("the router is shutting down")

func NewRouter(root string, runtime Runtime) *Router {
	r := &Router{root: root, runtime: runtime, now: time.Now, functions: map[string]*state{}}
	r.retired = sync.NewCond(&r.mu)
	return r
}

// function returns the state of a deployed function. It reads function.json
// again when the file changed, and retires the state of the old version.
func (r *Router) function(name string) (*state, error) {
	if !nameRE.MatchString(name) {
		return nil, os.ErrNotExist
	}
	// One lookup at a time: two first requests must end with one state, or
	// each would wake its own instance and one of them would never be reaped.
	r.mu.Lock()
	s, stale, err := r.lookup(name)
	if stale != nil {
		r.retiring++
	}
	r.mu.Unlock()
	if stale != nil {
		stale.retire()
		r.mu.Lock()
		r.retiring--
		r.retired.Broadcast()
		r.mu.Unlock()
	}
	return s, err
}

// lookup runs with r.mu held. stale is a state the caller must retire.
func (r *Router) lookup(name string) (s, stale *state, err error) {
	if r.closed {
		return nil, nil, errClosed
	}
	dir := filepath.Join(r.root, name)
	current := r.functions[name]
	info, err := os.Stat(filepath.Join(dir, "function.json"))
	if err != nil {
		delete(r.functions, name)
		return nil, current, err
	}
	if current != nil && current.loaded.Equal(info.ModTime()) {
		return current, nil, nil
	}
	// New or deployed again: the old instance runs the old version.
	f, err := LoadFunction(dir)
	if err != nil {
		delete(r.functions, name)
		return nil, current, err
	}
	s = &state{fn: f, loaded: info.ModTime(), slots: make(chan struct{}, f.MaxInstances), fresh: map[Instance]struct{}{}}
	r.functions[name] = s
	return s, current, nil
}

// retire stops the state's instances and tells requests that still hold the
// state to look the function up again. It returns when no instance of the
// state runs: a removal deletes the files next.
func (s *state) retire() {
	s.mu.Lock()
	current := s.current
	s.current = nil
	s.retired = true
	running := make([]Instance, 0, len(s.fresh))
	for instance := range s.fresh {
		running = append(running, instance)
	}
	s.mu.Unlock()
	if current != nil {
		current.instance.Stop()
	}
	for _, instance := range running {
		instance.Stop()
	}
	// A wake in progress sees the state retired and stops its instance.
	s.wakes.Wait()
}

// Forget drops a function's cached state and stops its instance, so the next
// request reads the directory again.
func (r *Router) Forget(name string) {
	r.mu.Lock()
	s := r.functions[name]
	delete(r.functions, name)
	r.mu.Unlock()
	if s != nil {
		s.retire()
	}
	// A request may have taken the state out first and still be retiring it.
	r.mu.Lock()
	for r.retiring > 0 {
		r.retired.Wait()
	}
	r.mu.Unlock()
}

// functionName takes the function from the X-Carrel-Function header the
// gateway sets, or from the first label of the host name.
func functionName(req *http.Request) string {
	if name := req.Header.Get("X-Carrel-Function"); name != "" {
		return name
	}
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	label, _, _ := strings.Cut(host, ".")
	return label
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	name := functionName(req)
	// A state can be retired between the lookup and its use, by a deploy or
	// a removal. Look it up again; a few tries cover any real sequence.
	for range 4 {
		s, err := r.function(name)
		switch {
		case errors.Is(err, os.ErrNotExist):
			http.Error(w, "no such function", http.StatusNotFound)
			return
		case errors.Is(err, errClosed):
			busy(w)
			return
		case err != nil:
			slog.Error("load function", "error", err)
			http.Error(w, "function is not deployable", http.StatusInternalServerError)
			return
		}
		ctx, cancel := context.WithTimeout(req.Context(), time.Duration(s.fn.TimeoutSeconds)*time.Second)
		served := r.serve(w, req.WithContext(ctx), s)
		cancel()
		if served {
			return
		}
	}
	busy(w)
}

// serve reports false when the state was retired before the request used it.
func (r *Router) serve(w http.ResponseWriter, req *http.Request, s *state) bool {
	if s.fn.Mode == ModeFresh {
		return r.serveFresh(w, req, s)
	}
	return r.serveReuse(w, req, s)
}

func (r *Router) serveReuse(w http.ResponseWriter, req *http.Request, s *state) bool {
	s.mu.Lock()
	if s.retired {
		s.mu.Unlock()
		return false
	}
	if s.current != nil {
		select {
		case <-s.current.instance.Done(): // it ended on its own; wake a new one
			s.current.instance.Stop()
			s.current = nil
		default:
		}
	}
	if s.current == nil {
		// The lock is held across the wake, so concurrent first requests share one instance.
		instance, err := r.wake(req.Context(), s.fn)
		if err != nil {
			s.mu.Unlock()
			wakeFailed(w, err)
			return true
		}
		s.current = &awake{instance: instance, proxy: proxyTo(instance, s.fn)}
	}
	current := s.current
	current.inflight++
	s.mu.Unlock()

	current.proxy.ServeHTTP(w, req)

	s.mu.Lock()
	current.inflight--
	current.lastUsed = r.now()
	s.mu.Unlock()
	return true
}

func (r *Router) serveFresh(w http.ResponseWriter, req *http.Request, s *state) bool {
	s.mu.Lock()
	if s.retired {
		s.mu.Unlock()
		return false
	}
	select {
	case s.slots <- struct{}{}:
	default:
		s.mu.Unlock()
		busy(w)
		return true
	}
	defer func() { <-s.slots }()
	s.wakes.Add(1)
	s.mu.Unlock()
	instance, err := r.wake(req.Context(), s.fn)
	if err != nil {
		s.wakes.Done()
		wakeFailed(w, err)
		return true
	}
	s.mu.Lock()
	if s.retired {
		s.mu.Unlock()
		instance.Stop()
		s.wakes.Done()
		return false
	}
	s.fresh[instance] = struct{}{}
	s.mu.Unlock()
	s.wakes.Done()
	// The instance dies with the answer: no request sees another's memory or files.
	defer func() {
		s.mu.Lock()
		delete(s.fresh, instance)
		s.mu.Unlock()
		instance.Stop()
	}()
	proxyTo(instance, s.fn).ServeHTTP(w, req)
	return true
}

func (r *Router) wake(ctx context.Context, f Function) (Instance, error) {
	start := r.now()
	instance, err := r.runtime.Wake(ctx, f)
	if err != nil {
		slog.Error("wake", "function", f.Name, "mode", f.Mode, "error", err)
		return nil, err
	}
	slog.Info("wake", "function", f.Name, "mode", f.Mode, "ms", float64(r.now().Sub(start).Microseconds())/1000)
	return instance, nil
}

// Reap stops reuse instances that had no request for idle_seconds, and
// forgets the ones that ended on their own.
func (r *Router) Reap() {
	r.mu.Lock()
	states := make([]*state, 0, len(r.functions))
	for _, s := range r.functions {
		states = append(states, s)
	}
	r.mu.Unlock()
	for _, s := range states {
		s.mu.Lock()
		current := s.current
		idle := time.Duration(s.fn.IdleSeconds) * time.Second
		stop := false
		if current != nil && current.inflight == 0 {
			select {
			case <-current.instance.Done():
				stop = true
			default:
				stop = !current.lastUsed.IsZero() && r.now().Sub(current.lastUsed) >= idle
			}
		}
		if stop {
			s.current = nil
		}
		s.mu.Unlock()
		if stop {
			current.instance.Stop()
			slog.Info("sleep", "function", s.fn.Name)
		}
	}
}

// Run reaps once a second until the context ends, then stops every instance.
func (r *Router) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.Reap()
		case <-ctx.Done():
			// Closed first: no request may wake an instance after this.
			r.mu.Lock()
			r.closed = true
			states := r.functions
			r.functions = map[string]*state{}
			r.mu.Unlock()
			for _, s := range states {
				s.retire()
			}
			return
		}
	}
}

func proxyTo(instance Instance, f Function) *httputil.ReverseProxy {
	target := &url.URL{Scheme: "http", Host: "function:" + strconv.Itoa(f.Port)}
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return instance.Dial(ctx)
			},
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     30 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			if errors.Is(err, context.DeadlineExceeded) {
				http.Error(w, "function timed out", http.StatusGatewayTimeout)
				return
			}
			slog.Warn("proxy", "function", f.Name, "error", err)
			http.Error(w, "function did not answer", http.StatusBadGateway)
		},
	}
}

func busy(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	http.Error(w, "function is at its instance limit", http.StatusServiceUnavailable)
}

func wakeFailed(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrBusy):
		busy(w)
	case errors.Is(err, context.DeadlineExceeded):
		http.Error(w, "function timed out while waking", http.StatusGatewayTimeout)
	default:
		http.Error(w, "function could not wake", http.StatusBadGateway)
	}
}
