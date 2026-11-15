package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCarrel answers the agent's pull-mode requests and records what it
// receives.
type fakeCarrel struct {
	mu       sync.Mutex
	src      source
	status   int // the upload's answer
	uploads  []string
	files    [][]string
	failures []string
	key      string
	polls    int
}

func (f *fakeCarrel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/apps/v1/agent/next":
		// Every other poll says the webhook was called.
		f.polls++
		if f.polls%2 == 1 {
			w.Write([]byte(`{"pull":true}`))
			return
		}
		w.WriteHeader(204)
	case "/apps/v1/agent/source":
		json.NewEncoder(w).Encode(f.src)
	case "/apps/v1/agent/report":
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["deploy_key"] != "" {
			f.key = body["deploy_key"]
		}
		if body["state"] == "failed" {
			f.failures = append(f.failures, body["sha"]+" "+body["log"])
		}
		w.Write([]byte(`{"ok":true}`))
	case "/apps/v1/agent/upload":
		names := []string{}
		gz, err := gzip.NewReader(r.Body)
		if err == nil {
			tr := tar.NewReader(gz)
			for h, err := tr.Next(); err == nil; h, err = tr.Next() {
				names = append(names, h.Name)
			}
		}
		io.Copy(io.Discard, r.Body)
		if f.status != 200 {
			w.WriteHeader(f.status)
			w.Write([]byte(`{"error":{"message":"busy"}}`))
			return
		}
		f.uploads = append(f.uploads, r.Header.Get("X-Carrel-Sha"))
		f.files = append(f.files, names)
		w.Write([]byte(`{"release":{}}`))
	default:
		http.NotFound(w, r)
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main"}, args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestPullBuildsEachCommitOnceAndRetriesWhatCarrelDidNotTake(t *testing.T) {
	for _, tool := range []string{"git", "ssh-keygen", "tar"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	os.MkdirAll(repo, 0755)
	git(t, repo, "init", "-q")
	os.WriteFile(filepath.Join(repo, "run"), []byte("#!/bin/sh\n"), 0755)
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "one")
	first := git(t, repo, "rev-parse", "HEAD")

	carrel := &fakeCarrel{src: source{Mode: "pull", URL: repo, Branch: "main", Build: "echo built > built.txt"}, status: 200}
	server := httptest.NewServer(carrel)
	defer server.Close()
	a := &agent{cfg: config{Origin: server.URL, Token: "cdt_test", App: "site", Port: 8000}, root: filepath.Join(dir, "app"), state: filepath.Join(dir, "state"), http: server.Client(), every: time.Minute, wake: make(chan bool, 1)}
	a.command = func(ctx context.Context, script string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", script)
	}
	ctx := context.Background()

	// A new commit is built once, packed without .git, and uploaded.
	a.check(ctx, false)
	a.check(ctx, false)
	if len(carrel.uploads) != 1 || carrel.uploads[0] != first {
		t.Fatalf("uploads: %v", carrel.uploads)
	}
	files := strings.Join(carrel.files[0], " ")
	if !strings.Contains(files, "./built.txt") || !strings.Contains(files, "./run") || strings.Contains(files, ".git/") {
		t.Fatalf("packed: %s", files)
	}
	if !strings.HasPrefix(carrel.key, "ssh-ed25519 ") || !strings.HasSuffix(carrel.key, " carrel-site") {
		t.Fatalf("deploy key: %q", carrel.key)
	}

	// A failed build is reported once; the webhook builds it again.
	carrel.src.Build = "echo broken >&2; exit 2"
	os.WriteFile(filepath.Join(repo, "two"), []byte("2"), 0644)
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "two")
	second := git(t, repo, "rev-parse", "HEAD")
	a.check(ctx, false)
	a.check(ctx, false)
	if len(carrel.failures) != 1 || !strings.HasPrefix(carrel.failures[0], second+" ") || !strings.Contains(carrel.failures[0], "broken") {
		t.Fatalf("failures: %v", carrel.failures)
	}
	carrel.src.Build = ""
	a.check(ctx, true)
	if len(carrel.uploads) != 2 || carrel.uploads[1] != second {
		t.Fatalf("webhook did not rebuild the failed head: %v", carrel.uploads)
	}
	// The webhook does not rebuild a head that built.
	a.check(ctx, true)
	if len(carrel.uploads) != 2 {
		t.Fatalf("webhook rebuilt a good head: %v", carrel.uploads)
	}

	// carrel busy: nothing is marked built, and the next check waits.
	carrel.status = 503
	os.WriteFile(filepath.Join(repo, "three"), []byte("3"), 0644)
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "three")
	third := git(t, repo, "rev-parse", "HEAD")
	a.check(ctx, false)
	if a.retryAt.IsZero() || a.backoff != time.Minute {
		t.Fatalf("no backoff: %v %v", a.retryAt, a.backoff)
	}
	carrel.status = 200
	a.check(ctx, false)
	if len(carrel.uploads) != 2 {
		t.Fatalf("built again before the backoff ended: %v", carrel.uploads)
	}
	a.retryAt = time.Now().Add(-time.Second)
	a.check(ctx, false)
	if len(carrel.uploads) != 3 || carrel.uploads[2] != third || !a.retryAt.IsZero() {
		t.Fatalf("retry: %v", carrel.uploads)
	}
}

// The poll loop and the builder run at once; go test -race checks that they
// share nothing but the wake channel.
func TestLoopAndBuilderRunTogether(t *testing.T) {
	for _, tool := range []string{"git", "ssh-keygen", "tar"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	os.MkdirAll(repo, 0755)
	git(t, repo, "init", "-q")
	os.WriteFile(filepath.Join(repo, "run"), []byte("#!/bin/sh\n"), 0755)
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "one")

	// A slow build, so polls and webhook wakes arrive while it runs.
	carrel := &fakeCarrel{src: source{Mode: "pull", URL: repo, Branch: "main", Build: "sleep 0.3; echo built > built.txt"}, status: 200}
	server := httptest.NewServer(carrel)
	defer server.Close()
	a := &agent{cfg: config{Origin: server.URL, Token: "cdt_test", App: "site", Port: 8000}, root: filepath.Join(dir, "app"), state: filepath.Join(dir, "state"), http: server.Client(), every: 50 * time.Millisecond, wake: make(chan bool, 1)}
	a.command = func(ctx context.Context, script string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", script)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.loop(ctx); close(done) }()

	// A new commit while the loop runs is built too.
	deadline := time.Now().Add(20 * time.Second)
	waitFor := func(n int) {
		for {
			carrel.mu.Lock()
			got := len(carrel.uploads)
			carrel.mu.Unlock()
			if got >= n {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d uploads, want %d", got, n)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitFor(1)
	os.WriteFile(filepath.Join(repo, "two"), []byte("2"), 0644)
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "two")
	second := git(t, repo, "rev-parse", "HEAD")
	waitFor(2)

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("loop did not stop")
	}
	carrel.mu.Lock()
	defer carrel.mu.Unlock()
	// Each commit once, however many wakes came in between.
	if len(carrel.uploads) != 2 || carrel.uploads[1] != second || carrel.polls < 2 {
		t.Fatalf("uploads %v after %d polls", carrel.uploads, carrel.polls)
	}
}
