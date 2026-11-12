//go:build linux

package fn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

// fakeBuild writes what a real build leaves: a version directory with its
// function.json and a file standing for the snapshot.
func fakeBuild(root string, builds *[]string, fail map[string]bool) func(context.Context, Function, string) error {
	return func(_ context.Context, f Function, image string) error {
		*builds = append(*builds, f.Name+"/"+f.Version)
		if fail[f.Name+"/"+f.Version] {
			return errors.New("pull failed")
		}
		dir := filepath.Join(root, f.Name, "v", f.Version)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := f.normalize(); err != nil {
			return err
		}
		f.Image, f.Digest = image, "sha256:"+f.Version
		content, _ := json.Marshal(f)
		if err := os.WriteFile(filepath.Join(dir, "snap.mem"), make([]byte, 8192), 0o600); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, "function.json"), content, 0o600)
	}
}

func version(v string) DesiredVersion {
	return DesiredVersion{Version: v, Image: "example/" + v, Port: 8080, MemoryMB: 256, Mode: ModeReuse}
}

func TestAgentAppliesTheDesiredState(t *testing.T) {
	root := t.TempDir()
	var builds, forgotten []string
	a := &Agent{Root: root, failed: map[string]string{},
		Build:  fakeBuild(root, &builds, map[string]bool{"t1-api/v3": true}),
		Forget: func(name string) { forgotten = append(forgotten, name) }}

	// A function the state does not name, left from earlier, goes away.
	if err := os.MkdirAll(filepath.Join(root, "t9-old", "v", "v1"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Directories that are not functions stay.
	if err := os.MkdirAll(filepath.Join(root, ".jail"), 0o700); err != nil {
		t.Fatal(err)
	}

	desired := Desired{Revision: 1, Functions: []DesiredFunction{
		{ID: "t1-api", Current: "v1", Versions: []DesiredVersion{version("v1"), version("v3")}},
		{ID: "t2-job", Versions: []DesiredVersion{version("v1")}},
		{ID: "../evil", Versions: []DesiredVersion{version("v1")}},
		{ID: "t2-bad", Versions: []DesiredVersion{version("../x")}},
	}}
	a.apply(context.Background(), desired)

	if want := []string{"t1-api/v1", "t1-api/v3", "t2-job/v1"}; !slices.Equal(builds, want) {
		t.Fatalf("builds %v, want %v", builds, want)
	}
	if got := liveVersion(root, "t1-api"); got != "v1" {
		t.Fatalf("t1-api live %q, want v1", got)
	}
	if got := liveVersion(root, "t2-job"); got != "" {
		t.Fatalf("t2-job live %q before the control plane named a current version", got)
	}
	for _, gone := range []string{"t9-old", "../evil"} {
		if _, err := os.Stat(filepath.Join(root, gone)); !os.IsNotExist(err) {
			t.Fatalf("%s still exists: %v", gone, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".jail")); err != nil {
		t.Fatal(".jail was removed")
	}
	if !slices.Contains(forgotten, "t1-api") || !slices.Contains(forgotten, "t9-old") {
		t.Fatalf("router not told: %v", forgotten)
	}

	inv := a.inventory(desired)
	byID := map[string]HeldFunction{}
	for _, f := range inv.Functions {
		byID[f.ID] = f
	}
	api := byID["t1-api"]
	if api.Current != "v1" || len(api.Versions) != 2 {
		t.Fatalf("t1-api inventory %+v", api)
	}
	if v := api.Versions[0]; v.State != "ready" || v.Digest != "sha256:v1" || v.Bytes < 8192 {
		t.Fatalf("v1 %+v", v)
	}
	if v := api.Versions[1]; v.State != "failed" || v.Error != "pull failed" {
		t.Fatalf("v3 %+v", v)
	}
	if _, ok := byID["../evil"]; ok {
		t.Fatal("an invalid id reached the inventory")
	}

	// A second pass builds nothing again: built versions stay, a failed one
	// waits until the control plane stops naming it.
	builds = nil
	a.apply(context.Background(), desired)
	if len(builds) != 0 {
		t.Fatalf("second pass built %v", builds)
	}

	// Rollback and removal: v3 is dropped, v1 stays live, t2-job goes.
	desired = Desired{Revision: 2, Functions: []DesiredFunction{
		{ID: "t1-api", Current: "v1", Versions: []DesiredVersion{version("v1")}},
	}}
	a.apply(context.Background(), desired)
	if _, err := os.Stat(filepath.Join(root, "t2-job")); !os.IsNotExist(err) {
		t.Fatal("t2-job not removed")
	}
	if len(a.failed) != 0 {
		t.Fatalf("failures kept for versions no longer named: %v", a.failed)
	}
	// A version named again after its failure is built again.
	desired.Functions[0].Versions = append(desired.Functions[0].Versions, version("v3"))
	a.apply(context.Background(), desired)
	if !slices.Equal(builds, []string{"t1-api/v3"}) {
		t.Fatalf("builds %v", builds)
	}
}

func TestAgentSwitchesTheLiveVersion(t *testing.T) {
	root := t.TempDir()
	var builds, forgotten []string
	a := &Agent{Root: root, failed: map[string]string{},
		Build:  fakeBuild(root, &builds, nil),
		Forget: func(name string) { forgotten = append(forgotten, name) }}
	desired := Desired{Functions: []DesiredFunction{
		{ID: "t1-api", Current: "v2", Versions: []DesiredVersion{version("v1"), version("v2")}},
	}}
	a.apply(context.Background(), desired)
	if liveVersion(root, "t1-api") != "v2" {
		t.Fatal("v2 not live")
	}
	desired.Functions[0].Current = "v1"
	a.apply(context.Background(), desired)
	if liveVersion(root, "t1-api") != "v1" {
		t.Fatal("rollback to v1 not live")
	}
	if len(forgotten) != 2 {
		t.Fatalf("router told %d times, want 2", len(forgotten))
	}
	// The router loads the live version.
	f, err := LoadFunction(filepath.Join(root, "t1-api"))
	if err != nil || f.Version != "v1" || f.Image != "example/v1" {
		t.Fatalf("router reads %+v, %v", f, err)
	}
	// A current version the state does not list never goes live.
	desired.Functions[0].Current = "v9"
	a.apply(context.Background(), desired)
	if liveVersion(root, "t1-api") != "v1" {
		t.Fatal("an unlisted version went live")
	}
}

func TestAgentTalksToTheControlPlane(t *testing.T) {
	root := t.TempDir()
	var mu sync.Mutex
	var reports []Inventory
	var auth []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		auth = append(auth, r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/functions/v1/agent/state":
			if r.URL.Query().Get("since") != "-1" {
				// The second request waits: the test ends here.
				mu.Unlock()
				<-r.Context().Done()
				mu.Lock()
				return
			}
			_ = json.NewEncoder(w).Encode(Desired{Revision: 7, Functions: []DesiredFunction{
				{ID: "t1-api", Current: "v1", Versions: []DesiredVersion{version("v1")}},
			}})
		case "/functions/v1/agent/report":
			var inv Inventory
			if err := json.NewDecoder(r.Body).Decode(&inv); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			reports = append(reports, inv)
			_, _ = w.Write([]byte("{}"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	var builds []string
	a := &Agent{Control: server.URL, Token: "cfh_test", Root: root,
		Build: fakeBuild(root, &builds, nil), Forget: func(string) {}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		a.Run(ctx)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(reports)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 1 || reports[0].Revision != 7 || len(reports[0].Functions) != 1 ||
		reports[0].Functions[0].Current != "v1" || reports[0].Functions[0].Versions[0].State != "ready" {
		t.Fatalf("reports %+v", reports)
	}
	for _, h := range auth {
		if h != "Bearer cfh_test" {
			t.Fatalf("request sent %q", h)
		}
	}
}
