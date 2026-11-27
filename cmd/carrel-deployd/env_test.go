package main

import (
	"context"
	"crypto/hpke"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func envAgent(t *testing.T) *agent {
	t.Helper()
	dir := t.TempDir()
	a := &agent{cfg: config{App: "web"}, root: filepath.Join(dir, "srv"), state: filepath.Join(dir, "state"), units: filepath.Join(dir, "units")}
	a.reload = func(context.Context) error { return nil }
	a.restart = func(context.Context) error { return nil }
	if err := a.loadEnvKey(); err != nil {
		t.Fatal(err)
	}
	return a
}

func sealFor(t *testing.T, a *agent, app, set string, version int, pairs ...string) string {
	t.Helper()
	plain, _ := json.Marshal(pairs)
	box, err := hpke.Seal(a.envKey.PublicKey(), envKDF, envAEAD, envInfo(app, set, version), plain)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(box)
}

func update(sets ...[3]any) envUpdate {
	var u envUpdate
	u.Revision = "r1"
	for _, s := range sets {
		u.Sets = append(u.Sets, struct {
			Set     string `json:"set"`
			Version int    `json:"version"`
			Box     string `json:"box"`
		}{s[0].(string), s[1].(int), s[2].(string)})
	}
	return u
}

func TestTheKeyIsMadeOnceAndKeptPrivate(t *testing.T) {
	a := envAgent(t)
	info, err := os.Stat(a.envKeyFile())
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file %v %v", info, err)
	}
	public := a.envKey.PublicKey().Bytes()
	if err := a.loadEnvKey(); err != nil || string(a.envKey.PublicKey().Bytes()) != string(public) {
		t.Fatal("a second start made another key")
	}
}

func TestSetsAreOpenedIntoARootOnlyFile(t *testing.T) {
	a := envAgent(t)
	u := update(
		[3]any{"base", 3, sealFor(t, a, "web", "base", 3, "A=1", `QUOTE=say "hi" \ bye`)},
		[3]any{"prod", 1, sealFor(t, a, "web", "prod", 1, "A=2", "B=two words")},
	)
	if err := a.writeEnv(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(a.envFile())
	want := "A=\"2\"\nQUOTE=\"say \\\"hi\\\" \\\\ bye\"\nB=\"two words\"\n"
	if !strings.HasSuffix(string(b), want) {
		t.Fatalf("file:\n%s", b)
	}
	if info, _ := os.Stat(a.envFile()); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode())
	}
	drop, _ := os.ReadFile(a.dropIn())
	if string(drop) != "[Service]\nEnvironmentFile=-"+a.envFile()+"\n" {
		t.Fatalf("drop-in %q", drop)
	}
}

func TestACopyForAnotherAppOrVersionDoesNotOpen(t *testing.T) {
	a := envAgent(t)
	for _, u := range []envUpdate{
		update([3]any{"base", 1, sealFor(t, a, "other", "base", 1, "A=1")}),
		update([3]any{"base", 2, sealFor(t, a, "web", "base", 1, "A=1")}),
		update([3]any{"prod", 1, sealFor(t, a, "web", "base", 1, "A=1")}),
		update([3]any{"base", 1, sealFor(t, a, "web", "base", 1, "BAD KEY=1")}),
	} {
		if _, err := a.openEnv(u); err == nil {
			t.Fatalf("opened %+v", u.Sets[0])
		}
	}
}

func TestAFailedRestartPutsTheOldEnvironmentBack(t *testing.T) {
	a := envAgent(t)
	if err := os.MkdirAll(a.root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := a.writeEnv(context.Background(), update([3]any{"base", 1, sealFor(t, a, "web", "base", 1, "A=1")})); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("releases/r1", filepath.Join(a.root, "current")); err != nil {
		t.Fatal(err)
	}
	restarts := 0
	a.restart = func(context.Context) error {
		restarts++
		if restarts == 1 {
			return errors.New("health check failed")
		}
		return nil
	}
	err := a.writeEnv(context.Background(), update([3]any{"base", 2, sealFor(t, a, "web", "base", 2, "A=broken")}))
	if err == nil || !strings.Contains(err.Error(), "previous environment is back") || restarts != 2 {
		t.Fatalf("%v after %d restarts", err, restarts)
	}
	if b, _ := os.ReadFile(a.envFile()); !strings.Contains(string(b), `A="1"`) {
		t.Fatalf("file:\n%s", b)
	}
}

func TestTheKeyIsRegisteredAndAnUpdateIsReported(t *testing.T) {
	a := envAgent(t)
	var key, report map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch r.URL.Path {
		case "/apps/v1/agent/key":
			key = body
			_, _ = w.Write([]byte(`{"state":"trusted"}`))
		case "/apps/v1/agent/env":
			report = body
			_, _ = w.Write([]byte(`{}`))
		case "/apps/v1/agent/next":
			_, _ = w.Write([]byte(`{"env":{"revision":"r9","sets":[]}}`))
		}
	}))
	defer srv.Close()
	a.cfg.Origin, a.cfg.Token, a.http = srv.URL, "t", srv.Client()
	a.registerEnvKey(context.Background())
	if !a.envRegistered || key["public"] != base64.StdEncoding.EncodeToString(a.envKey.PublicKey().Bytes()) || int(key["kem"].(float64)) != int(envKEM.ID()) {
		t.Fatalf("registered %v %v", a.envRegistered, key)
	}
	_, _, _, env, _, err := a.next(context.Background())
	if err != nil || env == nil || env.Revision != "r9" {
		t.Fatalf("next %+v %v", env, err)
	}
	a.applyEnv(context.Background(), *env)
	if report["revision"] != "r9" || report["error"] != "" {
		t.Fatalf("report %v", report)
	}
	// The same revision again, as when a report was lost: reported, not restarted.
	if err := os.MkdirAll(a.root, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink("releases/r1", filepath.Join(a.root, "current"))
	restarts := 0
	a.restart = func(context.Context) error { restarts++; return nil }
	report = nil
	a.applyEnv(context.Background(), *env)
	if restarts != 0 || report["revision"] != "r9" {
		t.Fatalf("%d restarts, report %v", restarts, report)
	}
}

func TestAFailedFirstEnvironmentIsRemoved(t *testing.T) {
	a := envAgent(t)
	if err := os.MkdirAll(a.root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("releases/r1", filepath.Join(a.root, "current")); err != nil {
		t.Fatal(err)
	}
	restarts := 0
	a.restart = func(context.Context) error {
		restarts++
		if restarts == 1 {
			return errors.New("health check failed")
		}
		return nil
	}
	err := a.writeEnv(context.Background(), update([3]any{"base", 1, sealFor(t, a, "web", "base", 1, "A=broken")}))
	if err == nil || restarts != 2 {
		t.Fatalf("%v after %d restarts", err, restarts)
	}
	if _, err := os.Stat(a.envFile()); !os.IsNotExist(err) {
		t.Fatal("the failed environment stayed")
	}
	// An empty update with nothing held changes nothing and restarts nothing.
	if err := a.writeEnv(context.Background(), envUpdate{Revision: "none"}); err != nil || restarts != 2 {
		t.Fatalf("%v after %d restarts", err, restarts)
	}
}

func TestARevokedSetNeverComesBack(t *testing.T) {
	a := envAgent(t)
	if err := os.MkdirAll(a.root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := a.writeEnv(context.Background(), update([3]any{"base", 1, sealFor(t, a, "web", "base", 1, "SECRET=1")})); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("releases/r1", filepath.Join(a.root, "current")); err != nil {
		t.Fatal(err)
	}
	a.restart = func(context.Context) error { return errors.New("health check failed") }
	err := a.writeEnv(context.Background(), envUpdate{Revision: "none"})
	if err == nil || !strings.Contains(err.Error(), "stay removed") {
		t.Fatalf("%v", err)
	}
	if b, _ := os.ReadFile(a.envFile()); strings.Contains(string(b), "SECRET") {
		t.Fatalf("revoked value back:\n%s", b)
	}
}
