package carrel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const portalTestKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPortalKeyOfAlice"

// portal stands in for the portal's service route: it serves alice one key
// with a comment, and counts the reads.
func portal(t *testing.T, p *Platform, status int) *atomic.Int32 {
	t.Helper()
	reads := &atomic.Int32{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads.Add(1)
		if r.Header.Get("Authorization") != "Bearer wkk_test" || r.URL.Query().Get("format") != "text" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		if r.URL.Path == "/services/carrel/alice" {
			_, _ = w.Write([]byte(portalTestKey + " alice\ncommand=\"id\" ssh-rsa AAAA evil\n"))
		}
	}))
	t.Cleanup(s.Close)
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("wkk_test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p.Config.PortalKeysURL, p.Config.PortalKeysTokenFile = s.URL+"/services/carrel", token
	return reads
}

func TestMachineCreateUsesTheCreatorsPortalKey(t *testing.T) {
	p, _ := fixture(t)
	app := NewApp(p, nil)
	ctx := context.Background()
	reads := portal(t, p, http.StatusOK)
	alice, bob := person("alice", false), person("bob", false)

	// A plan with no key anywhere no longer asks for one.
	r := app.Call(ctx, "machine_create", D{"name": "planned", "dry_run": true}, alice)
	assertOK(t, r)
	if len(arr(r["requirements"])) != 0 {
		t.Fatalf("plan still asks for a key: %s", encoded(r))
	}
	// A member with no key on the portal is asked as before.
	r = app.Call(ctx, "machine_create", D{"name": "planned", "dry_run": true}, bob)
	assertOK(t, r)
	if !equal(r["requirements"], []any{"ssh_public_key"}) {
		t.Fatalf("bob has no portal key: %s", encoded(r))
	}

	// The machine gets the key alone: no comment, no second line with options.
	e := p.execution(ctx)
	tenant := p.Store.Tenant("user:alice")
	if m := e.MachineSpec(tenant, e.withPortalKeys("machine_create", D{"name": "box"}, alice), false); !equal(m["ssh_keys"], []any{portalTestKey}) {
		t.Fatalf("machine keys: %s", encoded(m["ssh_keys"]))
	}
	// Every machine of a deployment that names no key gets it; one that names a key keeps its own.
	d := e.withPortalKeys("deployment_apply", D{"machines": []any{D{"name": "a"}, D{"name": "b", "ssh_keys": []any{"ssh-ed25519 AAAA own"}}}}, alice)
	if ms := dicts(d["machines"]); !equal(ms[0]["portal_keys"], []any{portalTestKey}) || ms[1]["portal_keys"] != nil {
		t.Fatalf("deployment: %s", encoded(d))
	}
	// Another tool's arguments pass through untouched.
	if a := e.withPortalKeys("machine_get", D{"machine": "box"}, alice); !equal(a, D{"machine": "box"}) {
		t.Fatalf("machine_get: %s", encoded(a))
	}

	// A key in the request wins, and the portal is not asked.
	before := reads.Load()
	r = app.Call(ctx, "machine_create", D{"name": "inline", "dry_run": true, "ssh_keys": []any{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIInlineKeyInTheRequest inline"}}, alice)
	assertOK(t, r)
	if reads.Load() != before {
		t.Fatal("the portal was read for a request that carries a key")
	}
	// A caller cannot hand in portal_keys of their own.
	r = app.Call(ctx, "machine_create", D{"name": "forged", "dry_run": true, "portal_keys": []any{"ssh-ed25519 AAAA forged"}}, bob)
	if boolean(r["ok"]) && len(arr(r["requirements"])) == 0 {
		t.Fatalf("a forged portal_keys was accepted: %s", encoded(r))
	}
}

func TestSavedKeysComeBeforeThePortal(t *testing.T) {
	p, _ := fixture(t)
	app := NewApp(p, nil)
	ctx := context.Background()
	portal(t, p, http.StatusOK)
	alice := person("alice", false)
	assertOK(t, app.Call(ctx, "ssh_key_add", D{"key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAsavedKeyOfTheTenant saved"}, alice))
	e := p.execution(ctx)
	m := e.MachineSpec(p.Store.Tenant("user:alice"), e.withPortalKeys("machine_create", D{"name": "box"}, alice), false)
	if keys := string(encoded(m["ssh_keys"])); !strings.Contains(keys, "savedKeyOfTheTenant") || strings.Contains(keys, "PortalKey") {
		t.Fatalf("machine keys: %s", keys)
	}
}

func TestAPortalThatFailsAsksForAKey(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusServiceUnavailable} {
		p, _ := fixture(t)
		app := NewApp(p, nil)
		portal(t, p, status)
		r := app.Call(context.Background(), "machine_create", D{"name": "planned", "dry_run": true}, person("alice", false))
		assertOK(t, r)
		if !equal(r["requirements"], []any{"ssh_public_key"}) {
			t.Fatalf("status %d: %s", status, encoded(r))
		}
	}
	// A username that would change the path is never sent.
	p, _ := fixture(t)
	reads := portal(t, p, http.StatusOK)
	if keys := p.execution(context.Background()).portalKeys("../alice"); len(keys) != 0 || reads.Load() != 0 {
		t.Fatal("an unsafe username reached the portal")
	}
}

func TestPortalKeysStayOutOfTheFingerprint(t *testing.T) {
	a := D{"name": "box", "portal_keys": []any{"x"}, "machines": []any{D{"name": "m", "portal_keys": []any{"x"}}, "plain"}}
	got := withoutPortalKeys(a)
	if string(encoded(got)) != `{"machines":[{"name":"m"},"plain"],"name":"box"}` {
		t.Fatal(string(encoded(got)))
	}
	if a["portal_keys"] == nil {
		t.Fatal("the caller's arguments were changed")
	}
}
