package carrel

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

func groupMember(name string) D {
	return D{"sub": name, "username": name, "admin": false, "projects": []any{"winlab-projects/shared"}}
}

func TestGuestKeysServeEveryGroupMembersSavedKey(t *testing.T) {
	p, _ := fixture(t)
	ctx := context.Background()
	app := NewApp(p, nil)
	n := integer(p.Store.Tenant("winlab-projects/shared")["n"])
	m := seedMachine(p, "group-box", 10300)
	m["tenant_n"], m["ip"] = n, "10.200.3.10"
	p.Store.Put("machines", 10300, n, m)
	aliceKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAliceAliceAliceAliceAliceAliceAliceAlic laptop"
	bobKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBobBobBobBobBobBobBobBobBobBobBobBobBobB"
	for who, key := range map[string]string{"alice": aliceKey, "bob": bobKey} {
		if r := app.Call(ctx, "ssh_key_add", D{"tenant": "shared", "key": key}, groupMember(who)); !boolean(r["ok"]) {
			t.Fatalf("%s could not save a key: %v", who, r)
		}
	}
	e := p.execution(ctx)
	body := D{"vmid": 10300, "token": "test-token"}
	keys := e.GuestKeys(body, "10.200.3.10")
	lines := strings.Split(strings.TrimSpace(keys), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 keys, got %q", keys)
	}
	for _, want := range []string{strings.TrimSuffix(aliceKey, " laptop") + " carrel:alice", bobKey + " carrel:bob"} {
		if !strings.Contains(keys, want+"\n") {
			t.Fatalf("missing %q in %q", want, keys)
		}
	}
	for _, tc := range []struct{ source, token string }{{"10.200.1.10", "test-token"}, {"10.200.3.10", "wrong"}, {"10.200.3.10", ""}} {
		if attempt(func() { e.GuestKeys(D{"vmid": 10300, "token": tc.token}, tc.source) }) == nil {
			t.Fatalf("served keys to a forged call from %s", tc.source)
		}
	}
}

func TestGuestKeysDropOptionsAndUnsafeComments(t *testing.T) {
	p, _ := fixture(t)
	m := seedMachine(p, "box", 10100)
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAliceAliceAliceAliceAliceAliceAliceAlic"
	p.Store.Put("keys", "1-a", 1, D{"id": "a", "key": key, "by": "evil\ncommand=\"sh\""})
	p.Store.Put("keys", "1-b", 1, D{"id": "b", "key": `command="sh" ` + key})
	keys := p.execution(context.Background()).GuestKeys(D{"vmid": 10100, "token": "test-token"}, str(m["ip"]))
	if keys != key+" carrel:a\n" {
		t.Fatalf("unsafe key lines: %q", keys)
	}
}

func TestGuestKeysStopForAnInactiveTenant(t *testing.T) {
	p, _ := fixture(t)
	m := seedMachine(p, "box", 10100)
	p.Store.Exec("UPDATE tenants SET status='suspended' WHERE n=1")
	if attempt(func() {
		p.execution(context.Background()).GuestKeys(D{"vmid": 10100, "token": "test-token"}, str(m["ip"]))
	}) == nil {
		t.Fatal("a suspended tenant's machine still gets keys")
	}
}

func TestKeysInstallScriptIsOnAGatewayRoutedPath(t *testing.T) {
	p, _ := fixture(t)
	a := NewApp(p, nil)
	code, out := do(t, a, "GET", "/apps/v1/keys/install.sh", "", nil)
	if code != 200 || !strings.Contains(str(out["body"]), "https://carrel.test/apps/v1/keys/install.sh") {
		t.Fatalf("install script: %d %v", code, out)
	}
	routed := false
	for _, c := range controlPaths {
		routed = routed || (strings.HasSuffix(c, "/*") && strings.HasPrefix("/apps/v1/keys/install.sh", strings.TrimSuffix(c, "*")))
	}
	if !routed {
		t.Fatal("the gateway does not send the install script path to control")
	}
}

func TestGuestKeysHTTPRefusesAForgedGuest(t *testing.T) {
	p, _ := fixture(t)
	m := seedMachine(p, "box", 10100)
	a := NewApp(p, nil)
	for token, want := range map[string]int{"wrong": 403, "test-token": 200} {
		req := httptest.NewRequest("POST", "http://10.200.0.3:8080/internal/guest-keys", strings.NewReader(`{"vmid":10100,"token":"`+token+`"}`))
		req.RemoteAddr = str(m["ip"]) + ":40000"
		w := httptest.NewRecorder()
		a.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("token %q: status %d, want %d", token, w.Code, want)
		}
	}
}
