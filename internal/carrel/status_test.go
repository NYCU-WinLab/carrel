package carrel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func statusRequest(app *App, ctx context.Context) (int, D, string) {
	r := httptest.NewRequest("GET", "https://carrel.test/status", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	var body D
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body, w.Body.String()
}

// seedFor puts a machine in tenant n (1 alice, 2 bob, 3 shared).
func seedFor(p *Platform, n int, name string, vmid int) {
	p.Store.Put("machines", vmid, n, D{"name": name, "vmid": vmid, "tenant_n": n, "kind": "vm", "image": "debian-13", "cpu": 2, "memory_mb": 2048, "disk_gb": 20, "state": "ready", "ip": "10.200.1.10", "readiness_token": "test-token", "mac": "02:ca:01:00:00:01", "allocation_id": "allocation-" + name})
}

func TestPublicStatusNamesOnlyTenantsWithAPublicDomain(t *testing.T) {
	p, b := fixture(t)
	seedFor(p, 1, "dev", 10100)
	seedFor(p, 1, "web", 10101)
	seedFor(p, 2, "secret-box", 10102)
	seedFor(p, 3, "lab-db", 10103)
	p.Store.Put("domains", "d1", 1, D{"id": "d1", "name": "app.alice.winlab.tw", "sub": "app", "state": "ready", "vmid": 10101})
	// A project with a domain that is suspended stays unnamed.
	p.Store.Put("domains", "d3", 3, D{"id": "d3", "name": "db.shared.winlab.tw", "sub": "db", "state": "ready", "vmid": 10103})
	p.Store.Exec("UPDATE tenants SET status='suspended' WHERE n=3")
	app := NewApp(p, nil)
	code, body, raw := statusRequest(app, context.Background())
	if code != 200 {
		t.Fatalf("status %d: %s", code, raw)
	}
	tenants := dicts(body["tenants"])
	if len(tenants) != 1 || tenants[0]["name"] != "alice" || num(tenants[0]["machines"]) != 2 || num(tenants[0]["vcpu"]) != 4 || num(tenants[0]["memory_gib"]) != 4 || num(tenants[0]["disk_gib"]) != 40 {
		t.Fatalf("unexpected tenants: %s", raw)
	}
	others := obj(body["others"])
	if num(others["tenants"]) != 2 || num(others["machines"]) != 2 || num(others["vcpu"]) != 4 {
		t.Fatalf("unexpected others: %s", raw)
	}
	member := obj(obj(body["quota"])["member"])
	if num(member["machines"]) != 8 || num(member["vcpu"]) != 8 || num(member["memory_gib"]) != 16 || num(member["disk_gib"]) != 100 || obj(obj(body["quota"])["project"])["vcpu"] == nil {
		t.Fatalf("unexpected quota: %s", raw)
	}
	node := obj(body["node"])
	if num(obj(node["cpu"])["logical_cpus"]) != 32 || num(obj(node["memory_gib"])["total"]) != 192 {
		t.Fatalf("unexpected node: %s", raw)
	}
	for _, secret := range []string{"bob", "shared", "dev", "web", "secret-box", "lab-db", "app.alice", "10.200.", "test-token", "02:ca", "allocation-"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("status leaks %q: %s", secret, raw)
		}
	}
	// A second load within the cache window does not ask the node again.
	calls := b.count("inventory")
	if code, _, _ := statusRequest(app, context.Background()); code != 200 || b.count("inventory") != calls {
		t.Fatal("status was not served from cache")
	}
}

func TestPublicStatusIgnoresAVisitorsCancellation(t *testing.T) {
	p, b := fixture(t)
	b.call = func(r D, _ string) (any, error) {
		if r["op"] == "inventory" {
			return baseInventory(), nil
		}
		return D{}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code, _, raw := statusRequest(NewApp(p, nil), ctx); code != 200 {
		t.Fatalf("a cancelled visitor got %d: %s", code, raw)
	}
	if err := attempt(func() { p.execution(context.Background()).Capacity(nil, true) }); err != nil {
		t.Fatalf("member capacity failed after a cancelled visitor: %v", err)
	}
}

func TestPublicStatusCachesAFailureBriefly(t *testing.T) {
	p, b := fixture(t)
	b.call = func(r D, _ string) (any, error) { return nil, errors.New("node down") }
	app := NewApp(p, nil)
	for range 3 {
		if code, _, _ := statusRequest(app, context.Background()); code != 503 {
			t.Fatalf("expected 503, got %d", code)
		}
	}
	if b.count("inventory") != 1 {
		t.Fatalf("a failing node was asked %d times", b.count("inventory"))
	}
}

func TestPublicStatusIsReadOnly(t *testing.T) {
	p, _ := fixture(t)
	r := httptest.NewRequest("POST", "https://carrel.test/status", nil)
	w := httptest.NewRecorder()
	NewApp(p, nil).ServeHTTP(w, r)
	if w.Code != 405 {
		t.Fatalf("POST /status returned %d", w.Code)
	}
}
