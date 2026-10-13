package carrel

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicStatusListsTenantSharesWithoutMachineDetails(t *testing.T) {
	p, b := fixture(t)
	seedMachine(p, "dev", 10100)
	seedMachine(p, "db", 10101)
	app := NewApp(p, nil)
	get := func() (int, D, string) {
		r := httptest.NewRequest("GET", "https://carrel.test/status", nil)
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		var body D
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return w.Code, body, w.Body.String()
	}
	code, body, raw := get()
	if code != 200 {
		t.Fatalf("status %d: %s", code, raw)
	}
	tenants := dicts(body["tenants"])
	if len(tenants) != 1 || tenants[0]["name"] != "alice" || num(tenants[0]["machines"]) != 2 || num(tenants[0]["vcpu"]) != 4 || num(tenants[0]["memory_gib"]) != 4 || num(tenants[0]["disk_gib"]) != 40 {
		t.Fatalf("unexpected tenants: %s", raw)
	}
	node := obj(body["node"])
	if num(obj(node["cpu"])["logical_cpus"]) != 32 || num(obj(node["memory_gib"])["total"]) != 192 {
		t.Fatalf("unexpected node: %s", raw)
	}
	for _, secret := range []string{"dev", "10.200.", "readiness_token", "test-token", "02:ca", "allocation-"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("status leaks %q: %s", secret, raw)
		}
	}
	// A second load within the cache window does not ask the node again.
	calls := b.count("inventory")
	if code, _, _ := get(); code != 200 || b.count("inventory") != calls {
		t.Fatal("status was not served from cache")
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
