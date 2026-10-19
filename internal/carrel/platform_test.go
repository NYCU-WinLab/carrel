package carrel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeBackend struct {
	mu        sync.Mutex
	calls     []D
	inventory D
	call      func(D, string) (any, error)
}

func (b *fakeBackend) Call(ctx context.Context, r D, target string) (any, error) {
	b.mu.Lock()
	b.calls = append(b.calls, clone(r))
	fn := b.call
	inventory := clone(b.inventory)
	b.mu.Unlock()
	if fn != nil {
		return fn(r, target)
	}
	if r["op"] == "inventory" {
		return inventory, nil
	}
	if r["op"] == "storage_usage" {
		return []D{}, nil
	}
	return D{"status": "running"}, nil
}
func (b *fakeBackend) count(op string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, r := range b.calls {
		if r["op"] == op {
			n++
		}
	}
	return n
}
func baseInventory() D {
	return D{"status": D{"cpuinfo": D{"cpus": 32, "cores": 16, "sockets": 2}, "memory": D{"total": 192 * GiB, "used": 20 * GiB}}, "storage": D{"total": 1500 * GiB, "used": 10 * GiB}, "resources": []D{}, "disk_committed_bytes": 20 * GiB, "thin_pool": D{"metadata_fraction": 0.01}}
}
func person(name string, admin bool) D {
	return D{"sub": name, "username": name, "admin": admin, "projects": []string{}}
}
func fixture(t *testing.T) (*Platform, *fakeBackend) {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	s.Register("user:alice", "alice")
	s.Register("user:bob", "bob")
	s.Register("winlab-projects/shared", "shared")
	b := &fakeBackend{inventory: baseInventory()}
	p := NewPlatform(s, b, D{"origin": "https://carrel.test", "issuer": "https://issuer.test", "guest_poll_interval": 1, "guest_ready_timeout": 3})
	p.sshProbe = func(context.Context, D) bool { return false }
	t.Cleanup(func() { p.Close(); s.DB.Close() })
	return p, b
}
func assertOK(t *testing.T, r D) {
	t.Helper()
	if !boolean(r["ok"]) {
		t.Fatalf("unexpected failure: %s", encoded(r))
	}
}
func assertCode(t *testing.T, r D, code string) {
	t.Helper()
	if obj(r["error"])["code"] != code {
		t.Fatalf("expected %s: %s", code, encoded(r))
	}
}
func TestSchemaAndTenantBoundaries(t *testing.T) {
	p, _ := fixture(t)
	app := NewApp(p, nil)
	ctx := context.Background()
	who := person("alice", false)
	for _, tc := range []struct {
		name string
		args D
		code string
	}{{"quota_get", D{"tenant": "bob"}, "forbidden"}, {"quota_get", D{"tenant": "shared"}, "forbidden"}, {"quota_set", D{"tenant": "alice", "dimension": "vcpu", "amount": 100}, "forbidden"}, {"machine_create", D{"name": "test", "cpu": -1}, "invalid"}, {"machine_create", D{"name": "test", "extra": true}, "invalid"}, {"machine_create", D{"name": "test", "kind": "ct", "packages": []any{"git"}, "dry_run": true}, "invalid"}, {"machine_get", D{"machine": "missing"}, "not_found"}} {
		t.Run(tc.name+tc.code, func(t *testing.T) { assertCode(t, app.Call(ctx, tc.name, tc.args, who), tc.code) })
	}
	r := app.Call(ctx, "machine_create", D{"name": "planned", "dry_run": true}, who)
	assertOK(t, r)
	if !equal(r["requirements"], []any{"ssh_public_key"}) || boolean(r["resource_changes"]) {
		t.Fatal(r)
	}
	if len(p.Store.Objects("machines")) != 0 {
		t.Fatal("preview wrote a machine")
	}
}
func TestCapacityCacheNeverAdmitsFromStaleData(t *testing.T) {
	p, b := fixture(t)
	e := p.execution(context.Background())
	e.Capacity(nil, true)
	e.Capacity(nil, true)
	if b.count("inventory") != 1 {
		t.Fatal("observation not cached")
	}
	b.mu.Lock()
	obj(b.inventory["storage"])["used"] = 1490 * GiB
	b.mu.Unlock()
	err := attempt(func() { e.Admission(p.Nodes()[0], 1, 1024, 20, nil, false) })
	if err == nil || obj(failureResult(err)["error"])["code"] != "capacity_exhausted" {
		t.Fatalf("stale admission: %v", err)
	}
	if b.count("inventory") != 2 {
		t.Fatal("admission skipped fresh read")
	}
}
func TestCacheCoalescingAndInvalidation(t *testing.T) {
	var cache ObservationCache
	start, release := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	reads := 0
	fetch := func(ctx context.Context) (any, error) {
		mu.Lock()
		reads++
		if reads == 1 {
			close(start)
		}
		mu.Unlock()
		<-release
		return D{"value": 1}, nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, _, err := cache.Get(context.Background(), time.Second, fetch)
			if err != nil {
				t.Error(err)
			}
			obj(v)["value"] = 99
		}()
	}
	<-start
	time.Sleep(20 * time.Millisecond)
	cache.Invalidate()
	close(release)
	wg.Wait()
	mu.Lock()
	count := reads
	mu.Unlock()
	if count != 1 {
		t.Fatalf("expected one in-flight read: %d", count)
	}
	v, _, err := cache.Get(context.Background(), time.Second, func(context.Context) (any, error) { return D{"value": 2}, nil })
	if err != nil || num(obj(v)["value"]) != 2 {
		t.Fatal("in-flight read restored invalidated cache")
	}
}
func TestCapacityAccountsStoppedUnmanagedAndAllVolumes(t *testing.T) {
	inventory := baseInventory()
	inventory["disk_committed_bytes"] = 125 * GiB
	inventory["resources"] = []D{{"type": "qemu", "vmid": 1, "status": "running", "maxcpu": 4, "maxmem": 4 * GiB, "maxdisk": 20 * GiB}, {"type": "qemu", "vmid": 10100, "status": "stopped", "maxcpu": 2, "maxmem": 2 * GiB, "maxdisk": 20 * GiB}}
	c := summarize(inventory, []D{{"vmid": 10100, "cpu": 2, "memory_mb": 2048, "disk_gb": 20}, {"vmid": 10101, "cpu": 2, "memory_mb": 2048, "disk_gb": 20}}, []D{{"disk_gb": 20}}, time.Now())
	a := obj(c["allocatable"])
	if num(obj(a["vcpu"])["committed"]) != 8 || num(obj(a["disk_gib"])["committed"]) != 165 {
		t.Fatal(c)
	}
}
func TestNetworkOnlyPlanSkipsInventory(t *testing.T) {
	p, b := fixture(t)
	r := p.Execute(context.Background(), "deployment_plan", D{"networks": []D{{"name": "private"}}}, person("alice", false))
	assertOK(t, r)
	if b.count("inventory") != 0 {
		t.Fatal("network plan read compute inventory")
	}
	for _, cidr := range []string{"10.200.1.0/24", "8.8.8.0/24", "10.1.1.5/24"} {
		r = p.Execute(context.Background(), "network_create", D{"name": "bad", "cidr": cidr, "dry_run": true}, person("alice", false))
		assertCode(t, r, "invalid")
	}
}
func seedMachine(p *Platform, name string, vmid int) D {
	m := D{"name": name, "vmid": vmid, "tenant_n": 1, "allocation_id": "allocation-" + name, "operation_id": "original-" + name, "created_at": 1, "kind": "vm", "image": "debian-13", "cpu": 2, "memory_mb": 2048, "disk_gb": 20, "state": "ready", "ip": "10.200.1.10", "host": 10, "mac": "02:ca:01:00:00:01", "nics": []D{}, "readiness_token": "test-token", "guest_management": 1, "network_access": "tenant"}
	p.Store.Put("machines", vmid, 1, m)
	return m
}
func TestReconcileOmitsStorageAccounting(t *testing.T) {
	p, b := fixture(t)
	p.execution(context.Background()).Reconcile()
	if b.count("reconcile") != 2 || b.count("storage_usage") != 0 {
		t.Fatal("accounting remains on the mutation path")
	}
}
func TestQueueCanProvisionAnotherMachineWhileFirstBoots(t *testing.T) {
	p, b := fixture(t)
	p.wg.Add(1)
	go p.Operations.Loop()
	created := make(chan string, 2)
	b.call = func(r D, _ string) (any, error) {
		if r["op"] == "inventory" {
			return baseInventory(), nil
		}
		if r["op"] == "create" {
			created <- str(obj(r["machine"])["name"])
		}
		return D{}, nil
	}
	who := person("alice", false)
	ctx, cancel := context.WithCancel(context.Background())
	args := D{"name": "one", "ssh_keys": []any{"ssh-ed25519 AAAA test"}, "wait_seconds": 0}
	a := p.Execute(ctx, "machine_create", args, who)
	assertOK(t, a)
	cancel()
	select {
	case <-created:
	case <-time.After(time.Second):
		t.Fatal("first create not applied")
	}
	bresult := p.Execute(context.Background(), "machine_create", merge(args, D{"name": "two"}), who)
	assertOK(t, bresult)
	select {
	case name := <-created:
		if name != "two" {
			t.Fatal(name)
		}
	case <-time.After(time.Second):
		t.Fatal("second create blocked by first guest readiness")
	}
	if b.count("storage_usage") != 0 {
		t.Fatal("create performed accounting")
	}
	// The adapter returns before the writer commits its initializing checkpoint.
	p.writer.Lock()
	defer p.writer.Unlock()
	for _, m := range p.Store.Objects("machines", 1) {
		if m["state"] != "initializing" {
			t.Fatal("expected durable initializing state")
		}
	}
}
func TestOwnershipBoundRetryAndDuplicateSubmission(t *testing.T) {
	p, _ := fixture(t)
	m := seedMachine(p, "original", 10100)
	e := p.execution(context.Background())
	tnt := p.Store.TenantN(1)
	op := D{"id": "job", "tenant_n": 1, "tool": "machine_delete", "generation": 0, "args": D{"machine": "original", "confirm": "original"}, "who": person("alice", false), "state": "failed"}
	e.Op = op
	e.BindMachine(tnt)
	replacement := merge(m, D{"allocation_id": "different", "name": "replacement"})
	p.Store.Put("machines", 10100, 1, replacement)
	err := attempt(func() { e.BindMachine(tnt) })
	if err == nil {
		t.Fatal("retry accepted replacement")
	}
	args := D{"name": "x", "idempotency_key": "stable", "wait_seconds": 0, "ssh_keys": []any{"ssh-ed25519 AAAA test"}}
	a := p.Execute(context.Background(), "machine_create", args, person("alice", false))
	b := p.Execute(context.Background(), "machine_create", args, person("alice", false))
	assertOK(t, a)
	assertOK(t, b)
	if obj(a["operation"])["id"] != obj(b["operation"])["id"] {
		t.Fatal("duplicate allocation")
	}
	c := p.Execute(context.Background(), "machine_create", merge(args, D{"name": "y"}), person("alice", false))
	assertCode(t, c, "conflict")
}
func TestTransactionRollbackAndPersistentOAuth(t *testing.T) {
	p, _ := fixture(t)
	s := p.Store
	_ = attempt(func() {
		s.Transaction(func(tx *Store) { tx.Put("networks", "bad", 1, D{"id": "bad"}); panic(errors.New("abort")) })
	})
	if s.Get("networks", "bad") != nil {
		t.Fatal("rollback failed")
	}
	s.OAuthPut("client", "desktop", D{"client_id": "desktop"}, 0)
	s.OAuthPut("refresh", digest("secret"), D{"client": "desktop", "offline": true}, 0)
	s.PurgeOAuth()
	if s.OAuthGet("refresh", digest("secret")) == nil {
		t.Fatal("offline session expired")
	}
	for _, row := range s.Rows("SELECT data FROM oauth") {
		if strings.Contains(str(row["data"]), "secret") {
			t.Fatal("raw token persisted")
		}
	}
}
func TestGuestReportRequiresMatchingSourceAndToken(t *testing.T) {
	p, _ := fixture(t)
	m := seedMachine(p, "test", 10100)
	e := p.execution(context.Background())
	body := D{"vmid": 10100, "token": "test-token", "boot_id": "00000000-0000-0000-0000-000000000001", "initialization_status": "complete", "application_status": "not_checked", "checks": []any{}, "interfaces": []any{}}
	for _, tc := range []struct{ source, token string }{{"10.200.2.10", "test-token"}, {"10.200.1.10", "wrong"}} {
		if attempt(func() { e.GuestReport(merge(body, D{"token": tc.token}), tc.source) }) == nil {
			t.Fatal("accepted forged report")
		}
	}
	e.GuestReport(body, str(m["ip"]))
	if p.Store.Get("guest_reports", "10100") == nil {
		t.Fatal("report missing")
	}
}

type testVerifier struct {
	who D
	err error
}

func (v testVerifier) Verify(context.Context, string) (D, error) { return v.who, v.err }
func requestApp(app http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://carrel.test"+path, strings.NewReader(body))
	r.RemoteAddr = "10.200.0.2:12345"
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	return w
}
func TestMCPHTTPDiscoveryAndTools(t *testing.T) {
	p, _ := fixture(t)
	app := NewApp(p, testVerifier{who: person("alice", false)})
	headers := map[string]string{"Authorization": "Bearer test", "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
	for _, method := range []string{"initialize", "tools/list", "resources/list", "resources/templates/list", "tools/call"} {
		params := D{}
		if method == "initialize" {
			params = D{"protocolVersion": "2025-06-18", "capabilities": D{}, "clientInfo": D{"name": "test", "version": "1"}}
		}
		if method == "tools/call" {
			params = D{"name": "whoami", "arguments": D{}}
		}
		w := requestApp(app, "POST", "/mcp", string(encoded(D{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})), headers)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", method, w.Code, w.Body.String())
		}
		var result D
		must(json.Unmarshal(w.Body.Bytes(), &result))
		if result["error"] != nil {
			t.Fatalf("%s: %s", method, w.Body)
		}
		if method == "tools/list" {
			for _, tool := range dicts(obj(result["result"])["tools"]) {
				if named("admin_tools", str(tool["name"])) {
					t.Fatal("admin tool exposed")
				}
			}
		}
	}
	w := requestApp(app, "POST", "/mcp", "{}", nil)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	w = requestApp(app, "GET", "/healthz", "", map[string]string{"Origin": "https://evil.test"})
	if w.Code != 403 {
		t.Fatal("origin accepted")
	}
}

func TestReadinessProbeUpdatesOnlyOriginalAllocation(t *testing.T) {
	p, _ := fixture(t)
	m := seedMachine(p, "probe", 10100)
	m["ip"] = "127.0.0.1"
	m["allocation_id"] = "replaced"
	p.Store.Put("machines", 10100, 1, m)
	original := merge(m, D{"allocation_id": "original"})
	errValue := attempt(func() { p.execution(context.Background()).WaitReady(original, "") })
	if errValue == nil {
		t.Fatal("accepted replaced allocation")
	}
}
func TestPythonCompatibleRequestHash(t *testing.T) {
	v := []any{"operation", 0, "carrel-node", D{"op": "action", "action": "resize", "cpu": 4, "vmid": 10100}}
	want := `["operation", 0, "carrel-node", {"action": "resize", "cpu": 4, "op": "action", "vmid": 10100}]`
	if got := pythonJSON(v); got != want {
		t.Fatal(fmt.Sprintf("%s != %s", got, want))
	}
}
func TestCapacityNamesTheNodeStorage(t *testing.T) {
	if got := storageID(D{}); got != "local-lvm" {
		t.Fatalf("default storage %q", got)
	}
	if got := storageID(D{"storage_id": "local-zfs"}); got != "local-zfs" {
		t.Fatalf("configured storage %q", got)
	}
}
