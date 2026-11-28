package carrel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// receiver is a webhook endpoint on loopback that records each delivery.
type receiver struct {
	mu     sync.Mutex
	got    []*http.Request
	bodies []string
	status int
}

func (r *receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got, r.bodies = append(r.got, req), append(r.bodies, string(body))
	w.WriteHeader(r.status)
}

func (r *receiver) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.got) }

// allowLoopback lets the webhook client reach a test server on 127.0.0.1
// and trust its certificate, for the length of the test.
func allowLoopback(t *testing.T, srv *httptest.Server) {
	allowed, client := webhookAddrAllowed, webhookClient
	webhookAddrAllowed = func(ip netip.Addr) bool { return ip.IsLoopback() || publicAddr(ip) }
	tr := client.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	webhookClient = &http.Client{Timeout: client.Timeout, Transport: tr, CheckRedirect: client.CheckRedirect}
	t.Cleanup(func() { webhookAddrAllowed, webhookClient = allowed, client })
}

func TestWebhookURLMustBePublicHTTPS(t *testing.T) {
	p, _ := fixture(t)
	p.Config.ServiceEnvKey = testEnvKey
	a, alice := NewApp(p, nil), person("alice", false)
	for _, url := range []string{"http://example.com/hook", "https://10.0.0.5/hook", "https://127.0.0.1/hook", "https://[::1]/hook", "https://100.64.1.1/x", "https://u:p@example.com/", "ftp://example.com/"} {
		if r := a.Call(context.Background(), "webhook_add", D{"url": url}, alice); r["ok"] != false {
			t.Errorf("%s accepted: %s", url, encoded(r))
		}
	}
	r := a.Call(context.Background(), "webhook_add", D{"url": "https://example.com/hook", "types": []any{"app.release.failed"}}, alice)
	assertOK(t, r)
	if !strings.HasPrefix(str(r["secret"]), "whsec_") {
		t.Fatalf("no secret: %s", encoded(r))
	}
	// The secret is shown once: the list never has it.
	list := a.Call(context.Background(), "webhook_list", D{}, alice)
	if strings.Contains(string(encoded(list)), str(r["secret"])) || len(arr(list["webhooks"])) != 1 {
		t.Fatalf("list: %s", encoded(list))
	}
	if stored := p.Store.Objects("webhooks"); strings.Contains(string(encoded(stored)), str(r["secret"])) {
		t.Fatal("the secret is stored in the clear")
	}
	// Another tenant's member does not see or reach it.
	id := obj(r["webhook"])["id"]
	if r := a.Call(context.Background(), "webhook_remove", D{"webhook": id}, person("bob", false)); r["ok"] != false {
		t.Fatalf("bob removed alice's webhook: %s", encoded(r))
	}
}

// The dialer checks the address it connects to, so a name or an address
// inside the site is refused even when the URL passed the check.
func TestWebhookClientRefusesPrivateAddresses(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	_, err := webhookClient.Post(srv.URL, "application/json", strings.NewReader("{}"))
	if err == nil || webhookError(err) != "the URL resolves to an address that is not public" {
		t.Fatalf("loopback reached: %v", err)
	}
	for _, ip := range []string{"10.1.2.3", "192.168.0.1", "172.16.0.1", "100.100.1.1", "169.254.169.254", "::1", "fe80::1", "fd00::1", "::ffff:10.0.0.1", "0.0.0.0"} {
		if publicAddr(netip.MustParseAddr(ip)) {
			t.Errorf("%s counted as public", ip)
		}
	}
	for _, ip := range []string{"140.113.1.1", "8.8.8.8", "2001:4860:4860::8888"} {
		if !publicAddr(netip.MustParseAddr(ip)) {
			t.Errorf("%s counted as private", ip)
		}
	}
}

func TestReleaseEventsAreSignedAndDelivered(t *testing.T) {
	p, a, agent := appFixture(t)
	p.Config.ServiceEnvKey = testEnvKey
	rcv := &receiver{status: 500}
	srv := httptest.NewTLSServer(rcv)
	defer srv.Close()
	allowLoopback(t, srv)
	backoff := webhookBackoff
	webhookBackoff = []time.Duration{0, 0, 0}
	t.Cleanup(func() { webhookBackoff = backoff })
	ctx, alice := context.Background(), person("alice", false)
	added := a.Call(ctx, "webhook_add", D{"url": srv.URL + "/hook"}, alice)
	assertOK(t, added)
	secret := str(added["secret"])

	_, out := upload(t, a, "good", "one")
	id := str(obj(out["release"])["id"])
	do(t, a, "POST", "/apps/v1/agent/report", agent, strings.NewReader(`{"release":"`+id+`","state":"deploying"}`))
	do(t, a, "POST", "/apps/v1/agent/report", agent, strings.NewReader(`{"release":"`+id+`","state":"failed","error":"health check failed; previous release restored"}`))
	// A repeated report is not a second event.
	do(t, a, "POST", "/apps/v1/agent/report", agent, strings.NewReader(`{"release":"`+id+`","state":"failed","error":"health check failed; previous release restored"}`))
	if rows := p.Store.Rows("SELECT type FROM events"); len(rows) != 1 || rows[0]["type"] != "app.release.failed" {
		t.Fatalf("events: %s", encoded(rows))
	}

	// The endpoint fails: the event is tried len(webhookBackoff) times, then
	// given up, and the endpoint's record says so.
	for range 3 {
		p.deliverPass(ctx)
	}
	h := p.Store.Objects("webhooks")[0]
	if rcv.count() != 3 || obj(h["last_delivery"])["given_up"] != true || integer(h["cursor"]) == 0 {
		t.Fatalf("after failures: %d deliveries, %s", rcv.count(), encoded(h))
	}

	// The next event goes through, signed.
	rcv.status = 204
	_, out = upload(t, a, "good", "two")
	second := str(obj(out["release"])["id"])
	do(t, a, "POST", "/apps/v1/agent/report", agent, strings.NewReader(`{"release":"`+second+`","state":"live"}`))
	p.deliverPass(ctx)
	if rcv.count() != 4 {
		t.Fatalf("deliveries: %d", rcv.count())
	}
	req, body := rcv.got[3], rcv.bodies[3]
	ts := req.Header.Get("webhook-timestamp")
	var sec int64
	_ = json.Unmarshal([]byte(ts), &sec)
	if want := webhookSignature(secret, req.Header.Get("webhook-id"), sec, []byte(body)); req.Header.Get("webhook-signature") != want {
		t.Fatalf("signature %q, want %q", req.Header.Get("webhook-signature"), want)
	}
	var event D
	_ = json.Unmarshal([]byte(body), &event)
	if event["type"] != "app.release.live" || obj(event["data"])["release"] != second || obj(event["data"])["tenant"] != "alice" {
		t.Fatalf("event: %s", body)
	}
	var failed D
	_ = json.Unmarshal([]byte(rcv.bodies[0]), &failed)
	if obj(failed["data"])["rolled_back"] != true {
		t.Fatalf("failed event: %s", rcv.bodies[0])
	}
	if p.deliverPass(ctx); rcv.count() != 4 {
		t.Fatal("an event was delivered twice")
	}

	// After a rotation, deliveries carry both signatures for a day.
	rotated := a.Call(ctx, "webhook_rotate", D{"webhook": obj(added["webhook"])["id"]}, alice)
	assertOK(t, rotated)
	test := a.Call(ctx, "webhook_test", D{"webhook": obj(added["webhook"])["id"]}, alice)
	if test["delivered"] != true || integer(test["status"]) != 204 {
		t.Fatalf("test: %s", encoded(test))
	}
	last := rcv.got[len(rcv.got)-1]
	if sigs := strings.Fields(last.Header.Get("webhook-signature")); len(sigs) != 2 {
		t.Fatalf("signatures after rotation: %q", sigs)
	}
}

func TestBuildAndServiceEvents(t *testing.T) {
	p, a, _ := appFixture(t)
	seedMachine(p, "pull", 10102)
	ctx, alice := context.Background(), person("alice", false)
	r := a.Call(ctx, "app_link", D{"machine": "pull", "name": "gitea", "mode": "pull", "repo": "git@git.example.org:alice/site.git", "build": "make", "start": "./run", "port": 8000}, alice)
	assertOK(t, r)
	if code, _ := do(t, a, "POST", "/apps/v1/agent/report", str(r["agent_token"]), strings.NewReader(`{"sha":"`+strings.Repeat("a", 40)+`","state":"failed","error":"build failed"}`)); code != 200 {
		t.Fatalf("report: %d", code)
	}
	types := func(p *Platform) []string {
		out := []string{}
		for _, row := range p.Store.Rows("SELECT type FROM events ORDER BY id") {
			out = append(out, str(row["type"]))
		}
		return out
	}
	if got := types(p); len(got) != 1 || got[0] != "app.build.failed" {
		t.Fatalf("events: %v", got)
	}

	fp, fa := serviceFixture(t)
	call := func(tool string, args D) D { return fa.Call(ctx, tool, args, alice) }
	assertOK(t, call("service_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1", "port": 9000}))
	report(t, fa, `{"revision":1,"services":[{"id":"t1-hook","versions":[{"version":"v1","state":"ready"}]}]}`)
	assertOK(t, call("service_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:2"}))
	report(t, fa, `{"revision":2,"services":[{"id":"t1-hook","current":"v1","versions":[{"version":"v1","state":"ready"},{"version":"v2","state":"failed","error":"pull failed"}]}]}`)
	// The same report again changes nothing and is no event.
	report(t, fa, `{"revision":3,"services":[{"id":"t1-hook","current":"v1","versions":[{"version":"v1","state":"ready"}]}]}`)
	if got := types(fp); len(got) != 2 || got[0] != "service.version.ready" || got[1] != "service.version.failed" {
		t.Fatalf("events: %v", got)
	}
}

func TestEventStreamSendsBacklogAndChecksTenant(t *testing.T) {
	p, _ := fixture(t)
	app := NewApp(p, testVerifier{who: person("alice", false)})
	e := p.execution(context.Background())
	tenant := e.Tenant(person("alice", false), "")
	n := integer(tenant["n"])
	for i := range 3 {
		e.emit(n, "app.release.live", D{"app": "site", "release": i})
	}
	stream := func(path string, headers map[string]string) *httptest.ResponseRecorder {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		r := httptest.NewRequestWithContext(ctx, "GET", "https://carrel.test"+path, nil)
		r.RemoteAddr = "10.200.0.2:12345"
		r.Header.Set("Authorization", "Bearer test")
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		return w
	}
	first := int64(integer(p.Store.Rows("SELECT MIN(id) AS id FROM events")[0]["id"]))
	w := stream("/v1/events", map[string]string{"Last-Event-ID": "evt_" + itoa(first)})
	if w.Code != 200 || w.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream: %d %s", w.Code, w.Body.String())
	}
	if got := strings.Count(w.Body.String(), "event: app.release.live"); got != 2 {
		t.Fatalf("backlog after the first event: %d in %s", got, w.Body.String())
	}
	// Without Last-Event-ID the stream starts at the newest event.
	if w := stream("/v1/events", nil); strings.Contains(w.Body.String(), "event:") {
		t.Fatalf("old events sent: %s", w.Body.String())
	}
	if w := stream("/v1/events?tenant=bob", nil); w.Code != 403 {
		t.Fatalf("another tenant: %d", w.Code)
	}
	if w := stream("/v1/events", map[string]string{"Last-Event-ID": "x"}); w.Code != 400 {
		t.Fatalf("bad id: %d", w.Code)
	}
}

func TestEventStreamEndsWithTheToken(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	if got := streamLife(D{}, now); got != eventStreamLife {
		t.Fatalf("no exp: %v", got)
	}
	if got := streamLife(D{"exp": now.Add(5 * time.Minute).Unix()}, now); got != 5*time.Minute {
		t.Fatalf("token expires first: %v", got)
	}
	if got := streamLife(D{"exp": now.Add(time.Hour).Unix()}, now); got != eventStreamLife {
		t.Fatalf("stream life first: %v", got)
	}
	if got := streamLife(D{"exp": now.Add(-time.Minute).Unix()}, now); got != 0 {
		t.Fatalf("expired: %v", got)
	}
	// A stream whose token has expired closes on its own, long before the
	// request's own deadline.
	p, _ := fixture(t)
	who := merge(person("alice", false), D{"exp": time.Now().Add(-time.Second).Unix()})
	app := NewApp(p, testVerifier{who: who})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r := httptest.NewRequestWithContext(ctx, "GET", "https://carrel.test/v1/events", nil)
	r.RemoteAddr = "10.200.0.2:12345"
	r.Header.Set("Authorization", "Bearer test")
	w := httptest.NewRecorder()
	start := time.Now()
	app.ServeHTTP(w, r)
	if w.Code != 200 || time.Since(start) > 5*time.Second {
		t.Fatalf("stream with an expired token: %d after %v", w.Code, time.Since(start))
	}
}

func TestEventLogKeepsItsCap(t *testing.T) {
	p, _ := fixture(t)
	e := p.execution(context.Background())
	n := integer(e.Tenant(person("alice", false), "")["n"])
	for i := range eventsKept + 5 {
		e.emit(n, "webhook.test", D{"i": i})
	}
	if rows := p.Store.Rows("SELECT COUNT(*) AS c FROM events WHERE tenant=?", n); integer(rows[0]["c"]) != eventsKept {
		t.Fatalf("kept %v", rows[0]["c"])
	}
}

// A webhook removed during a delivery gets no more events, and webhook_test
// waits on its endpoint without the platform's write lock.
func TestWebhookRemovalStopsDeliveryAndTestTakesNoLock(t *testing.T) {
	p, _ := fixture(t)
	p.Config.ServiceEnvKey = testEnvKey
	a, alice := NewApp(p, nil), person("alice", false)
	ctx := context.Background()
	var id any
	held := make(chan bool, 1)
	rcv := &receiver{status: 204}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("webhook-id") != "" && strings.HasPrefix(r.Header.Get("webhook-id"), "evt_test_") {
			// The test call is waiting here: the writer must be free.
			locked := p.writer.TryLock()
			if locked {
				p.writer.Unlock()
			}
			held <- !locked
		} else {
			assertOK(t, a.Call(ctx, "webhook_remove", D{"webhook": id}, alice))
		}
		rcv.ServeHTTP(w, r)
	}))
	defer srv.Close()
	allowLoopback(t, srv)
	added := a.Call(ctx, "webhook_add", D{"url": srv.URL}, alice)
	assertOK(t, added)
	id = obj(added["webhook"])["id"]

	assertOK(t, a.Call(ctx, "webhook_test", D{"webhook": id}, alice))
	if <-held {
		t.Fatal("webhook_test held the writer lock while it waited on the endpoint")
	}
	n := integer(p.Store.Objects("webhooks")[0]["tenant_n"])
	e := p.execution(ctx)
	for i := range 3 {
		e.emit(n, "app.release.live", D{"i": i})
	}
	p.deliverPass(ctx)
	if rcv.count() != 2 {
		t.Fatalf("deliveries after the removal: %d, want the test and 1 event", rcv.count())
	}
}

// A webhook whose secret no key opens does not stop the others.
func TestBrokenWebhookDoesNotStopTheOthers(t *testing.T) {
	p, _ := fixture(t)
	p.Config.ServiceEnvKey = testEnvKey
	a, ctx := NewApp(p, nil), context.Background()
	rcv := &receiver{status: 204}
	srv := httptest.NewTLSServer(rcv)
	defer srv.Close()
	allowLoopback(t, srv)
	e := p.execution(ctx)
	ns := []int{}
	for _, who := range []string{"alice", "bob"} {
		assertOK(t, a.Call(ctx, "webhook_add", D{"url": srv.URL}, person(who, false)))
		n := integer(e.Tenant(person(who, false), "")["n"])
		ns = append(ns, n)
	}
	hooks := p.Store.Objects("webhooks")
	broken := hooks[0]
	broken["secret"] = "AAAA" + str(broken["secret"])[4:]
	p.Store.Put("webhooks", broken["id"], integer(broken["tenant_n"]), broken)
	for _, n := range ns {
		e.emit(n, "app.release.live", D{"app": "site"})
	}
	p.deliverPass(ctx)
	if rcv.count() != 1 {
		t.Fatalf("deliveries: %d, want the healthy webhook's 1", rcv.count())
	}
}

func itoa(v int64) string { return string(encoded(v)) }

func TestWebhookURLRefusesQueryAndBlockedRanges(t *testing.T) {
	p, _ := fixture(t)
	p.Config.ServiceEnvKey = testEnvKey
	a, alice := NewApp(p, nil), person("alice", false)
	if r := a.Call(context.Background(), "webhook_add", D{"url": "https://example.com/hook?token=abc"}, alice); r["ok"] != false {
		t.Errorf("query accepted: %s", encoded(r))
	}
	old := webhookBlocked
	t.Cleanup(func() { webhookBlocked = old })
	webhookBlocked = []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}
	if publicAddr(netip.MustParseAddr("8.8.8.8")) || !publicAddr(netip.MustParseAddr("1.1.1.1")) {
		t.Error("configured range not blocked, or too much blocked")
	}
}

func TestMachineOperationAndQuotaEvents(t *testing.T) {
	p, b := fixture(t)
	seedMachine(p, "dev", 10100)
	b.call = func(D, string) (any, error) { return D{"power_state": "stopped", "changed": true}, nil }
	runQueue(p)
	ctx, alice, root := context.Background(), person("alice", false), person("root", true)
	// The machine's memory is all of the limit: the next operation warns once.
	if r := p.Execute(ctx, "quota_set", D{"tenant": "alice", "dimension": "memory_mb", "amount": 2048}, root); !boolean(r["ok"]) {
		t.Fatalf("quota_set: %s", encoded(r))
	}
	events := func() []D {
		out := []D{}
		for _, row := range p.Store.Rows("SELECT tenant,type,data FROM events ORDER BY id") {
			var data D
			_ = json.Unmarshal([]byte(str(row["data"])), &data)
			out = append(out, D{"tenant": row["tenant"], "type": row["type"], "data": data})
		}
		return out
	}
	assertOK(t, NewApp(p, nil).Call(ctx, "machine_power", D{"machine": "dev", "action": "shutdown"}, alice))
	got := events()
	if len(got) != 2 || got[0]["type"] != "machine.operation.succeeded" || obj(got[0]["data"])["machine"] != "dev" || obj(got[0]["data"])["tool"] != "machine_power" || integer(got[0]["tenant"]) != 1 {
		t.Fatalf("events: %s", encoded(got))
	}
	if got[1]["type"] != "quota.warning" || obj(got[1]["data"])["dimension"] != "memory_mb" {
		t.Fatalf("quota event: %s", encoded(got[1]))
	}
	// A second operation at the same usage does not warn again.
	b.call = func(D, string) (any, error) { return nil, errors.New("node unreachable") }
	assertOK(t, NewApp(p, nil).Call(ctx, "machine_power", D{"machine": "dev", "action": "shutdown"}, alice))
	got = events()
	if len(got) != 3 || got[2]["type"] != "machine.operation.failed" || obj(obj(got[2]["data"])["error"])["code"] == nil {
		t.Fatalf("after failure: %s", encoded(got))
	}
}
