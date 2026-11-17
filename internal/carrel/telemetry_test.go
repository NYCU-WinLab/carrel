package carrel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// collector stands in for an OTLP/HTTP collector.
type collector struct {
	mu     sync.Mutex
	status int
	posts  []collected
	server *httptest.Server
}

type collected struct {
	path, authorization, contentType string
	body                             D
}

func newCollector(t *testing.T) *collector {
	t.Helper()
	c := &collector{status: 200}
	c.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content, _ := io.ReadAll(r.Body)
		var body D
		_ = json.Unmarshal(content, &body)
		c.mu.Lock()
		c.posts = append(c.posts, collected{r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), body})
		status := c.status
		c.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(c.server.Close)
	return c
}

func (c *collector) seen(path string) []collected {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []collected{}
	for _, p := range c.posts {
		if p.path == path {
			out = append(out, p)
		}
	}
	return out
}

// telemetryFixture sends to the collector with the token in a file.
func telemetryFixture(t *testing.T, c *collector, stderr slog.Handler) (*Telemetry, string) {
	t.Helper()
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("first-token-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return newTelemetry(Config{TelemetryURL: c.server.URL + "/", TelemetryTokenFile: token}, c.server.Client(), stderr), token
}

func walk(v any, path ...any) any {
	for _, k := range path {
		switch x := k.(type) {
		case string:
			v = obj(v)[x]
		case int:
			v = arr(v)[x]
		}
	}
	return v
}

func TestTelemetrySendsWarningsAndErrorsOnly(t *testing.T) {
	c := newCollector(t)
	var local bytes.Buffer
	stderr := slog.NewJSONHandler(&local, nil)
	tel, _ := telemetryFixture(t, c, stderr)
	log := slog.New(tel.Handler(stderr))
	log.Info("carrel_started")
	log.Warn("node_without_tenant_route", "node", "carrel03")
	log.Error("reconcile_failed", "type", "maintenance", "detail", strings.Repeat("x", 1000))
	tel.Close()

	posts := c.seen("/v1/logs")
	if len(posts) != 1 || posts[0].authorization != "Bearer first-token-value" || posts[0].contentType != "application/json" {
		t.Fatal(posts)
	}
	if walk(posts[0].body, "resourceLogs", 0, "resource", "attributes", 0, "value", "stringValue") != "carrel" {
		t.Fatal(posts[0].body)
	}
	records := arr(walk(posts[0].body, "resourceLogs", 0, "scopeLogs", 0, "logRecords"))
	if len(records) != 2 {
		t.Fatal(records)
	}
	warn, fail := obj(records[0]), obj(records[1])
	if walk(warn, "body", "stringValue") != "node_without_tenant_route" || warn["severityText"] != "WARN" || num(warn["severityNumber"]) != 13 {
		t.Fatal(warn)
	}
	if walk(warn, "attributes", 0, "key") != "node" || walk(warn, "attributes", 0, "value", "stringValue") != "carrel03" {
		t.Fatal(warn)
	}
	if fail["severityText"] != "ERROR" || num(fail["severityNumber"]) != 17 || len(str(walk(fail, "attributes", 1, "value", "stringValue"))) != telemetryValue {
		t.Fatal(fail)
	}
	// Everything still reaches stderr, the INFO record included.
	for _, msg := range []string{"carrel_started", "node_without_tenant_route", "reconcile_failed"} {
		if !strings.Contains(local.String(), msg) {
			t.Fatalf("%s missing from stderr", msg)
		}
	}
}

func TestTelemetryGaugesCarryTheirAttributes(t *testing.T) {
	c := newCollector(t)
	tel, token := telemetryFixture(t, c, slog.NewJSONHandler(io.Discard, nil))
	// The token is read on every send: a rotation needs no restart.
	if err := os.WriteFile(token, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	tel.Gauge("carrel.node.storage.utilization", "1", 0.25, "node", "carrel04")
	tel.Close()
	posts := c.seen("/v1/metrics")
	if len(posts) != 1 || posts[0].authorization != "Bearer second" {
		t.Fatal(posts)
	}
	metric := obj(walk(posts[0].body, "resourceMetrics", 0, "scopeMetrics", 0, "metrics", 0))
	point := obj(walk(metric, "gauge", "dataPoints", 0))
	if metric["name"] != "carrel.node.storage.utilization" || num(point["asDouble"]) != 0.25 || walk(point, "attributes", 0, "value", "stringValue") != "carrel04" {
		t.Fatal(metric)
	}
	if at, err := strconv.ParseInt(str(point["timeUnixNano"]), 10, 64); err != nil || time.Since(time.Unix(0, at)) > time.Minute {
		t.Fatal(point)
	}
}

// A collector that fails or hangs costs the caller nothing, and its failure
// is one INFO line on stderr that never goes back into the queue.
func TestTelemetryFailureStaysLocalAndNeverBlocks(t *testing.T) {
	c := newCollector(t)
	c.status = 503
	var local bytes.Buffer
	stderr := slog.NewJSONHandler(&local, nil)
	tel, _ := telemetryFixture(t, c, stderr)
	log := slog.New(tel.Handler(stderr))
	started := time.Now()
	for i := range telemetryQueue * 4 {
		log.Error("failure_" + strconv.Itoa(i))
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("logging waited for the collector")
	}
	tel.Close()
	if n := strings.Count(local.String(), "telemetry_export_failed"); n != 1 {
		t.Fatalf("%d failure lines", n)
	}
	if strings.Contains(local.String(), "first-token-value") {
		t.Fatal("the token reached stderr")
	}
	if !strings.Contains(local.String(), `"level":"INFO","msg":"telemetry_export_failed","path":"/v1/logs","problem":"collector answered 503"`) {
		t.Fatal(local.String())
	}
	for _, p := range c.seen("/v1/logs") {
		for _, r := range arr(walk(p.body, "resourceLogs", 0, "scopeLogs", 0, "logRecords")) {
			if !strings.HasPrefix(str(walk(r, "body", "stringValue")), "failure_") {
				t.Fatal("the exporter exported its own failure")
			}
		}
	}
}

// A collector that never answers: logging stays fast, and Close gives up
// after the send timeout instead of hanging the shutdown.
func TestTelemetryCollectorThatHangs(t *testing.T) {
	c := newCollector(t)
	release := make(chan struct{})
	c.server.Config.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release })
	t.Cleanup(func() { close(release) })
	client := c.server.Client()
	client.Timeout = 200 * time.Millisecond
	var local bytes.Buffer
	stderr := slog.NewJSONHandler(&local, nil)
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("first-token-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	tel := newTelemetry(Config{TelemetryURL: c.server.URL, TelemetryTokenFile: token}, client, stderr)
	log := slog.New(tel.Handler(stderr))
	started := time.Now()
	for i := range 2000 {
		log.Error("failure_" + strconv.Itoa(i))
		tel.Gauge("x", "1", 1)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("logging waited for the collector")
	}
	tel.Close()
	if time.Since(started) > 10*time.Second {
		t.Fatal("Close waited for the collector")
	}
	// After Close nothing panics and nothing blocks.
	log.Error("after_close")
	tel.Gauge("x", "1", 1)
	if !strings.Contains(local.String(), `"problem":"collector unreachable"`) || strings.Contains(local.String(), "first-token-value") {
		t.Fatal("the hang was not what failed, or the token reached stderr")
	}
}

// The token goes to the configured host only, never where a redirect points.
func TestTelemetryDoesNotFollowRedirects(t *testing.T) {
	elsewhere := newCollector(t)
	c := newCollector(t)
	c.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.server.URL+r.URL.Path, http.StatusTemporaryRedirect)
	})
	var local bytes.Buffer
	stderr := slog.NewJSONHandler(&local, nil)
	tel, _ := telemetryFixture(t, c, stderr)
	slog.New(tel.Handler(stderr)).Error("reconcile_failed")
	tel.Close()
	if len(elsewhere.seen("/v1/logs")) != 0 {
		t.Fatal("the request followed a redirect")
	}
	if !strings.Contains(local.String(), "collector answered 307") {
		t.Fatal(local.String())
	}
}

// One message cannot crowd out the rest: a warning any outsider can cause
// leaves at most telemetryRepeat times a minute.
func TestTelemetryCapsARepeatedMessage(t *testing.T) {
	c := newCollector(t)
	stderr := slog.NewJSONHandler(io.Discard, nil)
	tel, _ := telemetryFixture(t, c, stderr)
	log := slog.New(tel.Handler(stderr))
	for range telemetryQueue * 2 {
		log.Warn("oauth_rate_limited", "client", "203.0.113.9")
	}
	log.Error("reconcile_failed")
	// An error that shares the flooded message still leaves.
	log.Error("oauth_rate_limited")
	tel.Close()
	count := map[string]int{}
	for _, p := range c.seen("/v1/logs") {
		for _, r := range arr(walk(p.body, "resourceLogs", 0, "scopeLogs", 0, "logRecords")) {
			count[str(obj(r)["severityText"])+" "+str(walk(r, "body", "stringValue"))]++
		}
	}
	if count["WARN oauth_rate_limited"] != telemetryRepeat || count["ERROR reconcile_failed"] != 1 || count["ERROR oauth_rate_limited"] != 1 {
		t.Fatal(count)
	}
}

func TestTelemetryOffByDefault(t *testing.T) {
	var tel *Telemetry
	if NewTelemetry(Config{}, nil) != nil {
		t.Fatal("telemetry without a collector")
	}
	base := slog.NewJSONHandler(io.Discard, nil)
	if tel.Handler(base) != slog.Handler(base) {
		t.Fatal("nil telemetry wrapped the handler")
	}
	tel.Gauge("x", "1", 1)
	tel.Close()
}

func TestTelemetryConfig(t *testing.T) {
	base := Config{Origin: "https://carrel.test", Database: "x", PublicAddress: "140.113.60.184", Nodes: []NodeConfig{{"carrel01", "node"}}}
	for _, c := range []struct {
		url, file string
		ok        bool
	}{
		{"", "", true},
		{"https://sensorium.example", "/etc/carrel/telemetry.token", true},
		{"https://sensorium.example", "", false},
		{"http://sensorium.example", "/etc/carrel/telemetry.token", false},
		{"https://user@sensorium.example", "/etc/carrel/telemetry.token", false},
		{"https://sensorium.example/?x=1", "/etc/carrel/telemetry.token", false},
	} {
		cfg := base
		cfg.TelemetryURL, cfg.TelemetryTokenFile = c.url, c.file
		if err := cfg.WithDefaults().Validate(); (err == nil) != c.ok {
			t.Fatalf("%q %q: %v", c.url, c.file, err)
		}
	}
}

func TestCapacityReportNamesEveryNode(t *testing.T) {
	p, b, _ := nodeFixture(t)
	c := newCollector(t)
	tel, _ := telemetryFixture(t, c, slog.NewJSONHandler(io.Discard, nil))
	p.Telemetry = tel
	p.Store.Put("snapshots", "10100-s", 1, D{"id": "10100-s", "vmid": 10100, "name": "s", "disk_gb": 40, "state": "ready"})
	inner := b.call
	b.call = func(r D, target string) (any, error) {
		if r["op"] == "inventory" && target == "node-02" {
			return nil, errors.New("unreachable")
		}
		if r["op"] == "guest_memory" {
			if target == "node-03" {
				return nil, errors.New("no answer")
			}
			return D{"node": "carrel01", "running": 5, "reporting": 2, "assigned_bytes": 6 * GiB, "available_bytes": 4 * GiB}, nil
		}
		v, err := inner(r, target)
		if inv, ok := v.(D); ok && r["op"] == "inventory" && target == "node-01" {
			inv["storage"] = D{"total": 1000 * GiB, "used": 750 * GiB}
			inv["snapshot_bytes"] = 2 * GiB
		}
		return v, err
	}
	p.reportCapacity()
	tel.Close()
	got := map[string]float64{}
	for _, post := range c.seen("/v1/metrics") {
		for _, m := range arr(walk(post.body, "resourceMetrics", 0, "scopeMetrics", 0, "metrics")) {
			point := walk(m, "gauge", "dataPoints", 0)
			got[str(obj(m)["name"])+"/"+str(walk(point, "attributes", 0, "value", "stringValue"))] = num(obj(point)["asDouble"])
		}
	}
	for name, want := range map[string]float64{
		"carrel.node.reachable/carrel01":           1,
		"carrel.node.reachable/carrel02":           0,
		"carrel.node.reachable/carrel03":           1,
		"carrel.node.storage.utilization/carrel01": 0.75,
		"carrel.node.snapshot.counted/carrel01":    2 * GiB,
		"carrel.node.snapshot.declared/carrel01":   40 * GiB,
		"carrel.node.disk.limit/carrel01":          1500 * GiB,
		"carrel.node.vcpu.limit/carrel03":          128,
		// The fixture's node holds 192 GiB and uses 100.
		"carrel.node.memory.utilization/carrel01":    100.0 / 192,
		"carrel.node.guest.running/carrel01":         5,
		"carrel.node.guest.reporting/carrel01":       2,
		"carrel.node.guest.memory.assigned/carrel01": 6 * GiB,
		"carrel.node.guest.memory.needed/carrel01":   2 * GiB,
	} {
		if v, ok := got[name]; !ok || v != want {
			t.Fatalf("%s = %v (reported %v), want %v", name, v, ok, want)
		}
	}
	if _, ok := got["carrel.node.disk.limit/carrel02"]; ok {
		t.Fatal("an unreachable node reported capacity")
	}
	// A node that does not answer about its guests still reports the rest.
	if _, ok := got["carrel.node.guest.running/carrel03"]; ok {
		t.Fatal("a node with no answer reported guest memory")
	}
}

// A failed operation is quiet only when the member can fix it. The refusals
// come from fail, as they do in the tools.
func TestOperationFailureLevels(t *testing.T) {
	p, _ := fixture(t)
	var local bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&local, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	refusal := func(code string, details ...D) any {
		return attempt(func() { fail(code, "x", details...) })
	}
	for _, c := range []struct {
		err   any
		level string
	}{
		{refusal("invalid"), "INFO"},
		{refusal("not_found"), "INFO"},
		{refusal("forbidden"), "INFO"},
		{refusal("quota_exceeded"), "INFO"},
		{refusal("conflict"), "INFO"},
		{refusal("capacity_exhausted"), "WARN"},
		{refusal("guest_not_ready"), "WARN"},
		{refusal("backend_unavailable"), "ERROR"},
		// A damaged sealed value, a function host that is not set up.
		{refusal("internal"), "ERROR"},
		{refusal("unavailable"), "ERROR"},
		// A code nobody listed is the operators' until someone lists it.
		{refusal("something_new"), "ERROR"},
		// The recovery names the operators, whatever the code.
		{refusal("conflict", D{"recovery": "retry_infrastructure"}), "ERROR"},
		{refusal("conflict", D{"recovery": "contact_administrator"}), "ERROR"},
		{refusal("quota_exceeded", D{"recovery": "contact_administrator"}), "ERROR"},
		{refusal("capacity_exhausted", D{"recovery": "retry_infrastructure"}), "ERROR"},
		{refusal("conflict", D{"recovery": "revise_request"}), "INFO"},
		{errors.New("unexpected"), "ERROR"},
	} {
		local.Reset()
		e := p.execution(context.Background())
		e.Op = D{"id": "op", "tool": "machine_create", "args": D{}}
		p.Operations.handleError(e, c.err)
		if !strings.Contains(local.String(), `"level":"`+c.level+`","msg":"operation_failed"`) || !strings.Contains(local.String(), `"tool":"machine_create"`) {
			t.Fatalf("%v: %s", c.err, local.String())
		}
	}
}

// One span per tool call: the tool, the tenant number and the outcome, and
// nothing from the arguments.
func TestToolCallsBecomeSpans(t *testing.T) {
	p, _ := fixture(t)
	c := newCollector(t)
	tel, _ := telemetryFixture(t, c, slog.NewJSONHandler(io.Discard, nil))
	p.Telemetry = tel
	app := NewApp(p, nil)
	ctx := context.Background()
	alice := p.Store.Tenant("user:alice")
	assertOK(t, app.Call(ctx, "machine_list", D{}, person("alice", false)))
	assertCode(t, app.Call(ctx, "machine_get", D{"machine": "secret-name"}, person("alice", false)), "not_found")
	assertCode(t, app.Call(ctx, "no_such_tool", D{}, person("alice", false)), "invalid")
	tel.Close()

	posts := c.seen("/v1/traces")
	if len(posts) != 1 || posts[0].authorization != "Bearer first-token-value" {
		t.Fatal(posts)
	}
	spans := arr(walk(posts[0].body, "resourceSpans", 0, "scopeSpans", 0, "spans"))
	if len(spans) != 3 {
		t.Fatal(spans)
	}
	attr := func(s any, key string) string {
		for _, a := range arr(obj(s)["attributes"]) {
			if obj(a)["key"] == key {
				return str(walk(a, "value", "stringValue"))
			}
		}
		return ""
	}
	for i, want := range [][3]string{
		{"machine_list", strconv.Itoa(integer(alice["n"])), "ok"},
		{"machine_get", strconv.Itoa(integer(alice["n"])), "not_found"},
		{"unknown", strconv.Itoa(integer(alice["n"])), "invalid"},
	} {
		s := spans[i]
		if obj(s)["name"] != want[0] || attr(s, "carrel.tool") != want[0] || attr(s, "carrel.tenant") != want[1] || attr(s, "carrel.outcome") != want[2] {
			t.Fatalf("span %d: %v", i, s)
		}
		if len(str(obj(s)["traceId"])) != 32 || len(str(obj(s)["spanId"])) != 16 {
			t.Fatal(s)
		}
		start, _ := strconv.ParseInt(str(obj(s)["startTimeUnixNano"]), 10, 64)
		end, _ := strconv.ParseInt(str(obj(s)["endTimeUnixNano"]), 10, 64)
		if start == 0 || end < start {
			t.Fatal(s)
		}
		if strings.Contains(string(encoded(s)), "secret-name") {
			t.Fatal("arguments leaked into a span")
		}
	}
	if num(walk(spans[0], "status", "code")) != 1 || num(walk(spans[1], "status", "code")) != 2 {
		t.Fatal(spans)
	}
}

// startTelemetry reports capacity on its own clock, as soon as Start runs.
func TestStartTelemetryReportsCapacityAtOnce(t *testing.T) {
	p, _, _ := nodeFixture(t)
	c := newCollector(t)
	tel, _ := telemetryFixture(t, c, slog.NewJSONHandler(io.Discard, nil))
	p.Telemetry = tel
	p.startTelemetry()
	deadline := time.Now().Add(5 * time.Second)
	for len(c.seen("/v1/metrics")) == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	p.Close()
	tel.Close()
	if len(c.seen("/v1/metrics")) == 0 {
		t.Fatal("no capacity gauges reached the collector")
	}
}
