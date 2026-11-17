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
	if err := os.WriteFile(token, []byte("first\n"), 0o600); err != nil {
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
	if len(posts) != 1 || posts[0].authorization != "Bearer first" || posts[0].contentType != "application/json" {
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
	for range telemetryQueue * 4 {
		log.Error("reconcile_failed")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("logging waited for the collector")
	}
	tel.Close()
	if n := strings.Count(local.String(), "telemetry_export_failed"); n != 1 {
		t.Fatalf("%d failure lines", n)
	}
	if !strings.Contains(local.String(), `"level":"INFO","msg":"telemetry_export_failed","path":"/v1/logs","problem":"collector answered 503"`) {
		t.Fatal(local.String())
	}
	for _, p := range c.seen("/v1/logs") {
		for _, r := range arr(walk(p.body, "resourceLogs", 0, "scopeLogs", 0, "logRecords")) {
			if walk(r, "body", "stringValue") != "reconcile_failed" {
				t.Fatal("the exporter exported its own failure")
			}
		}
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
	} {
		if v, ok := got[name]; !ok || v != want {
			t.Fatalf("%s = %v (reported %v), want %v", name, v, ok, want)
		}
	}
	if _, ok := got["carrel.node.disk.limit/carrel02"]; ok {
		t.Fatal("an unreachable node reported capacity")
	}
}

// A failed operation is an alert only when the platform is at fault.
func TestOperationFailureLevels(t *testing.T) {
	p, _ := fixture(t)
	var local bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&local, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	fail := func(code string) any {
		return Failure{D{"ok": false, "error": D{"code": code, "message": "x"}}}
	}
	for _, c := range []struct {
		err   any
		level string
	}{
		{fail("quota_exceeded"), "INFO"},
		{fail("invalid"), "INFO"},
		{fail("capacity_exhausted"), "WARN"},
		{fail("backend_unavailable"), "ERROR"},
		{errors.New("unexpected"), "ERROR"},
	} {
		local.Reset()
		e := p.execution(context.Background())
		e.Op = D{"id": "op", "tool": "machine_create", "args": D{}}
		p.Operations.handleError(e, c.err)
		if !strings.Contains(local.String(), `"level":"`+c.level+`","msg":"operation_failed"`) {
			t.Fatalf("%v: %s", c.err, local.String())
		}
	}
}
