package carrel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Telemetry sends what an admin must see to an OTLP/HTTP collector
// (PLAN 9.1): every WARN and ERROR log record, and the gauges handed to
// Gauge. It never slows the caller: items wait in a bounded queue, a full
// queue drops them, and a collector that does not answer costs one line on
// stderr a minute. A nil *Telemetry does nothing, so callers need no check.
type Telemetry struct {
	url       string
	tokenFile string
	client    *http.Client
	stderr    slog.Handler
	queue     chan telemetryItem
	done      chan struct{}
	wg        sync.WaitGroup
	failedAt  time.Time
}

// telemetryItem is one OTLP log record or one OTLP metric.
type telemetryItem struct {
	metric bool
	body   D
}

const (
	telemetryQueue = 512
	telemetryBatch = 200
	telemetryFlush = 2 * time.Second
	telemetrySend  = 5 * time.Second
	telemetryValue = 400
)

// NewTelemetry starts the sender, or returns nil when the configuration
// names no collector. stderr receives its own failures: they are never
// exported, so a dead collector cannot feed itself.
func NewTelemetry(c Config, stderr slog.Handler) *Telemetry {
	if c.TelemetryURL == "" {
		return nil
	}
	// The request carries the write token: it goes to the configured host
	// and nowhere a redirect points.
	client := &http.Client{Timeout: telemetrySend, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return newTelemetry(c, client, stderr)
}

func newTelemetry(c Config, client *http.Client, stderr slog.Handler) *Telemetry {
	t := &Telemetry{
		url:       strings.TrimRight(c.TelemetryURL, "/"),
		tokenFile: c.TelemetryTokenFile,
		client:    client,
		stderr:    stderr,
		queue:     make(chan telemetryItem, telemetryQueue),
		done:      make(chan struct{}),
	}
	t.wg.Add(1)
	go t.loop()
	return t
}

// Close sends what is queued and stops the sender.
func (t *Telemetry) Close() {
	if t == nil {
		return
	}
	close(t.done)
	t.wg.Wait()
}

// Handler wraps the process's log handler: records at WARN and above also
// go to the collector. Attributes bound with With stay on stderr only;
// carrel binds none.
func (t *Telemetry) Handler(h slog.Handler) slog.Handler {
	if t == nil {
		return h
	}
	return telemetryHandler{h, t}
}

type telemetryHandler struct {
	slog.Handler
	t *Telemetry
}

func (h telemetryHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		h.t.log(r)
	}
	return h.Handler.Handle(ctx, r)
}
func (h telemetryHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return telemetryHandler{h.Handler.WithAttrs(a), h.t}
}
func (h telemetryHandler) WithGroup(name string) slog.Handler {
	return telemetryHandler{h.Handler.WithGroup(name), h.t}
}

func (t *Telemetry) log(r slog.Record) {
	attrs := []D{}
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, otlpString(a.Key, truncate(fmt.Sprint(a.Value.Resolve().Any()), telemetryValue)))
		return true
	})
	severity := 13 // WARN
	if r.Level >= slog.LevelError {
		severity = 17
	}
	t.enqueue(telemetryItem{body: D{
		"timeUnixNano":   strconv.FormatInt(r.Time.UnixNano(), 10),
		"severityNumber": severity,
		"severityText":   r.Level.String(),
		"body":           D{"stringValue": r.Message},
		"attributes":     attrs,
	}})
}

// Gauge queues one reading. attrs are key, value pairs; every point carries
// them itself, because a collector may return points without the resource.
func (t *Telemetry) Gauge(name, unit string, value float64, attrs ...string) {
	if t == nil {
		return
	}
	point := D{"timeUnixNano": strconv.FormatInt(time.Now().UnixNano(), 10), "asDouble": value, "attributes": []D{}}
	for i := 0; i+1 < len(attrs); i += 2 {
		point["attributes"] = append(point["attributes"].([]D), otlpString(attrs[i], attrs[i+1]))
	}
	t.enqueue(telemetryItem{metric: true, body: D{"name": name, "unit": unit, "gauge": D{"dataPoints": []D{point}}}})
}

func (t *Telemetry) enqueue(item telemetryItem) {
	select {
	case t.queue <- item:
	default:
		// Full: the collector is slow or gone. Dropping keeps the caller fast.
	}
}

func otlpString(key, value string) D {
	return D{"key": key, "value": D{"stringValue": value}}
}

func (t *Telemetry) loop() {
	defer t.wg.Done()
	tick := time.NewTicker(telemetryFlush)
	defer tick.Stop()
	var logs, metrics []D
	flush := func() {
		if len(logs) > 0 {
			t.post("/v1/logs", D{"resourceLogs": []D{{"resource": otlpResource(), "scopeLogs": []D{{"scope": D{"name": "carrel"}, "logRecords": logs}}}}})
			logs = nil
		}
		if len(metrics) > 0 {
			t.post("/v1/metrics", D{"resourceMetrics": []D{{"resource": otlpResource(), "scopeMetrics": []D{{"scope": D{"name": "carrel"}, "metrics": metrics}}}}})
			metrics = nil
		}
	}
	add := func(item telemetryItem) {
		if item.metric {
			metrics = append(metrics, item.body)
		} else {
			logs = append(logs, item.body)
		}
	}
	for {
		select {
		case item := <-t.queue:
			add(item)
			if len(logs)+len(metrics) >= telemetryBatch {
				flush()
			}
		case <-tick.C:
			flush()
		case <-t.done:
			for {
				select {
				case item := <-t.queue:
					add(item)
					continue
				default:
				}
				break
			}
			flush()
			return
		}
	}
}

func otlpResource() D {
	return D{"attributes": []D{otlpString("service.name", "carrel"), otlpString("service.version", Version)}}
}

// post sends one request. The token is read on every send, so rotating it
// needs no restart.
func (t *Telemetry) post(path string, body D) {
	problem := func() string {
		token, err := os.ReadFile(t.tokenFile)
		if err != nil {
			return "token file unreadable"
		}
		content, err := json.Marshal(body)
		if err != nil {
			return "encoding failed"
		}
		req, err := http.NewRequest(http.MethodPost, t.url+path, bytes.NewReader(content))
		if err != nil {
			return "invalid request"
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
		resp, err := t.client.Do(req)
		if err != nil {
			return "collector unreachable"
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return "collector answered " + strconv.Itoa(resp.StatusCode)
		}
		return ""
	}()
	if problem == "" || time.Since(t.failedAt) < time.Minute {
		return
	}
	t.failedAt = time.Now()
	// Straight to stderr at INFO, never through the exporting handler.
	r := slog.NewRecord(t.failedAt, slog.LevelInfo, "telemetry_export_failed", 0)
	r.AddAttrs(slog.String("path", path), slog.String("problem", problem))
	_ = t.stderr.Handle(context.Background(), r)
}

// reportCapacity hands each node's admission view to telemetry: what the
// Proxmox metric server does not export. An alert rule on
// carrel.node.storage.utilization is how an admin hears about a watermark,
// and carrel.node.reachable about a node the control plane cannot read.
func (p *Platform) reportCapacity() {
	t := p.Telemetry
	e := p.execution(p.ctx)
	nodes := p.Nodes()
	inventories, times, failures := e.inventories(nodes, true)
	for i, n := range nodes {
		if failures[i] != nil {
			t.Gauge("carrel.node.reachable", "1", 0, "node", n.Name)
			continue
		}
		t.Gauge("carrel.node.reachable", "1", 1, "node", n.Name)
		reservations, snapshots := e.nodeLoad(n, nil)
		c := summarize(obj(inventories[i]), reservations, snapshots, times[i])
		allocatable, disk := obj(c["allocatable"]), obj(obj(c["physical"])["disk"])
		for _, dim := range []struct {
			key, name, unit string
			scale           float64
		}{{"vcpu", "vcpu", "{vcpu}", 1}, {"memory_gib", "memory", "By", GiB}, {"disk_gib", "disk", "By", GiB}} {
			a := obj(allocatable[dim.key])
			t.Gauge("carrel.node."+dim.name+".committed", dim.unit, num(a["committed"])*dim.scale, "node", n.Name)
			t.Gauge("carrel.node."+dim.name+".limit", dim.unit, num(a["limit"])*dim.scale, "node", n.Name)
		}
		if total := num(disk["total"]); total > 0 {
			t.Gauge("carrel.node.storage.utilization", "1", num(disk["used"])/total, "node", n.Name)
		}
		t.Gauge("carrel.node.snapshot.counted", "By", num(disk["snapshot_gib"])*GiB, "node", n.Name)
		t.Gauge("carrel.node.snapshot.declared", "By", num(disk["snapshot_declared_gib"])*GiB, "node", n.Name)
	}
}

// startTelemetry reports capacity every minute, on its own clock: a slow
// reconcile must not leave a gap an alert rule reads as silence.
func (p *Platform) startTelemetry() {
	if p.Telemetry == nil {
		return
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			_ = attempt(p.reportCapacity)
			if !sleep(p.ctx, time.Minute) {
				return
			}
		}
	}()
}
