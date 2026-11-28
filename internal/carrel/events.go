package carrel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Events (#642): each tenant has one event log in the events table. A
// member learns of a failed deploy from a signed webhook (Standard Webhooks)
// or from the SSE stream GET /v1/events, without polling app_get.

const (
	eventsKept     = 1000
	eventsMaxAge   = 7 * 24 * time.Hour
	maxWebhooks    = 10
	webhookTimeout = 10 * time.Second
	webhookBatch   = 20
	webhookOverlap = 24 * time.Hour
	// webhookPassBudget bounds one endpoint's share of a delivery pass.
	webhookPassBudget = 20 * time.Second
	eventStreamLife   = 30 * time.Minute
	// eventStreamRecheck is how often a stream checks its member still
	// belongs to the tenant.
	eventStreamRecheck = 2 * time.Minute
)

// webhookBackoff is the wait before each attempt at one event; after the
// last one the event is given up and the next one goes.
var webhookBackoff = []time.Duration{0, 30 * time.Second, 2 * time.Minute, 10 * time.Minute, time.Hour, 6 * time.Hour}

// eventTypes are the events a webhook can ask for.
var eventTypes = []string{"app.release.live", "app.release.failed", "app.build.failed", "service.version.ready", "service.version.failed", "machine.operation.succeeded", "machine.operation.failed", "quota.warning", "webhook.test"}

// eventHub wakes the SSE streams and the delivery loop when an event is
// written.
type eventHub struct {
	mu   sync.Mutex
	wake chan struct{}
}

func (h *eventHub) changed() <-chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.wake == nil {
		h.wake = make(chan struct{})
	}
	return h.wake
}

func (h *eventHub) notify() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.wake != nil {
		close(h.wake)
	}
	h.wake = make(chan struct{})
}

// emit writes an event to tenant n's log, in the caller's transaction when
// there is one, and keeps the log within its caps. The caller wakes the
// readers with p.events.notify once the transaction is committed.
func (e *Execution) emit(n int, typ string, data D) {
	e.S.Exec("INSERT INTO events(tenant,at,type,data) VALUES(?,?,?,?)", n, now(), typ, string(encoded(data)))
	e.S.Exec("DELETE FROM events WHERE tenant=? AND (at<? OR id<=(SELECT id FROM events WHERE tenant=? ORDER BY id DESC LIMIT 1 OFFSET ?))",
		n, now()-eventsMaxAge.Seconds(), n, eventsKept)
}

func (s *Store) eventsAfter(n int, after int64, limit int) []D {
	return s.Rows("SELECT id,at,type,data FROM events WHERE tenant=? AND id>? ORDER BY id LIMIT ?", n, after, limit)
}

func (s *Store) lastEvent(n int) int64 {
	rows := s.Rows("SELECT COALESCE(MAX(id),0) AS id FROM events WHERE tenant=?", n)
	return int64(integer(rows[0]["id"]))
}

func eventTime(at any) string {
	sec := num(at)
	return time.Unix(int64(sec), int64((sec-float64(int64(sec)))*1e9)).UTC().Format(time.RFC3339Nano)
}

// publicEvent is an event as webhooks and the stream carry it.
func publicEvent(row D, slug string) D {
	var data D
	_ = json.Unmarshal([]byte(str(row["data"])), &data)
	return D{"id": "evt_" + strconv.FormatInt(int64(integer(row["id"])), 10), "type": row["type"], "timestamp": eventTime(row["at"]), "tenant": slug, "data": data}
}

// Webhook endpoints

func newWebhookSecret() string {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	must(err)
	return "whsec_" + base64.StdEncoding.EncodeToString(key)
}

// webhookSignature is one Standard Webhooks signature of a delivery.
func webhookSignature(secret, id string, ts int64, body []byte) string {
	key, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%s.%d.", id, ts)
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func checkWebhookURL(raw string) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || strings.Contains(raw, "?") || len(raw) > 2048 {
		fail("invalid", "url must be an https URL with no user, query or fragment; the signature proves a delivery, so do not put a token in the URL", D{"recovery": "revise_request"})
	}
	if ip, err := netip.ParseAddr(strings.Trim(u.Hostname(), "[]")); err == nil && !webhookAddrAllowed(ip) {
		fail("invalid", "url must reach a public address", D{"recovery": "revise_request"})
	}
}

// publicAddr tells whether a webhook may reach ip: never a private,
// loopback, link-local, tailnet (CGNAT) or reserved address, so a member
// cannot make the control plane call into the site's internal networks.
// Other public addresses are allowed; webhook_blocked_ranges lists the
// site's own public ranges that services may trust by source address.
func publicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range webhookBlocked {
		if p.Contains(ip) {
			return false
		}
	}
	for _, p := range []string{"100.64.0.0/10", "198.18.0.0/15", "192.0.0.0/24", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "64:ff9b::/96", "64:ff9b:1::/48", "2001::/32", "2002::/16", "2001:db8::/32", "fec0::/10", "::/96"} {
		if netip.MustParsePrefix(p).Contains(ip) {
			return false
		}
	}
	return true
}

// webhookBlocked are extra ranges webhooks must not reach, from the
// webhook_blocked_ranges setting (the site's public pool and IPv6 prefix).
var webhookBlocked []netip.Prefix

// webhookAddrAllowed is publicAddr; tests let loopback through.
var webhookAddrAllowed = publicAddr

var errWebhookAddress = errors.New("the webhook address is not public")

// webhookClient checks the address it connects to, after resolution, so a
// name that resolves inside the site is refused too. It follows no
// redirect and uses no proxy.
var webhookClient = &http.Client{
	Timeout: webhookTimeout,
	Transport: &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{Timeout: 5 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil || !webhookAddrAllowed(ip) {
				return errWebhookAddress
			}
			return nil
		}}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: webhookTimeout,
		MaxIdleConns:          10,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// webhookSecrets are the secrets a delivery is signed with: the current
// one, and the one before it for a day after a rotation.
func (p *Platform) webhookSecrets(h D) []string {
	var current string
	p.openValue("webhook:"+str(h["id"]), str(h["secret"]), &current)
	out := []string{current}
	if str(h["previous_secret"]) != "" && num(h["previous_until"]) > now() {
		var previous string
		p.openValue("webhook:"+str(h["id"])+"#previous", str(h["previous_secret"]), &previous)
		out = append(out, previous)
	}
	return out
}

// send posts one event to an endpoint and returns the HTTP status.
func (p *Platform) send(ctx context.Context, h D, event D) (int, error) {
	body := encoded(D{"type": event["type"], "timestamp": event["timestamp"], "data": merge(obj(event["data"]), D{"tenant": event["tenant"]})})
	id, ts := str(event["id"]), time.Now().Unix()
	signatures := []string{}
	for _, secret := range p.webhookSecrets(h) {
		signatures = append(signatures, webhookSignature(secret, id, ts, body))
	}
	req, err := http.NewRequestWithContext(ctx, "POST", str(h["url"]), bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "carrel-webhooks")
	req.Header.Set("webhook-id", id)
	req.Header.Set("webhook-timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("webhook-signature", strings.Join(signatures, " "))
	resp, err := webhookClient.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	return resp.StatusCode, nil
}

func publicWebhook(h D) D {
	return pick(h, "id", "url", "types", "created_at", "last_delivery", "rotated_at")
}

func (e *Execution) Webhook(t D, ref any) D {
	h := e.S.Get("webhooks", str(ref))
	if h == nil || integer(h["tenant_n"]) != integer(t["n"]) {
		fail("not_found", "Webhook not found")
	}
	return h
}

func (e *Execution) WebhookTool(tool string, a, t D) D {
	n := integer(t["n"])
	dry := boolean(a["dry_run"])
	switch tool {
	case "webhook_list":
		out := []any{}
		for _, h := range e.S.Objects("webhooks", n) {
			out = append(out, publicWebhook(h))
		}
		return D{"webhooks": out, "event_types": eventTypes}
	case "webhook_add":
		checkWebhookURL(str(a["url"]))
		types := []any{}
		for _, v := range arr(a["types"]) {
			if !contains(eventTypes, str(v)) {
				fail("invalid", "Unknown event type", D{"event_types": eventTypes, "recovery": "revise_request"})
			}
			if !contains(types, v) {
				types = append(types, v)
			}
		}
		if len(e.S.Objects("webhooks", n)) >= maxWebhooks {
			fail("conflict", "A tenant has at most 10 webhooks; remove one first")
		}
		if envAEAD(e.P.Config.ServiceEnvKey) == nil {
			fail("unavailable", "Webhooks need service_env_key on this platform")
		}
		id := "wh_" + randomID()[:16]
		h := D{"id": id, "tenant_n": n, "url": a["url"], "types": types, "created_at": now(), "cursor": e.S.lastEvent(n)}
		if dry {
			return D{"dry_run": true, "webhook": publicWebhook(h)}
		}
		secret := newWebhookSecret()
		h["secret"] = e.P.sealValue("webhook:"+id, secret)
		e.Put("webhooks", id, n, h)
		return D{"dry_run": false, "webhook": publicWebhook(h), "secret": secret,
			"verify": "Each delivery carries webhook-id, webhook-timestamp and webhook-signature (Standard Webhooks, https://www.standardwebhooks.com): check v1 = base64(HMAC-SHA256(base64-decoded secret after whsec_, id.timestamp.body)). The secret is shown once."}
	case "webhook_remove":
		h := e.Webhook(t, a["webhook"])
		if !dry {
			e.S.Remove("webhooks", h["id"])
		}
		return D{"dry_run": dry, "removed": h["id"]}
	case "webhook_rotate":
		h := e.Webhook(t, a["webhook"])
		if dry {
			return D{"dry_run": true, "webhook": publicWebhook(h)}
		}
		var current string
		e.P.openValue("webhook:"+str(h["id"]), str(h["secret"]), &current)
		secret := newWebhookSecret()
		h["previous_secret"] = e.P.sealValue("webhook:"+str(h["id"])+"#previous", current)
		h["previous_until"] = now() + webhookOverlap.Seconds()
		h["secret"] = e.P.sealValue("webhook:"+str(h["id"]), secret)
		h["rotated_at"] = now()
		e.Put("webhooks", h["id"], n, h)
		return D{"dry_run": false, "webhook": publicWebhook(h), "secret": secret, "previous_valid_until": eventTime(h["previous_until"])}
	case "webhook_test":
		h := e.Webhook(t, a["webhook"])
		event := D{"id": "evt_test_" + randomID()[:12], "type": "webhook.test", "timestamp": eventTime(now()), "tenant": t["slug"], "data": D{"webhook": h["id"]}}
		ctx, cancel := context.WithTimeout(e.Ctx, webhookTimeout+2*time.Second)
		defer cancel()
		status, err := e.P.send(ctx, h, event)
		out := D{"webhook": h["id"], "event": event["id"], "status": status, "delivered": err == nil && status >= 200 && status < 300}
		if err != nil {
			out["error"] = webhookError(err)
		}
		return out
	}
	fail("invalid", "Unknown tool")
	return nil
}

// webhookError says why a delivery failed without the resolver's details.
func webhookError(err error) string {
	switch {
	case errors.Is(err, errWebhookAddress):
		return "the URL resolves to an address that is not public"
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "Timeout"):
		return "no answer within 10 seconds"
	}
	return "the endpoint could not be reached"
}

// deliverWebhooks runs until ctx ends: each endpoint gets its tenant's
// events in order, one at a time, retried with webhookBackoff.
func (p *Platform) deliverWebhooks(ctx context.Context) {
	for ctx.Err() == nil {
		wake := p.events.changed()
		_ = attempt(func() { p.deliverPass(ctx) })
		select {
		case <-ctx.Done():
		case <-wake:
		case <-time.After(15 * time.Second):
		}
	}
}

func (p *Platform) deliverPass(ctx context.Context) {
	slugs := map[int]string{}
	for _, t := range p.Store.Tenants() {
		if t["status"] == "active" {
			slugs[integer(t["n"])] = str(t["slug"])
		}
	}
	for _, h := range p.Store.Objects("webhooks") {
		if ctx.Err() != nil {
			return
		}
		// A suspended tenant sends nothing; its events wait.
		if num(h["next_attempt_at"]) > now() || slugs[integer(h["tenant_n"])] == "" {
			continue
		}
		// One endpoint that cannot be served, such as a secret no key
		// opens, must not stop the others.
		if err := attempt(func() { p.deliverTo(ctx, h, slugs) }); err != nil {
			slog.Warn("webhook_delivery_failed", "webhook", h["id"], "error", describe(err))
		}
	}
}

// deliverTo sends one endpoint its waiting events, for at most
// webhookPassBudget, so a slow endpoint delays the others by little.
func (p *Platform) deliverTo(ctx context.Context, h D, slugs map[int]string) {
	started := time.Now()
	n, id := integer(h["tenant_n"]), str(h["id"])
	cursor := int64(integer(h["cursor"]))
	for range webhookBatch {
		if time.Since(started) > webhookPassBudget {
			break
		}
		// Read the record again before each send: a removal stops the
		// next delivery, and a rotation signs it with the new secret.
		if h = p.Store.Get("webhooks", id); h == nil {
			break
		}
		// Once the overlap is over, the previous secret is of no use.
		if str(h["previous_secret"]) != "" && num(h["previous_until"]) <= now() {
			p.saveDelivery(h, D{"previous_secret": "", "previous_until": 0})
		}
		cursor = int64(integer(h["cursor"]))
		rows := p.Store.eventsAfter(n, cursor, 1)
		if len(rows) == 0 {
			break
		}
		row := rows[0]
		eid := int64(integer(row["id"]))
		if types := arr(h["types"]); len(types) > 0 && !contains(types, row["type"]) {
			cursor = eid
			p.saveDelivery(h, D{"cursor": eid})
			continue
		}
		event := publicEvent(row, slugs[n])
		status, err := p.send(ctx, h, event)
		delivery := D{"event": event["id"], "status": status, "at": now()}
		if err == nil && status >= 200 && status < 300 {
			cursor = eid
			p.saveDelivery(h, D{"cursor": eid, "attempts": 0, "next_attempt_at": 0, "last_delivery": delivery})
			continue
		}
		if err != nil {
			delivery["error"] = webhookError(err)
		}
		attempts := integer(h["attempts"]) + 1
		if attempts >= len(webhookBackoff) {
			delivery["given_up"] = true
			p.saveDelivery(h, D{"cursor": eid, "attempts": 0, "next_attempt_at": 0, "last_delivery": delivery})
			slog.Warn("webhook_gave_up", "webhook", h["id"], "event", event["id"])
			cursor = eid
			continue
		}
		p.saveDelivery(h, D{"attempts": attempts, "next_attempt_at": now() + webhookBackoff[attempts].Seconds(), "last_delivery": delivery})
		break
	}
}

// saveDelivery writes the delivery fields into the endpoint's record, as
// it is now: a removal or rotation in the meantime wins.
func (p *Platform) saveDelivery(h D, fields D) {
	p.writer.Lock()
	defer p.writer.Unlock()
	current := p.Store.Get("webhooks", str(h["id"]))
	if current == nil {
		return
	}
	for k, v := range fields {
		current[k], h[k] = v, v
	}
	p.Store.Put("webhooks", current["id"], integer(current["tenant_n"]), current)
}

// eventStream serves GET /v1/events: the tenant's events as server-sent
// events, from Last-Event-ID (or ?after) on, then each new one as it is
// written. Without either, it starts at the newest event.
func (a *App) eventStream(origin string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		who, ok := a.bearerMember(w, r, origin, "/mcp")
		if !ok {
			return
		}
		p := a.Platform
		var t D
		if err := attempt(func() { t = p.execution(r.Context()).Tenant(who, r.URL.Query().Get("tenant")) }); err != nil {
			writeToolResult(w, failureResult(err))
			return
		}
		n := integer(t["n"])
		after := p.Store.lastEvent(n)
		for _, v := range []string{r.Header.Get("Last-Event-ID"), r.URL.Query().Get("after")} {
			if v == "" {
				continue
			}
			parsed, err := strconv.ParseInt(strings.TrimPrefix(v, "evt_"), 10, 64)
			if err != nil || parsed < 0 {
				jsonResponse(w, 400, D{"ok": false, "error": D{"code": "invalid", "message": "Last-Event-ID must be an event id"}})
				return
			}
			after = parsed
			break
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			jsonResponse(w, 500, D{"ok": false, "error": D{"code": "internal", "message": "Streaming is not available"}})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(200)
		flusher.Flush()
		end := time.After(streamLife(who, time.Now()))
		recheck := time.NewTicker(eventStreamRecheck)
		defer recheck.Stop()
		for {
			wake := p.events.changed()
			for _, row := range p.Store.eventsAfter(n, after, 100) {
				after = int64(integer(row["id"]))
				fmt.Fprintf(w, "id: evt_%d\nevent: %s\ndata: %s\n\n", after, row["type"], encoded(publicEvent(row, str(t["slug"]))))
			}
			flusher.Flush()
			select {
			case <-wake:
			case <-time.After(25 * time.Second):
				fmt.Fprint(w, ": keepalive\n\n")
			case <-recheck.C:
				// A deleted or renamed tenant ends the stream; a member removed
				// from a project loses it when the token expires (streamLife).
				if err := attempt(func() { p.execution(r.Context()).Tenant(who, str(t["slug"])) }); err != nil {
					return
				}
			case <-r.Context().Done():
				return
			case <-end:
				return
			}
		}
	}
}

// streamLife is how long an event stream may stay open: eventStreamLife, or
// less when the member's access token expires sooner. Carrel has no server
// side membership list, so the token's end is when a removal from a project
// takes effect; the client reconnects with a fresh token.
func streamLife(who D, now time.Time) time.Duration {
	life := eventStreamLife
	if exp, ok := who["exp"].(int64); ok {
		life = min(life, max(time.Unix(exp, 0).Sub(now), 0))
	}
	return life
}
