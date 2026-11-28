package carrel

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// service_logs asks the service's host for the tail of its log. carrel
// never connects to a host, so the request waits until the host's agent
// collects it (GET /services/v1/agent/logs) and posts the answer. Nothing
// is stored here: the host keeps the last 10 MB of each service's output.

// serviceLogWait bounds how long service_logs waits for the host.
var serviceLogWait = 15 * time.Second

const (
	serviceLogDefault = 64 << 10
	serviceLogMax     = 1 << 20
	// JSON writes a control character as six bytes.
	maxServiceLogReply = 6*serviceLogMax + 64<<10
)

type serviceLogAsk struct {
	host   string
	req    D
	answer chan D
}

// serviceLogs holds the requests no agent has collected or answered yet.
type serviceLogs struct {
	mu      sync.Mutex
	waiting map[string][]*serviceLogAsk // by host, not yet collected
	asked   map[string]*serviceLogAsk   // by request id, until answered
	wake    map[string]chan struct{}    // by host, closed on a new request
}

func (l *serviceLogs) init() {
	if l.waiting == nil {
		l.waiting, l.asked, l.wake = map[string][]*serviceLogAsk{}, map[string]*serviceLogAsk{}, map[string]chan struct{}{}
	}
}

func (l *serviceLogs) wakeOf(host string) chan struct{} {
	c := l.wake[host]
	if c == nil {
		c = make(chan struct{})
		l.wake[host] = c
	}
	return c
}

// ask hands req to host's agent and waits for its answer.
func (l *serviceLogs) ask(ctx context.Context, host string, req D) (D, bool) {
	ask := &serviceLogAsk{host: host, req: req, answer: make(chan D, 1)}
	l.mu.Lock()
	l.init()
	l.waiting[host] = append(l.waiting[host], ask)
	l.asked[str(req["id"])] = ask
	close(l.wakeOf(host))
	delete(l.wake, host)
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		delete(l.asked, str(req["id"]))
		// A new slice: compacting in place would keep the removed asks
		// reachable through the old array.
		var kept []*serviceLogAsk
		for _, a := range l.waiting[host] {
			if a != ask {
				kept = append(kept, a)
			}
		}
		if len(kept) == 0 {
			delete(l.waiting, host)
		} else {
			l.waiting[host] = kept
		}
		l.mu.Unlock()
	}()
	timer := time.NewTimer(serviceLogWait)
	defer timer.Stop()
	select {
	case answer := <-ask.answer:
		return answer, true
	case <-timer.C:
	case <-ctx.Done():
	}
	return nil, false
}

// collect returns host's waiting requests, waiting up to wait for one.
func (l *serviceLogs) collect(ctx context.Context, host string, wait time.Duration) []D {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		l.mu.Lock()
		l.init()
		if pending := l.waiting[host]; len(pending) > 0 {
			delete(l.waiting, host)
			l.mu.Unlock()
			out := []D{}
			for _, a := range pending {
				out = append(out, a.req)
			}
			return out
		}
		wake := l.wakeOf(host)
		l.mu.Unlock()
		select {
		case <-wake:
		case <-timer.C:
			return []D{}
		case <-ctx.Done():
			return []D{}
		}
	}
}

// answer delivers an agent's reply. A host answers only its own requests.
func (l *serviceLogs) answer(host string, reply D) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.init()
	ask := l.asked[str(reply["id"])]
	if ask == nil || ask.host != host {
		return // late, or not this host's: dropped
	}
	delete(l.asked, str(reply["id"]))
	select {
	case ask.answer <- reply:
	default:
	}
}

// ServiceLogRequests long-polls for the log requests of the calling host.
func (p *Platform) ServiceLogRequests(ctx context.Context, token, source string) D {
	host := p.serviceHostOf(token, source)
	return D{"requests": p.fnLogs.collect(ctx, host.Name, serviceAgentWait)}
}

// ServiceLogAnswer takes a host's reply to one request.
func (p *Platform) ServiceLogAnswer(token, source string, reply D) D {
	host := p.serviceHostOf(token, source)
	p.fnLogs.answer(host.Name, reply)
	return D{}
}

func (e *Execution) serviceLogs(f D, a D) D {
	var host *ServiceHostConfig
	for _, h := range e.P.Config.ServiceHosts {
		if h.Name == str(f["host"]) {
			host = &h
			break
		}
	}
	if host == nil {
		fail("unavailable", "The service's host is not configured")
	}
	limit := intAt(a, "max_bytes", serviceLogDefault)
	if limit < 1 || limit > serviceLogMax {
		fail("invalid", "max_bytes must be between 1 and 1048576")
	}
	req := D{"id": randomID(), "service": serviceHostID(integer(f["tenant_n"]), str(f["name"])), "build": boolean(a["build"]), "max_bytes": limit}
	if s := intAt(a, "since_seconds", 0); s > 0 {
		req["since"] = time.Now().Unix() - int64(s)
	}
	answer, ok := e.P.fnLogs.ask(e.Ctx, host.Name, req)
	if !ok {
		fail("unavailable", "The service's host did not answer; try again in a minute", D{"retryable": true})
	}
	if msg := str(answer["error"]); msg != "" {
		// The host's error can name paths on the host: it goes to the log,
		// not to the member.
		slog.Warn("service_log_read_failed", "service", f["id"], "host", host.Name, "detail", truncate(msg, 300))
		fail("unavailable", "The service's host could not read the log")
	}
	text := str(answer["text"])
	if len(text) > limit {
		text = strings.ToValidUTF8(text[len(text)-limit:], "")
	}
	return D{"service": f["name"], "build": req["build"], "log": text, "truncated": boolean(answer["truncated"])}
}
