package carrel

import (
	"context"
	"strings"
	"sync"
	"time"
)

// function_logs asks the function's host for the tail of its log. carrel
// never connects to a host, so the request waits until the host's agent
// collects it (GET /functions/v1/agent/logs) and posts the answer. Nothing
// is stored here: the host keeps the last 10 MB of each function's output.

// functionLogWait bounds how long function_logs waits for the host.
var functionLogWait = 15 * time.Second

const (
	functionLogDefault  = 64 << 10
	functionLogMax      = 1 << 20
	maxFunctionLogReply = functionLogMax + 64<<10
)

type functionLogAsk struct {
	host   string
	req    D
	answer chan D
}

// functionLogs holds the requests no agent has collected or answered yet.
type functionLogs struct {
	mu      sync.Mutex
	waiting map[string][]*functionLogAsk // by host, not yet collected
	asked   map[string]*functionLogAsk   // by request id, until answered
	wake    map[string]chan struct{}     // by host, closed on a new request
}

func (l *functionLogs) init() {
	if l.waiting == nil {
		l.waiting, l.asked, l.wake = map[string][]*functionLogAsk{}, map[string]*functionLogAsk{}, map[string]chan struct{}{}
	}
}

func (l *functionLogs) wakeOf(host string) chan struct{} {
	c := l.wake[host]
	if c == nil {
		c = make(chan struct{})
		l.wake[host] = c
	}
	return c
}

// ask hands req to host's agent and waits for its answer.
func (l *functionLogs) ask(ctx context.Context, host string, req D) (D, bool) {
	ask := &functionLogAsk{host: host, req: req, answer: make(chan D, 1)}
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
		kept := l.waiting[host][:0]
		for _, a := range l.waiting[host] {
			if a != ask {
				kept = append(kept, a)
			}
		}
		l.waiting[host] = kept
		l.mu.Unlock()
	}()
	timer := time.NewTimer(functionLogWait)
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
func (l *functionLogs) collect(ctx context.Context, host string, wait time.Duration) []D {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		l.mu.Lock()
		l.init()
		if pending := l.waiting[host]; len(pending) > 0 {
			l.waiting[host] = nil
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
func (l *functionLogs) answer(host string, reply D) {
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

// FunctionLogRequests long-polls for the log requests of the calling host.
func (p *Platform) FunctionLogRequests(ctx context.Context, token, source string) D {
	host := p.functionHostOf(token, source)
	return D{"requests": p.fnLogs.collect(ctx, host.Name, functionAgentWait)}
}

// FunctionLogAnswer takes a host's reply to one request.
func (p *Platform) FunctionLogAnswer(token, source string, reply D) D {
	host := p.functionHostOf(token, source)
	p.fnLogs.answer(host.Name, reply)
	return D{}
}

func (e *Execution) functionLogs(f D, a D) D {
	var host *FunctionHostConfig
	for _, h := range e.P.Config.FunctionHosts {
		if h.Name == str(f["host"]) {
			host = &h
			break
		}
	}
	if host == nil {
		fail("unavailable", "The function's host is not configured")
	}
	limit := intAt(a, "max_bytes", functionLogDefault)
	if limit < 1 || limit > functionLogMax {
		fail("invalid", "max_bytes must be between 1 and 1048576")
	}
	req := D{"id": randomID(), "function": functionHostID(integer(f["tenant_n"]), str(f["name"])), "build": boolean(a["build"]), "max_bytes": limit}
	if s := intAt(a, "since_seconds", 0); s > 0 {
		req["since"] = time.Now().Unix() - int64(s)
	}
	answer, ok := e.P.fnLogs.ask(e.Ctx, host.Name, req)
	if !ok {
		fail("unavailable", "The function's host did not answer; try again in a minute", D{"retryable": true})
	}
	if msg := str(answer["error"]); msg != "" {
		fail("unavailable", "The function's host could not read the log", D{"detail": truncate(msg, 300)})
	}
	text := str(answer["text"])
	if len(text) > limit {
		text = strings.ToValidUTF8(text[len(text)-limit:], "")
	}
	return D{"function": f["name"], "build": req["build"], "log": text, "truncated": boolean(answer["truncated"])}
}
