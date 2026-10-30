package carrel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type streamBackend struct {
	*fakeBackend
	mu     sync.Mutex
	opened []D
}

func (s *streamBackend) last() D {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opened[len(s.opened)-1]
}

// Stream answers like `qm vncproxy` would: an echo of what the browser sends.
func (s *streamBackend) Stream(_ context.Context, r D, _ string) (io.ReadWriteCloser, error) {
	s.mu.Lock()
	s.opened = append(s.opened, r)
	s.mu.Unlock()
	a, b := net.Pipe()
	go func() { _, _ = io.Copy(b, b) }()
	return a, nil
}

type tokenVerifier struct{}

func (tokenVerifier) Verify(_ context.Context, token string) (D, error) {
	return D{"sub": strings.TrimPrefix(token, "token-"), "username": "x"}, nil
}

func TestTheConsoleOpensOnlyForTheMemberWhoAskedOnce(t *testing.T) {
	p, b := fixture(t)
	b.call = func(r D, _ string) (any, error) { return D{"status": "running"}, nil }
	backend := &streamBackend{fakeBackend: b}
	p.Backend = backend
	login := "alice"
	keycloak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, D{"access_token": "token-" + login})
	}))
	defer keycloak.Close()
	srv := httptest.NewUnstartedServer(nil)
	origin := "http://" + srv.Listener.Addr().String()
	oauth := &OAuth{Store: p.Store, Origin: origin, Issuer: keycloak.URL, ClientID: "carrel-mcp", Verifier: tokenVerifier{}, HTTP: keycloak.Client()}
	console := consoleHandler{p: p, o: oauth, ping: 100 * time.Millisecond}
	oauth.Console = console.finish
	mux := http.NewServeMux()
	mux.Handle("/oauth/", oauth)
	mux.Handle("/console/", console)
	srv.Config.Handler = mux
	srv.Start()
	defer srv.Close()
	p.Config.Origin = origin
	seedMachine(p, "web", 10100)
	e := p.execution(context.Background())
	link := str(e.ConsoleURL(D{"machine": "web"}, D{"sub": "alice"}, p.Store.TenantN(1))["url"])

	jar := newJar()
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	open := func(link string) *http.Response {
		r, err := client.Get(link)
		must(err)
		if r.StatusCode != 302 {
			return r
		}
		to, _ := url.Parse(r.Header.Get("Location"))
		callback := origin + "/oauth/callback?" + url.Values{"state": {to.Query().Get("state")}, "code": {"c"}, "iss": {keycloak.URL}}.Encode()
		r, err = client.Get(callback)
		must(err)
		return r
	}
	// Someone else who got the link cannot use it, and it is then spent.
	login = "mallory"
	if r := open(link); r.StatusCode != 403 {
		t.Fatal("another member opened the console", r.StatusCode)
	}
	link = str(e.ConsoleURL(D{"machine": "web"}, D{"sub": "alice"}, p.Store.TenantN(1))["url"])
	login = "alice"
	if r := open(link); r.StatusCode != 302 || r.Header.Get("Location") != "/console/view" {
		t.Fatal("the member could not log in", r.StatusCode)
	}
	if r := open(link); r.StatusCode != 404 {
		t.Fatal("a link worked twice", r.StatusCode)
	}
	page := func() string {
		view, err := client.Get(origin + "/console/view")
		must(err)
		body, _ := io.ReadAll(view.Body)
		// The page's own scripts carry the nonce that the policy allows.
		nonce := strings.Split(strings.Split(view.Header.Get("Content-Security-Policy"), "'nonce-")[1], "'")[0]
		if view.StatusCode != 200 || strings.Count(string(body), `nonce="`+nonce+`"`) == 0 {
			t.Fatal(view.StatusCode)
		}
		// Scripts from the two pinned releases only, not the whole CDN.
		if csp := view.Header.Get("Content-Security-Policy"); strings.Contains(csp, "https://cdn.jsdelivr.net ") || !strings.Contains(csp, novnc+"/") {
			t.Fatal(csp)
		}
		return string(body)
	}
	// A cloud image has no screen: its serial port, in a terminal.
	if body := page(); !strings.Contains(body, "lib/xterm.js") || strings.Contains(body, "rfb.js") || strings.Contains(body, "ticket") || !strings.Contains(body, `integrity="`+xtermJS+`"`) {
		t.Fatal("a cloud image got no serial terminal, or the page carries the VNC ticket")
	}
	if cs := jar.Cookies(must2(url.Parse(origin + "/"))); !strings.Contains(fmt.Sprint(cs), "__Host-carrel_console") {
		t.Fatal("the session cookie is not host-only", cs)
	}
	header := http.Header{}
	for _, c := range jar.Cookies(must2(url.Parse(origin + "/console/ws"))) {
		header.Add("Cookie", c.String())
	}
	wsURL := "ws" + strings.TrimPrefix(origin, "http") + "/console/ws"
	// Another site's page cannot drive the console with the member's cookie.
	evil := header.Clone()
	evil.Set("Origin", "https://evil.example")
	if _, _, err := websocket.Dial(context.Background(), wsURL, &websocket.DialOptions{HTTPHeader: evil}); err == nil {
		t.Fatal("cross-site socket accepted")
	}
	header.Set("Origin", origin)
	c, _, err := websocket.Dial(context.Background(), wsURL, &websocket.DialOptions{HTTPHeader: header, Subprotocols: []string{"binary"}})
	must(err)
	defer c.CloseNow()
	must(c.Write(context.Background(), websocket.MessageBinary, []byte("RFB")))
	_, got, err := c.Read(context.Background())
	if err != nil || string(got) != "RFB" || backend.last()["op"] != "console" || backend.last()["mode"] != "serial" {
		t.Fatal("console not bridged", err, string(got))
	}
	// The serial port takes one client: a 2nd tab is told so.
	second, _, err := websocket.Dial(context.Background(), wsURL, &websocket.DialOptions{HTTPHeader: header, Subprotocols: []string{"binary"}})
	must(err)
	if _, _, err := second.Read(context.Background()); websocket.CloseStatus(err) != websocket.StatusTryAgainLater {
		t.Fatal("a 2nd serial session opened", err)
	}
	c.Close(websocket.StatusNormalClosure, "")
	// The port is free again once a session ends (issue #130), also when
	// the tab vanished without closing: it answers no ping.
	reopen := func() *websocket.Conn {
		for range 50 {
			next, _, err := websocket.Dial(context.Background(), wsURL, &websocket.DialOptions{HTTPHeader: header, Subprotocols: []string{"binary"}})
			must(err)
			must(next.Write(context.Background(), websocket.MessageBinary, []byte("hi")))
			read, cancel := context.WithTimeout(context.Background(), time.Second)
			_, got, err := next.Read(read)
			cancel()
			if err == nil && string(got) == "hi" {
				return next
			}
			next.CloseNow()
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("the serial port stayed taken")
		return nil
	}
	gone := reopen()
	// gone stops reading: its pings go unanswered.
	time.Sleep(400 * time.Millisecond)
	reopen().Close(websocket.StatusNormalClosure, "")
	gone.CloseNow()
	// A machine installed from an ISO: its screen over VNC, with the
	// session's password on both ends.
	m := p.Store.Get("machines", "10100")
	m["guest_management"] = 0
	p.Store.Put("machines", "10100", 1, m)
	body := page()
	c, _, err = websocket.Dial(context.Background(), wsURL, &websocket.DialOptions{HTTPHeader: header, Subprotocols: []string{"binary"}})
	must(err)
	defer c.CloseNow()
	must(c.Write(context.Background(), websocket.MessageBinary, []byte("RFB")))
	_, _, err = c.Read(context.Background())
	ticket := str(backend.last()["ticket"])
	// Every module of the pinned noVNC is checked by the browser (issue #130).
	if !strings.Contains(body, `"`+novnc+`/core/rfb.js":"`+novncIntegrity["/core/rfb.js"]+`"`) || len(novncIntegrity) < 40 {
		t.Fatal("the VNC page has no import map integrity for noVNC")
	}
	if err != nil || !strings.Contains(body, "core/rfb.js") || backend.last()["mode"] != "vnc" || len(ticket) != 8 || !strings.Contains(body, `"ticket":"`+ticket+`"`) {
		t.Fatal("an ISO machine got no VNC screen", err, backend.last())
	}
	if n := len(p.Store.Rows("SELECT * FROM audit WHERE tool='console_open'")); n != 2 {
		t.Fatal("console openings audited", n)
	}
}

func must2[T any](v T, err error) T { must(err); return v }

type jar struct{ cookies map[string][]*http.Cookie }

func newJar() *jar { return &jar{cookies: map[string][]*http.Cookie{}} }

// SetCookies keeps cookies by name; the test server is plain HTTP, so the
// Secure flag is ignored here.
func (j *jar) SetCookies(u *url.URL, cs []*http.Cookie) {
	for _, c := range cs {
		kept := []*http.Cookie{}
		for _, old := range j.cookies[u.Host] {
			if old.Name != c.Name {
				kept = append(kept, old)
			}
		}
		j.cookies[u.Host] = append(kept, &http.Cookie{Name: c.Name, Value: c.Value, Path: c.Path})
	}
}

func (j *jar) Cookies(u *url.URL) []*http.Cookie {
	out := []*http.Cookie{}
	for _, c := range j.cookies[u.Host] {
		if strings.HasPrefix(u.Path, c.Path) {
			out = append(out, &http.Cookie{Name: c.Name, Value: c.Value})
		}
	}
	return out
}
