package carrel

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/coder/websocket"
)

type streamBackend struct {
	*fakeBackend
	opened []D
}

// Stream answers like `qm vncproxy` would: an echo of what the browser sends.
func (s *streamBackend) Stream(_ context.Context, r D, _ string) (io.ReadWriteCloser, error) {
	s.opened = append(s.opened, r)
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
	console := consoleHandler{p: p, o: oauth}
	oauth.Console = console.finish
	mux := http.NewServeMux()
	mux.Handle("/oauth/", oauth)
	mux.Handle("/console/", console)
	srv.Config.Handler = mux
	srv.Start()
	defer srv.Close()
	p.Config["origin"] = origin
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
	view, err := client.Get(origin + "/console/view")
	must(err)
	if body, _ := io.ReadAll(view.Body); view.StatusCode != 200 || !strings.Contains(string(body), "core/rfb.js") {
		t.Fatal(view.StatusCode)
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
	if err != nil || string(got) != "RFB" || len(backend.opened) != 1 || backend.opened[0]["op"] != "console" {
		t.Fatal("console not bridged", err, string(got))
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
