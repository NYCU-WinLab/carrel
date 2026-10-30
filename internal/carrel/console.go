package carrel

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// The browser console (PLAN 7.8): machine_console_url gives a single-use
// link valid for 15 minutes. Opening it needs a WinLab login as the member
// who asked for it, so a forwarded link is useless to anyone else. The
// session that follows is a __Host- cookie, and the page talks over a
// WebSocket that the control plane bridges to the machine's node: VNC from
// `qm vncproxy` for a VM installed from an ISO, the serial port through
// socat for a cloud image (its VGA is serial0). Every link and every
// opening is audited.

const (
	consoleLinkTTL    = 15 * 60
	consoleSessionTTL = 3600
	// noVNC v1.6.0, pinned to its commit so the tag cannot move under it.
	novnc = "https://cdn.jsdelivr.net/gh/novnc/noVNC@a8dfd6a3ea3c74244f5ebdaa5a7f1023007a7820"
	xterm = "https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0"
	// The files of that release, checked by the browser (issue #122).
	xtermJS  = "sha384-M169f14mRZOXm3hD/v2Ti0ThIT/RnAQagXA9nlE15yHAtrW19gdePJh/HaTzUOe/"
	xtermCSS = "sha384-8Xk9wy/gzEDUKrXtrmCFa2bBuK3BpjpDuL/p0SeKQX19Khl/M+lHOgD/CyYf7efP"
	// __Host-: no other host under winlab.tw (member sites included) can
	// set or shadow it.
	consoleCookie = "__Host-carrel_console"
	// The login binding of /oauth/authorize and of a console link: also
	// __Host-, so a member's site cannot plant its own (issue #122).
	oauthCookie = "__Host-carrel_oauth"
)

// ConsoleURL makes the link.
func (e *Execution) ConsoleURL(a, w, t D) D {
	n := integer(t["n"])
	m := e.Machine(t, a["machine"])
	if m["kind"] != "vm" {
		fail("invalid", "Only VMs have a browser console")
	}
	if powerState(obj(e.Call(D{"op": "status", "machine": m}))) != "running" {
		fail("conflict", "Start the machine first", D{"recovery": "resolve_prerequisite"})
	}
	if boolean(a["dry_run"]) {
		return D{"dry_run": true, "machine": m["name"]}
	}
	token := random(32)
	expires := now() + consoleLinkTTL
	e.S.Put("consoles", digest(token), n, D{"id": digest(token), "tenant_n": n, "vmid": m["vmid"], "sub": w["sub"], "expires": expires})
	origin := strings.TrimRight(e.P.Config.Origin, "/")
	return D{"url": origin + "/console/" + token, "expires_at": expires, "single_use": true, "opens_for": "the WinLab account that asked for it"}
}

// Stream opens a node adapter request that keeps its stdin and stdout for
// a byte stream after the first reply line (the console).
func (b *SSHBackend) Stream(ctx context.Context, request D, target string) (io.ReadWriteCloser, error) {
	cmd := exec.CommandContext(ctx, "ssh", "-F", b.Config, "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3", target)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	stop := func() { in.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() }
	if _, err := in.Write(append(encoded(request), '\n')); err != nil {
		stop()
		return nil, err
	}
	// ReadSlice stops at the buffer: a node cannot make this read unbounded.
	reader := bufio.NewReaderSize(out, 4096)
	line, err := reader.ReadSlice('\n')
	var reply D
	if err != nil || json.Unmarshal(line, &reply) != nil || reply["ok"] != true {
		stop()
		return nil, errors.New("the node did not open the console")
	}
	return &stream{Reader: reader, Writer: in, stop: stop}, nil
}

type stream struct {
	io.Reader
	io.Writer
	stop func()
}

func (s *stream) Close() error { s.stop(); return nil }

// Streamer is a backend that can open a console.
type Streamer interface {
	Stream(context.Context, D, string) (io.ReadWriteCloser, error)
}

type consoleHandler struct {
	p *Platform
	o *OAuth
	// ping overrides the keepalive interval (tests).
	ping time.Duration
}

func (h consoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/console/view" && r.Method == "GET":
		h.view(w, r)
	case r.URL.Path == "/console/ws" && r.Method == "GET":
		h.socket(w, r)
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/console/") && !strings.Contains(r.URL.Path[9:], "/"):
		h.begin(w, r, r.URL.Path[9:])
	default:
		consolePage(w, 404, "找不到這個頁面。")
	}
}

func (h consoleHandler) link(id string) D {
	rec := h.p.Store.Get("consoles", id)
	if rec == nil || boolean(rec["used"]) || num(rec["expires"]) < now() {
		return nil
	}
	return rec
}

// begin sends the browser to Keycloak; the callback comes back through
// /oauth/callback, which hands console logins to finish.
func (h consoleHandler) begin(w http.ResponseWriter, r *http.Request, token string) {
	rec := h.link(digest(token))
	if rec == nil {
		consolePage(w, 404, "這個連結已失效：連結只能用一次，15 分鐘後過期。請重新產生。")
		return
	}
	state, cookie, verifier := random(32), random(32), random(48)
	h.p.Store.OAuthPut("state", state, D{"console": rec["id"], "verifier": verifier, "cookie": digest(cookie)}, 600)
	params := url.Values{"client_id": {h.o.ClientID}, "redirect_uri": {h.o.Origin + "/oauth/callback"}, "response_type": {"code"}, "scope": {strings.Join(scopes, " ")}, "state": {state}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}}
	http.SetCookie(w, &http.Cookie{Name: oauthCookie, Value: cookie, MaxAge: 600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, Path: "/"})
	http.Redirect(w, r, h.o.Issuer+"/protocol/openid-connect/auth?"+params.Encode(), 302)
}

// finish exchanges the code, checks that the member who logged in is the
// one who asked for the link, and starts the console session.
func (h consoleHandler) finish(w http.ResponseWriter, r *http.Request, txn D, code string) {
	body := url.Values{"client_id": {h.o.ClientID}, "grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {str(txn["verifier"])}, "redirect_uri": {h.o.Origin + "/oauth/callback"}}
	tokens, status, err := h.o.upstream(r.Context(), "token", body)
	access, _ := tokens["access_token"].(string)
	if err != nil || status != 200 || access == "" {
		consolePage(w, 503, "登入服務暫時無法使用，請稍後再試。")
		return
	}
	who, err := h.o.Verifier.Verify(r.Context(), access)
	if err != nil {
		consolePage(w, 403, "無法確認你的 WinLab 身分。")
		return
	}
	h.p.writer.Lock()
	defer h.p.writer.Unlock()
	rec := h.link(str(txn["console"]))
	if rec == nil {
		consolePage(w, 404, "這個連結已失效。請重新產生。")
		return
	}
	// Spent by any login, so nobody can try it twice.
	rec["used"] = true
	h.p.Store.Put("consoles", rec["id"], integer(rec["tenant_n"]), rec)
	if rec["sub"] != who["sub"] {
		h.p.Store.Log(str(who["sub"]), rec["tenant_n"], "console_open", D{"vmid": rec["vmid"]}, "forbidden")
		consolePage(w, 403, "這個連結不是給這個帳號的。")
		return
	}
	session := random(32)
	h.p.Store.OAuthPut("console", digest(session), D{"tenant_n": rec["tenant_n"], "vmid": rec["vmid"], "sub": rec["sub"], "ticket": vncTicket()}, consoleSessionTTL)
	h.p.Store.Log(str(who["sub"]), rec["tenant_n"], "console_open", D{"vmid": rec["vmid"]}, "ok")
	http.SetCookie(w, &http.Cookie{Name: consoleCookie, Value: session, MaxAge: consoleSessionTTL, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, Path: "/"})
	http.Redirect(w, r, "/console/view", 302)
}

func (h consoleHandler) session(r *http.Request) D {
	c, err := r.Cookie(consoleCookie)
	if err != nil || len(c.Value) > 200 {
		return nil
	}
	return h.p.Store.OAuthGet("console", digest(c.Value))
}

func (h consoleHandler) view(w http.ResponseWriter, r *http.Request) {
	s := h.session(r)
	if s == nil {
		consolePage(w, 403, "主控台工作階段已結束。請重新產生連結。")
		return
	}
	m := h.p.Store.Get("machines", str(s["vmid"]))
	if m == nil {
		consolePage(w, 404, "這台機器已不存在。")
		return
	}
	nonce := random(16)
	// Only the two pinned releases on the CDN, not the whole CDN.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"' "+novnc+"/ "+xterm+"/lib/; style-src 'unsafe-inline' "+xterm+"/css/; connect-src 'self'; img-src data: blob:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// json.Marshal escapes <, > and &, so the value cannot close the script.
	config := map[string]string{"name": str(m["name"])}
	if unmanaged(m) {
		// Only VNC uses the ticket; the serial page does not carry it.
		config["ticket"] = str(s["ticket"])
	}
	data, _ := json.Marshal(config)
	name := html.EscapeString(str(m["name"]))
	head := `<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><title>` + name + ` · Carrel</title><style>html,body{margin:0;height:100%;background:#111;color:#eee;font:14px system-ui}#bar{height:32px;line-height:32px;padding:0 12px}#screen{height:calc(100% - 32px)}</style>`
	if unmanaged(m) {
		integrity := map[string]string{}
		for path, sum := range novncIntegrity {
			integrity[novnc+path] = sum
		}
		imports, _ := json.Marshal(map[string]any{"integrity": integrity})
		fmt.Fprintf(w, `%s<script type="importmap" nonce="%s">%s</script></head><body><div id="bar">%s</div><div id="screen"></div><script type="module" nonce="%s">
import RFB from "%s/core/rfb.js";
const config = %s;
const bar = document.getElementById("bar");
const rfb = new RFB(document.getElementById("screen"), "wss://" + location.host + "/console/ws", {wsProtocols: ["binary"], credentials: {password: config.ticket}});
rfb.scaleViewport = true;
rfb.addEventListener("disconnect", () => { bar.textContent = config.name + "：已中斷，重新整理可再連線"; });
</script></body></html>`, head, nonce, imports, name, nonce, novnc, data)
		return
	}
	fmt.Fprintf(w, `%s<link rel="stylesheet" href="%s/css/xterm.css" integrity="%s" crossorigin="anonymous"></head><body><div id="bar">%s：序列埠主控台，看開機訊息與救援用；登入要有密碼的帳號，SSH 金鑰在這裡不能用。一次只能開一個分頁。</div><div id="screen"></div><script src="%s/lib/xterm.js" integrity="%s" crossorigin="anonymous" nonce="%s"></script><script nonce="%s">
const config = %s;
const bar = document.getElementById("bar");
const term = new Terminal({scrollback: 5000});
term.open(document.getElementById("screen"));
const ws = new WebSocket("wss://" + location.host + "/console/ws", ["binary"]);
ws.binaryType = "arraybuffer";
const encoder = new TextEncoder();
ws.onmessage = (e) => term.write(new Uint8Array(e.data));
ws.onclose = (e) => { bar.textContent = config.name + "：" + (e.reason === "busy" ? "另一個分頁正在使用序列埠，先關掉它" : "已中斷，重新整理可再連線"); };
term.onData((d) => { if (ws.readyState === 1) ws.send(encoder.encode(d)); });
term.focus();
</script></body></html>`, head, xterm, xtermCSS, name, xterm, xtermJS, nonce, nonce, data)
}

func (h consoleHandler) socket(w http.ResponseWriter, r *http.Request) {
	s := h.session(r)
	// Same origin only: a page elsewhere must not drive this console with
	// the member's cookie.
	if s == nil || r.Header.Get("Origin") != h.o.Origin {
		w.WriteHeader(403)
		return
	}
	m := h.p.Store.Get("machines", str(s["vmid"]))
	streamer, ok := h.p.Backend.(Streamer)
	if m == nil || integer(m["tenant_n"]) != integer(s["tenant_n"]) || !ok {
		w.WriteHeader(404)
		return
	}
	node, found := h.p.lookupNode(m)
	if !found {
		w.WriteHeader(503)
		return
	}
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"binary"}, InsecureSkipVerify: true})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), consoleSessionTTL*time.Second)
	defer cancel()
	request := D{"op": "console", "machine": m, "mode": "serial"}
	if unmanaged(m) {
		request["mode"], request["ticket"] = "vnc", s["ticket"]
	} else {
		// QEMU's serial socket takes one client: a 2nd tab would hang.
		if _, busy := serialInUse.LoadOrStore(str(m["vmid"]), true); busy {
			c.Close(websocket.StatusTryAgainLater, "busy")
			return
		}
		defer serialInUse.Delete(str(m["vmid"]))
	}
	vnc, err := streamer.Stream(ctx, request, node.Target)
	if err != nil {
		c.Close(websocket.StatusInternalError, "console unavailable")
		return
	}
	defer vnc.Close()
	conn := websocket.NetConn(ctx, c, websocket.MessageBinary)
	defer conn.Close()
	done := make(chan struct{}, 3)
	go func() { _, _ = io.Copy(conn, vnc); done <- struct{}{} }()
	go func() { _, _ = io.Copy(vnc, conn); done <- struct{}{} }()
	// A tab that vanished (sleep, a network change) answers no ping: the
	// session ends within a minute and frees the serial port (issue #130).
	go func() { keepAlive(ctx, c, h.pingEvery()); done <- struct{}{} }()
	<-done
}

// pingEvery is how often the console socket checks that the browser is there.
func (h consoleHandler) pingEvery() time.Duration {
	if h.ping > 0 {
		return h.ping
	}
	return 30 * time.Second
}

func keepAlive(ctx context.Context, c *websocket.Conn, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ping, cancel := context.WithTimeout(ctx, every)
			err := c.Ping(ping)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

// serialInUse holds the VMs whose serial console is open in this process.
var serialInUse sync.Map

func consolePage(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Carrel 主控台</title><style>%s</style></head><body><header><span>WinLab</span><span aria-hidden="true">/</span><span>Carrel</span></header><main><p>%s</p></main></body></html>`, consentStyle, html.EscapeString(message))
}

// vncTicket is one session's VNC password: qm vncproxy sets it on the VM
// for 30 seconds, and VNC reads only 8 characters.
func vncTicket() string {
	const letters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	b := []byte(random(8))
	for i := range b[:8] {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b[:8])
}
