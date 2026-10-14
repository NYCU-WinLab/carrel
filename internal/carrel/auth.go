package carrel

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var scopes = []string{"openid", "profile", "email", "offline_access"}

const clientTTL = 86400 * 90

// refreshGrace keeps a rotated refresh token usable for a short window. Several
// client processes can share one stored credential; the one that loses a race
// still holds the previous token and would otherwise be signed out.
// The issued response is held in process memory only (never in the database)
// and is dropped on expiry, revoke or restart.
const refreshGrace = 60 * time.Second

type rotated struct {
	client  string
	tokens  D
	expires time.Time
}

type IdentityVerifier interface {
	Verify(context.Context, string) (D, error)
}
type IssuerUnavailable struct{ error }
type Verifier struct {
	Issuer, Audience string
	JWKS             string
	HTTP             *http.Client
	mu               sync.Mutex
	keys             map[string]*rsa.PublicKey
	loaded           time.Time
}

func NewVerifier(issuer string) *Verifier {
	return &Verifier{Issuer: issuer, Audience: "carrel-mcp", HTTP: &http.Client{Timeout: 8 * time.Second}}
}
func identity(c D) (D, error) {
	groups, ok := c["groups"].([]any)
	if !ok {
		return nil, errors.New("missing groups claim")
	}
	admin, active := false, false
	projects := []string{}
	for _, v := range groups {
		g, ok := v.(string)
		if !ok {
			return nil, errors.New("invalid groups claim")
		}
		g = strings.TrimPrefix(g, "/")
		admin = admin || g == "winlab-admin"
		for _, name := range []string{"112", "113", "114", "115", "master", "doctoral", "undergrad", "assistant", "teacher"} {
			active = active || g == "lab-member/"+name
		}
		if matches(`^winlab-projects/[^/]+$`, g) {
			projects = append(projects, g)
		}
	}
	username, ok := c["preferred_username"].(string)
	if !ok || str(c["sub"]) == "" || (!admin && !active) {
		return nil, errors.New("current lab membership required")
	}
	return D{"sub": c["sub"], "username": username, "admin": admin, "projects": projects}, nil
}
func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if key := v.keys[kid]; key != nil && time.Since(v.loaded) < 300*time.Second {
		return key, nil
	}
	if v.keys[kid] == nil && time.Since(v.loaded) < 5*time.Second {
		return nil, errors.New("unknown signing key")
	}
	jwksURL := v.JWKS
	if jwksURL == "" {
		jwksURL = v.Issuer + "/protocol/openid-connect/certs"
	}
	req, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return nil, err
	}
	r, err := v.HTTP.Do(req)
	if err != nil {
		return nil, IssuerUnavailable{err}
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, IssuerUnavailable{fmt.Errorf("issuer returned %d", r.StatusCode)}
	}
	var jwks struct {
		Keys []struct{ Kid, Kty, N, E, Alg, Use string }
	}
	if err = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&jwks); err != nil {
		return nil, IssuerUnavailable{err}
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || (k.Alg != "" && k.Alg != "RS256") || (k.Use != "" && k.Use != "sig") {
			continue
		}
		n, en := base64.RawURLEncoding.DecodeString(k.N)
		ex, ee := base64.RawURLEncoding.DecodeString(k.E)
		if en != nil || ee != nil || len(ex) > 4 {
			continue
		}
		exponent := 0
		for _, b := range ex {
			exponent = exponent*256 + int(b)
		}
		if exponent < 3 {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}
	}
	v.keys = keys
	v.loaded = time.Now()
	if keys[kid] == nil {
		return nil, errors.New("unknown signing key")
	}
	return keys[kid], nil
}
func (v *Verifier) Verify(ctx context.Context, token string) (D, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) { return v.key(ctx, str(t.Header["kid"])) }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(v.Audience), jwt.WithIssuer(v.Issuer), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(10*time.Second))
	if err != nil {
		return nil, err
	}
	if claims["iat"] == nil || claims["sub"] == nil || claims["azp"] != v.Audience {
		return nil, errors.New("missing identity or wrong authorized party")
	}
	return identity(D(claims))
}

type OAuth struct {
	Store                    *Store
	Origin, Issuer, ClientID string
	Hosted                   []string
	Verifier                 IdentityVerifier
	HTTP                     *http.Client
	locks                    [64]sync.Mutex
	replayMu                 sync.Mutex
	replay                   map[string]rotated
}

// replayed returns the response already issued for a refresh token rotated
// within refreshGrace. Callers hold the client lock, so a racing request waits
// for the rotation to finish before it looks here.
func (o *OAuth) replayed(key, cid string) D {
	o.replayMu.Lock()
	defer o.replayMu.Unlock()
	now := time.Now()
	for k, v := range o.replay {
		if now.After(v.expires) {
			delete(o.replay, k)
		}
	}
	if v, ok := o.replay[key]; ok && v.client == cid {
		return v.tokens
	}
	return nil
}
func (o *OAuth) remember(key, cid string, tokens D) {
	o.replayMu.Lock()
	defer o.replayMu.Unlock()
	if o.replay == nil {
		o.replay = map[string]rotated{}
	}
	o.replay[key] = rotated{client: cid, tokens: tokens, expires: time.Now().Add(refreshGrace)}
}
func (o *OAuth) forget(refresh string) {
	o.replayMu.Lock()
	defer o.replayMu.Unlock()
	delete(o.replay, digest(refresh))
	for k, v := range o.replay {
		if v.tokens["refresh_token"] == refresh {
			delete(o.replay, k)
		}
	}
}

func (o *OAuth) allowedRedirect(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.User != nil || u.Fragment != "" {
		return false
	}
	if contains(o.Hosted, s) {
		return true
	}
	return u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1") && u.Port() != "" && matches(`^[0-9]+$`, u.Port()) && integer(u.Port()) > 0 && integer(u.Port()) <= 65535
}
func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func oauthError(w http.ResponseWriter, code string, status int) {
	w.Header().Set("Cache-Control", "no-store")
	jsonResponse(w, status, D{"error": code})
}
func secureEqual(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func (o *OAuth) upstream(ctx context.Context, path string, values url.Values) (D, int, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", o.Issuer+"/protocol/openid-connect/"+path, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, err := o.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, r.StatusCode, err
	}
	d := D{}
	if len(data) > 0 {
		err = json.Unmarshal(data, &d)
	}
	return d, r.StatusCode, err
}
func (o *OAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if p := recover(); p != nil {
			oauthError(w, "temporarily_unavailable", 503)
		}
	}()
	o.Store.PurgeOAuth()
	path, method := r.URL.Path, r.Method
	resource := o.Origin + "/mcp"
	callback := o.Origin + "/oauth/callback"
	if strings.HasPrefix(path, "/.well-known/oauth-protected-resource") && method == "GET" {
		jsonResponse(w, 200, D{"resource": resource, "authorization_servers": []string{o.Origin}, "scopes_supported": scopes, "bearer_methods_supported": []string{"header"}})
		return
	}
	if (path == "/.well-known/oauth-authorization-server" || path == "/.well-known/openid-configuration") && method == "GET" {
		jsonResponse(w, 200, D{"issuer": o.Origin, "authorization_endpoint": o.Origin + "/oauth/authorize", "token_endpoint": o.Origin + "/oauth/token", "registration_endpoint": o.Origin + "/oauth/register", "revocation_endpoint": o.Origin + "/oauth/revoke", "revocation_endpoint_auth_methods_supported": []string{"none"}, "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"none"}, "authorization_response_iss_parameter_supported": true, "scopes_supported": scopes})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case path == "/oauth/register" && method == "POST":
		o.locks[0].Lock()
		defer o.locks[0].Unlock()
		if integer(o.Store.Rows("SELECT count(*) AS n FROM oauth WHERE kind='client'")[0]["n"]) >= 10000 {
			oauthError(w, "temporarily_unavailable", 503)
			return
		}
		var data D
		if json.NewDecoder(r.Body).Decode(&data) != nil {
			oauthError(w, "invalid_request", 400)
			return
		}
		redirects, ok := data["redirect_uris"].([]any)
		if !ok || len(redirects) < 1 || len(redirects) > 5 {
			oauthError(w, "invalid_redirect_uri", 400)
			return
		}
		for _, u := range redirects {
			value, ok := u.(string)
			if !ok || !o.allowedRedirect(value) {
				oauthError(w, "invalid_redirect_uri", 400)
				return
			}
		}
		if textAt(data, "token_endpoint_auth_method", "none") != "none" {
			oauthError(w, "invalid_client_metadata", 400)
			return
		}
		name := []rune(textAt(data, "client_name", "MCP client"))
		if len(name) > 100 {
			name = name[:100]
		}
		c := D{"client_id": "carrel-" + random(24), "redirect_uris": redirects, "client_name": string(name), "token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}}
		o.Store.OAuthPut("client", str(c["client_id"]), c, clientTTL)
		jsonResponse(w, 201, c)
	case path == "/oauth/authorize" && method == "GET":
		q := r.URL.Query()
		c := o.Store.OAuthGet("client", q.Get("client_id"))
		if c == nil || !contains(c["redirect_uris"], q.Get("redirect_uri")) {
			oauthError(w, "invalid_client", 400)
			return
		}
		res := q.Get("resource")
		if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || !matches(`^[A-Za-z0-9_-]{43}$`, q.Get("code_challenge")) || (res != "" && res != resource) || len(q.Get("state")) > 4096 {
			oauthError(w, "invalid_request", 400)
			return
		}
		state, cookie := random(32), random(32)
		txn := D{"client": c["client_id"], "name": c["client_name"], "redirect": q.Get("redirect_uri"), "state": q.Get("state"), "challenge": q.Get("code_challenge"), "cookie": digest(cookie)}
		o.Store.OAuthPut("state", state, txn, 600)
		params := url.Values{"client_id": {o.ClientID}, "redirect_uri": {callback}, "response_type": {"code"}, "scope": {strings.Join(scopes, " ")}, "state": {state}, "code_challenge": {str(txn["challenge"])}, "code_challenge_method": {"S256"}}
		http.SetCookie(w, &http.Cookie{Name: "carrel_oauth", Value: cookie, MaxAge: 600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, Path: "/oauth"})
		http.Redirect(w, r, o.Issuer+"/protocol/openid-connect/auth?"+params.Encode(), 302)
	case path == "/oauth/callback" && method == "GET":
		q := r.URL.Query()
		txn := o.Store.OAuthPop("state", q.Get("state"))
		cookie, _ := r.Cookie("carrel_oauth")
		value := ""
		if cookie != nil {
			value = cookie.Value
		}
		if txn == nil || !secureEqual(str(txn["cookie"]), digest(value)) || q.Get("iss") != o.Issuer || q.Get("code") == "" || q.Get("error") != "" {
			oauthError(w, "access_denied", 400)
			return
		}
		consent := random(32)
		txn["code"] = q.Get("code")
		o.Store.OAuthPut("consent", consent, txn, 300)
		consentPage(w, str(txn["name"]), str(txn["redirect"]), consent)
	case path == "/oauth/consent" && method == "POST":
		if r.ParseForm() != nil {
			oauthError(w, "invalid_request", 400)
			return
		}
		txn := o.Store.OAuthPop("consent", r.PostForm.Get("consent"))
		cookie, _ := r.Cookie("carrel_oauth")
		value := ""
		if cookie != nil {
			value = cookie.Value
		}
		if r.Header.Get("Origin") != o.Origin || txn == nil || !secureEqual(str(txn["cookie"]), digest(value)) {
			oauthError(w, "access_denied", 400)
			return
		}
		out := url.Values{"state": {str(txn["state"])}, "iss": {o.Origin}}
		if r.PostForm.Get("allow") == "yes" {
			o.Store.OAuthPut("code", digest(str(txn["code"])), txn, 120)
			out.Set("code", str(txn["code"]))
		} else {
			out.Set("error", "access_denied")
		}
		separator := "?"
		if strings.Contains(str(txn["redirect"]), "?") {
			separator = "&"
		}
		http.Redirect(w, r, str(txn["redirect"])+separator+out.Encode(), 302)
	case (path == "/oauth/token" || path == "/oauth/revoke") && method == "POST":
		if r.ParseForm() != nil {
			oauthError(w, "invalid_request", 400)
			return
		}
		q := r.PostForm
		cid := q.Get("client_id")
		hash := sha256.Sum256([]byte(cid))
		o.locks[int(hash[0])%len(o.locks)].Lock()
		defer o.locks[int(hash[0])%len(o.locks)].Unlock()
		client := o.Store.OAuthGet("client", cid)
		if client == nil {
			oauthError(w, "invalid_client", 400)
			return
		}
		if path == "/oauth/revoke" {
			token := q.Get("token")
			txn := o.Store.OAuthGet("refresh", digest(token))
			if txn != nil && txn["client"] == cid {
				_, status, err := o.upstream(r.Context(), "revoke", url.Values{"client_id": {o.ClientID}, "token": {token}, "token_type_hint": {"refresh_token"}})
				if err != nil || status != 200 {
					oauthError(w, "temporarily_unavailable", 503)
					return
				}
				o.Store.OAuthPop("refresh", digest(token))
			}
			o.forget(token)
			jsonResponse(w, 200, D{})
			return
		}
		o.exchange(w, r, client, resource, callback)
	default:
		oauthError(w, "invalid_request", 404)
	}
}
func (o *OAuth) exchange(w http.ResponseWriter, r *http.Request, client D, resource, callback string) {
	q := r.PostForm
	cid := q.Get("client_id")
	if res, ok := q["resource"]; ok && (len(res) != 1 || res[0] != resource) {
		oauthError(w, "invalid_client", 400)
		return
	}
	grant := q.Get("grant_type")
	body := url.Values{"client_id": {o.ClientID}, "grant_type": {grant}}
	kind, key := "", ""
	var txn D
	switch grant {
	case "authorization_code":
		kind = "code"
		code, verifier := q.Get("code"), q.Get("code_verifier")
		key = digest(code)
		txn = o.Store.OAuthGet(kind, key)
		if txn == nil || txn["client"] != cid || q.Get("redirect_uri") != str(txn["redirect"]) || !matches(`^[A-Za-z0-9._~-]{43,128}$`, verifier) || !secureEqual(challenge(verifier), str(txn["challenge"])) {
			oauthError(w, "invalid_grant", 400)
			return
		}
		body.Set("code", code)
		body.Set("code_verifier", verifier)
		body.Set("redirect_uri", callback)
	case "refresh_token":
		kind = "refresh"
		token := q.Get("refresh_token")
		key = digest(token)
		if tokens := o.replayed(key, cid); tokens != nil {
			w.Header().Set("Pragma", "no-cache")
			jsonResponse(w, 200, tokens)
			return
		}
		txn = o.Store.OAuthGet(kind, key)
		if txn == nil || txn["client"] != cid {
			oauthError(w, "invalid_grant", 400)
			return
		}
		body.Set("refresh_token", token)
	default:
		oauthError(w, "unsupported_grant_type", 400)
		return
	}
	tokens, status, err := o.upstream(r.Context(), "token", body)
	if err == nil && status == 400 && tokens["error"] == "invalid_grant" {
		o.Store.OAuthPop(kind, key)
		oauthError(w, "invalid_grant", 400)
		return
	}
	if err != nil || status != 200 {
		oauthError(w, "temporarily_unavailable", 503)
		return
	}
	access, ok := tokens["access_token"].(string)
	if !ok || access == "" {
		oauthError(w, "temporarily_unavailable", 503)
		return
	}
	if _, err = o.Verifier.Verify(r.Context(), access); err != nil {
		var unavailable IssuerUnavailable
		if errors.As(err, &unavailable) {
			oauthError(w, "temporarily_unavailable", 503)
		} else {
			oauthError(w, "invalid_grant", 400)
		}
		return
	}
	scope := fallback(tokens, "scope", "")
	if tokens["scope"] == nil && boolean(txn["offline"]) {
		scope = "offline_access"
	}
	scopeText, ok := scope.(string)
	if !ok {
		oauthError(w, "temporarily_unavailable", 503)
		return
	}
	offline := contains(strings.Fields(scopeText), "offline_access")
	ttl := intAt(tokens, "refresh_expires_in", 1800)
	refresh, ok := tokens["refresh_token"].(string)
	if tokens["refresh_token"] != nil && !ok {
		oauthError(w, "temporarily_unavailable", 503)
		return
	}
	if refresh != "" && (ttl < 0 || (ttl == 0 && !offline)) {
		oauthError(w, "temporarily_unavailable", 503)
		return
	}
	o.Store.Transaction(func(tx *Store) {
		if refresh != "" {
			tx.OAuthPut("refresh", digest(refresh), D{"client": cid, "offline": offline}, ttl)
		}
		if grant == "authorization_code" || (refresh != "" && refresh != body.Get("refresh_token")) {
			tx.Exec("DELETE FROM oauth WHERE kind=? AND id=?", kind, key)
		}
		duration := clientTTL
		if offline {
			duration = 0
		}
		tx.OAuthPut("client", cid, client, duration)
	})
	if grant == "refresh_token" && refresh != "" && refresh != body.Get("refresh_token") {
		o.remember(key, cid, tokens)
	}
	w.Header().Set("Pragma", "no-cache")
	jsonResponse(w, 200, tokens)
}

// consentStyle is ui.winlab.tw's consent block (@winlab/consent) in its
// spotlight layout, written out with the same tokens because this page is
// served without React or scripts. Fonts come from the site at the same
// origin; without them the page falls back to system fonts.
const consentStyle = `
@font-face { font-family: Inter; src: url(/fonts/inter-latin.woff2) format("woff2"); font-weight: 100 900; font-display: swap; }
@font-face { font-family: "Noto Sans TC"; src: url(/fonts/noto-sans-tc-consent.woff2) format("woff2"); font-weight: 100 900; font-display: swap; }
:root { color-scheme: light dark; font-family: Inter, "Noto Sans TC", sans-serif; font-size: 16px; line-height: 1.5rem;
  --background: oklch(1 0 0); --foreground: oklch(0.145 0 0); --muted: oklch(0.97 0 0); --muted-foreground: oklch(0.556 0 0);
  --primary: oklch(0.378 0.182 262.5); --primary-foreground: oklch(0.985 0 0); --border: oklch(0.922 0 0); --ring: oklch(0.708 0 0); }
@media (prefers-color-scheme: dark) {
  :root { --background: oklch(0.145 0 0); --foreground: oklch(0.985 0 0); --muted: oklch(0.269 0 0); --muted-foreground: oklch(0.708 0 0);
    --primary: oklch(0.68 0.168 262.5); --primary-foreground: oklch(0.145 0 0); --border: oklch(1 0 0 / 10%); --ring: oklch(0.556 0 0); }
}
* { box-sizing: border-box; margin: 0; }
body { background: var(--background); color: var(--foreground); }
header { position: fixed; top: 1.5rem; left: 1.5rem; display: flex; gap: .5rem; color: var(--muted-foreground); }
header span:last-child { color: var(--foreground); }
main { min-height: 100svh; display: flex; align-items: center; justify-content: center; padding: 6rem 1.5rem; }
form { width: 100%; max-width: 42rem; display: flex; flex-direction: column; align-items: center; gap: 3rem; text-align: center; }
h1 { font-size: 1.5rem; line-height: 2rem; font-weight: 500; }
.text { display: flex; flex-direction: column; gap: 1rem; color: var(--muted-foreground); overflow-wrap: anywhere; }
strong { color: var(--foreground); font-weight: 500; }
.actions { display: flex; gap: 1rem; }
button { height: 2.5rem; padding: 0 1rem; border: 1px solid var(--border); border-radius: 1rem; background: var(--background);
  color: var(--foreground); font: inherit; font-weight: 500; cursor: pointer; transition: background-color 150ms; outline: none; }
button:hover { background: var(--muted); }
button.primary { border-color: transparent; background: var(--primary); color: var(--primary-foreground); }
button.primary:hover { background: color-mix(in oklch, var(--primary) 90%, transparent); }
button:focus-visible { box-shadow: 0 0 0 3px color-mix(in oklch, var(--ring) 50%, transparent); }
`

func consentPage(w http.ResponseWriter, name, redirect, nonce string) {
	u, err := url.Parse(redirect)
	must(err)
	host := u.Hostname()
	if u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		panic("invalid callback")
	}
	if strings.Contains(host, ":") {
		if net.ParseIP(host) == nil {
			panic("invalid callback host")
		}
	} else if !matches(`^[A-Za-z0-9.-]+$`, host) {
		panic("invalid callback host")
	}
	sum := sha256.Sum256([]byte(consentStyle))
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'; font-src 'self'; form-action 'self' "+u.Scheme+"://"+u.Host+"; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Referrer-Policy", "strict-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>連接 Carrel</title><style>%s</style></head><body><header><span>WinLab</span><span aria-hidden="true">/</span><span>Carrel</span></header><main><form method="post" action="/oauth/consent" aria-labelledby="title"><h1 id="title">連接 Carrel</h1><div class="text"><p>允許 <strong>%s</strong> 以你的帳號權限管理 Carrel 資源。</p><p>登入會持續保留，關閉瀏覽器後仍可使用。你可以在 WinLab 帳號的應用程式頁面撤銷存取。</p></div><input type="hidden" name="consent" value="%s"><div class="actions"><button name="allow" value="no">取消</button><button class="primary" name="allow" value="yes">允許</button></div></form></main></body></html>`, consentStyle, html.EscapeString(name), html.EscapeString(nonce))
}
