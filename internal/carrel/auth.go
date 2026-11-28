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
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var scopes = []string{"openid", "profile", "email", "offline_access"}

const clientTTL = 86400 * 90

// A registration lives a day until its first token exchange extends it to
// clientTTL, so registrations nobody uses cannot fill maxClients.
const registrationTTL = 86400
const maxClients = 10000

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
	// OIDC and endpoints are set for member tokens (NewVerifier) only.
	OIDC      OIDCConfig
	endpoints *endpoints
	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	loaded    time.Time
}

func NewVerifier(issuer string, oidc OIDCConfig, ep *endpoints) *Verifier {
	oidc = oidc.WithDefaults()
	return &Verifier{Issuer: issuer, Audience: oidc.Audience, OIDC: oidc, endpoints: ep, HTTP: &http.Client{Timeout: 8 * time.Second, CheckRedirect: noRedirect}}
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
		jwksURL = v.endpoints.url(v.Issuer, "jwks_uri")
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

// Verify checks the token signature, issuer, audience and identity claims. The requested resource (/mcp or
// /mcp/read-only) is deliberately not checked: the upstream issuer mints the tokens and sets no resource claim, so
// /mcp/read-only is a tool filter, not a credential boundary.
func (v *Verifier) Verify(ctx context.Context, token string) (D, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) { return v.key(ctx, str(t.Header["kid"])) }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(v.Audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(10*time.Second))
	if err != nil {
		return nil, err
	}
	// azp names the client; a provider that follows RFC 9068 without azp
	// names it in client_id instead.
	client, ok := claims["azp"]
	if !ok {
		client = claims["client_id"]
	}
	if claims["iat"] == nil || claims["sub"] == nil || client != v.OIDC.ClientID {
		return nil, errors.New("missing identity or wrong authorized party")
	}
	if iss, err := claims.GetIssuer(); err != nil || !sameIssuer(iss, v.Issuer) {
		return nil, errors.New("wrong issuer")
	}
	who, err := v.OIDC.identity(D(claims))
	if err != nil {
		return nil, err
	}
	// exp lets a long-lived request (the event stream) end when the token
	// does, so a member removed upstream loses access with their next token.
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		who["exp"] = exp.Unix()
	}
	return who, nil
}

type OAuth struct {
	Store                    *Store
	Origin, Issuer, ClientID string
	Hosted                   []string
	Verifier                 IdentityVerifier
	// endpoints finds the provider's authorize, token and revoke URLs;
	// nil uses Keycloak's paths under Issuer.
	endpoints *endpoints
	// Console finishes browser console logins (console.go).
	Console func(http.ResponseWriter, *http.Request, D, string)
	HTTP    *http.Client
	// ClientSecretFile, when set, makes Carrel a confidential client: the
	// secret is sent with every token and revocation request.
	ClientSecretFile string
	locks            [64]sync.Mutex
	replayMu         sync.Mutex
	replay           map[string]rotated
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
	_, _ = w.Write(append(encoded(value), '\n'))
}
func oauthError(w http.ResponseWriter, code string, status int) {
	w.Header().Set("Cache-Control", "no-store")
	jsonResponse(w, status, D{"error": code})
}
func secureEqual(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func (o *OAuth) upstream(ctx context.Context, endpoint string, values url.Values) (D, int, error) {
	target, _ := o.endpoints.lookup(o.Issuer, endpoint)
	if o.ClientSecretFile != "" {
		secret, err := os.ReadFile(o.ClientSecretFile)
		if err != nil || strings.TrimSpace(string(secret)) == "" {
			return nil, 0, errors.New("oidc client secret unreadable")
		}
		values.Set("client_secret", strings.TrimSpace(string(secret)))
	}
	req, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(values.Encode()))
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
			logPanic("oauth", p, "path", r.URL.Path)
			oauthError(w, "temporarily_unavailable", 503)
		}
	}()
	o.Store.PurgeOAuth()
	path, method := r.URL.Path, r.Method
	if strings.HasPrefix(path, "/.well-known/oauth-protected-resource") && method == "GET" {
		o.protectedResource(w, path)
		return
	}
	if (path == "/.well-known/oauth-authorization-server" || path == "/.well-known/openid-configuration") && method == "GET" {
		o.serverMetadata(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case path == "/oauth/register" && method == "POST":
		o.register(w, r)
	case path == "/oauth/authorize" && method == "GET":
		o.authorize(w, r)
	case path == "/oauth/callback" && method == "GET":
		o.callback(w, r)
	case path == "/oauth/consent" && method == "POST":
		o.consent(w, r)
	case path == "/oauth/token" && method == "POST":
		o.withClient(w, r, func(client D) { o.exchange(w, r, client, o.Origin+"/mcp", o.Origin+"/oauth/callback") })
	case path == "/oauth/revoke" && method == "POST":
		o.withClient(w, r, func(client D) { o.revoke(w, r, client) })
	default:
		oauthError(w, "invalid_request", 404)
	}
}
func (o *OAuth) protectedResource(w http.ResponseWriter, path string) {
	resource := o.Origin + "/mcp"
	if path == "/.well-known/oauth-protected-resource/mcp/read-only" {
		resource += "/read-only"
	}
	jsonResponse(w, 200, D{"resource": resource, "authorization_servers": []string{o.Origin}, "scopes_supported": scopes, "bearer_methods_supported": []string{"header"}})
}
func (o *OAuth) serverMetadata(w http.ResponseWriter) {
	jsonResponse(w, 200, D{"issuer": o.Origin, "authorization_endpoint": o.Origin + "/oauth/authorize", "token_endpoint": o.Origin + "/oauth/token", "registration_endpoint": o.Origin + "/oauth/register", "revocation_endpoint": o.Origin + "/oauth/revoke", "revocation_endpoint_auth_methods_supported": []string{"none"}, "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"none"}, "authorization_response_iss_parameter_supported": true, "scopes_supported": scopes})
}
func (o *OAuth) register(w http.ResponseWriter, r *http.Request) {
	o.locks[0].Lock()
	defer o.locks[0].Unlock()
	if integer(o.Store.Rows("SELECT count(*) AS n FROM oauth WHERE kind='client'")[0]["n"]) >= maxClients {
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
	o.Store.OAuthPut("client", str(c["client_id"]), c, registrationTTL)
	jsonResponse(w, 201, c)
}
func (o *OAuth) authorize(w http.ResponseWriter, r *http.Request) {
	resource := o.Origin + "/mcp"
	callback := o.Origin + "/oauth/callback"
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		oauthError(w, "invalid_request", 400)
		return
	}
	c := o.Store.OAuthGet("client", q.Get("client_id"))
	if c == nil || !contains(c["redirect_uris"], q.Get("redirect_uri")) {
		oauthError(w, "invalid_client", 400)
		return
	}
	res := q.Get("resource")
	if len(q["resource"]) > 1 || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || !matches(`^[A-Za-z0-9_-]{43}$`, q.Get("code_challenge")) || (res != "" && res != resource && res != resource+"/read-only") || len(q.Get("state")) > 4096 {
		oauthError(w, "invalid_request", 400)
		return
	}
	state, cookie := random(32), random(32)
	txn := D{"client": c["client_id"], "name": c["client_name"], "redirect": q.Get("redirect_uri"), "state": q.Get("state"), "challenge": q.Get("code_challenge"), "cookie": digest(cookie)}
	o.Store.OAuthPut("state", state, txn, 600)
	params := url.Values{"client_id": {o.ClientID}, "redirect_uri": {callback}, "response_type": {"code"}, "scope": {strings.Join(scopes, " ")}, "state": {state}, "code_challenge": {str(txn["challenge"])}, "code_challenge_method": {"S256"}}
	http.SetCookie(w, &http.Cookie{Name: oauthCookie, Value: cookie, MaxAge: 600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, Path: "/"})
	http.Redirect(w, r, o.authorizeURL(params), 302)
}

// authorizeURL is the provider's authorization endpoint with params, kept
// apart from any query the endpoint already has.
func (o *OAuth) authorizeURL(params url.Values) string {
	u := o.endpoints.url(o.Issuer, "authorization_endpoint")
	if strings.Contains(u, "?") {
		return u + "&" + params.Encode()
	}
	return u + "?" + params.Encode()
}

// badIss refuses an authorization response whose iss is not the issuer
// (RFC 9207). A response without iss passes unless the provider's discovery
// says it sends one.
func (o *OAuth) badIss(q url.Values) bool {
	if !q.Has("iss") {
		return o.endpoints.issParamRequired()
	}
	return !sameIssuer(q.Get("iss"), o.Issuer)
}
func (o *OAuth) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	txn := o.Store.OAuthPop("state", q.Get("state"))
	cookie, _ := r.Cookie(oauthCookie)
	value := ""
	if cookie != nil {
		value = cookie.Value
	}
	if txn == nil || !secureEqual(str(txn["cookie"]), digest(value)) || o.badIss(q) || q.Get("code") == "" || q.Get("error") != "" {
		oauthError(w, "access_denied", 400)
		return
	}
	if txn["console"] != nil && o.Console != nil {
		o.Console(w, r, txn, q.Get("code"))
		return
	}
	consent := random(32)
	txn["code"] = q.Get("code")
	o.Store.OAuthPut("consent", consent, txn, 300)
	consentPage(w, str(txn["name"]), str(txn["redirect"]), consent)
}
func (o *OAuth) consent(w http.ResponseWriter, r *http.Request) {
	if r.ParseForm() != nil {
		oauthError(w, "invalid_request", 400)
		return
	}
	txn := o.Store.OAuthPop("consent", r.PostForm.Get("consent"))
	cookie, _ := r.Cookie(oauthCookie)
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
}

// withClient parses the form, serialises on the client's lock and runs next
// for a registered client.
func (o *OAuth) withClient(w http.ResponseWriter, r *http.Request, next func(client D)) {
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
	next(client)
}
func (o *OAuth) revoke(w http.ResponseWriter, r *http.Request, client D) {
	q := r.PostForm
	cid := q.Get("client_id")
	token := q.Get("token")
	txn := o.Store.OAuthGet("refresh", digest(token))
	if txn != nil && txn["client"] == cid {
		// A provider that publishes no revocation endpoint has nothing to
		// revoke upstream; the local record still goes.
		if _, ok := o.endpoints.lookup(o.Issuer, "revocation_endpoint"); !ok {
			o.Store.OAuthPop("refresh", digest(token))
			o.forget(token)
			jsonResponse(w, 200, D{})
			return
		}
		_, status, err := o.upstream(r.Context(), "revocation_endpoint", url.Values{"client_id": {o.ClientID}, "token": {token}, "token_type_hint": {"refresh_token"}})
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
func (o *OAuth) exchange(w http.ResponseWriter, r *http.Request, client D, resource, callback string) {
	q := r.PostForm
	cid := q.Get("client_id")
	if res, ok := q["resource"]; ok && (len(res) != 1 || res[0] != resource && res[0] != resource+"/read-only") {
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
	tokens, status, err := o.upstream(r.Context(), "token_endpoint", body)
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
  --background: oklch(0.97 0.005 85); --foreground: oklch(0.25 0 0); --muted: oklch(0.93 0.005 85); --muted-foreground: oklch(0.52 0 0);
  --primary: oklch(0.378 0.182 262.5); --primary-foreground: oklch(0.985 0 0); --border: oklch(0.89 0.005 85); --ring: oklch(0.708 0 0); }
@media (prefers-color-scheme: dark) {
  :root { --background: oklch(0.17 0 0); --foreground: oklch(0.88 0 0); --muted: oklch(0.26 0 0); --muted-foreground: oklch(0.62 0 0);
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
  color: var(--foreground); font: inherit; font-weight: 500; cursor: pointer; transition: background-color 150ms; outline: 2px solid transparent; outline-offset: 2px; }
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
