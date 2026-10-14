package carrel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTSignatureIssuerAudienceAndMembership(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, D{"keys": []D{{"kid": "test", "kty": "RSA", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})
	}))
	defer issuer.Close()
	v := NewVerifier(issuer.URL)
	base := D{"iss": issuer.URL, "aud": "carrel-mcp", "azp": "carrel-mcp", "sub": "alice", "iat": time.Now().Unix(), "exp": time.Now().Unix() + 300, "preferred_username": "alice", "groups": []any{"/lab-member/master", "/winlab-projects/shared"}}
	sign := func(c D, k *rsa.PrivateKey) string {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(c))
		token.Header["kid"] = "test"
		s, err := token.SignedString(k)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if who, err := v.Verify(context.Background(), sign(base, key)); err != nil || who["sub"] != "alice" {
		t.Fatalf("%v %v", who, err)
	}
	for _, change := range []D{{"aud": "wrong"}, {"azp": "wrong"}, {"iss": "https://evil.test"}, {"exp": 1}, {"iat": nil}, {"groups": []any{"/winlab-admin/child"}}, {"groups": []any{"/lab-member/alumni"}}, {"groups": "winlab-admin"}} {
		if _, err := v.Verify(context.Background(), sign(merge(base, change), key)); err == nil {
			t.Fatalf("accepted %v", change)
		}
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := v.Verify(context.Background(), sign(base, other)); err == nil {
		t.Fatal("accepted wrong signing key")
	}
	claims := merge(base, D{"groups": []any{"/winlab-admin"}})
	if who, err := v.Verify(context.Background(), sign(claims, key)); err != nil || !boolean(who["admin"]) {
		t.Fatal(who, err)
	}
}
func authRequest(o *OAuth, path string, data url.Values) *httptest.ResponseRecorder {
	method := "GET"
	var body string
	if data != nil {
		method = "POST"
		body = data.Encode()
	}
	r := httptest.NewRequest(method, "https://carrel.test"+path, strings.NewReader(body))
	if data != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	w := httptest.NewRecorder()
	o.ServeHTTP(w, r)
	return w
}
func TestOfflineRefreshRotationAndOutage(t *testing.T) {
	for _, mode := range []string{"new", "same", "omitted", "unavailable", "revoked", "nonoffline-zero"} {
		t.Run(mode, func(t *testing.T) {
			p, _ := fixture(t)
			s := p.Store
			client := D{"client_id": "desktop", "client_name": "Codex", "redirect_uris": []any{"http://localhost:1234/cb"}}
			s.OAuthPut("client", "desktop", client, clientTTL)
			s.OAuthPut("refresh", digest("old"), D{"client": "desktop", "offline": true}, 1800)
			issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "unavailable" {
					jsonResponse(w, 503, D{"error": "unavailable"})
					return
				}
				if mode == "revoked" {
					jsonResponse(w, 400, D{"error": "invalid_grant"})
					return
				}
				tokens := D{"access_token": "access", "refresh_token": "new", "refresh_expires_in": 0, "expires_in": 300, "scope": "openid profile offline_access"}
				if mode == "same" {
					tokens["refresh_token"] = "old"
				}
				if mode == "omitted" {
					delete(tokens, "refresh_token")
				}
				if mode == "nonoffline-zero" {
					tokens["scope"] = "openid profile"
				}
				jsonResponse(w, 200, tokens)
			}))
			defer issuer.Close()
			o := &OAuth{Store: s, Origin: "https://carrel.test", Issuer: issuer.URL, ClientID: "carrel-mcp", HTTP: issuer.Client(), Verifier: testVerifier{who: person("alice", false)}}
			w := authRequest(o, "/oauth/token", url.Values{"client_id": {"desktop"}, "grant_type": {"refresh_token"}, "refresh_token": {"old"}})
			expected := 200
			if mode == "unavailable" || mode == "nonoffline-zero" {
				expected = 503
			}
			if mode == "revoked" {
				expected = 400
			}
			if w.Code != expected {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			oldExists := s.OAuthGet("refresh", digest("old")) != nil
			if oldExists != (mode != "new" && mode != "revoked") {
				t.Fatalf("old credential lifecycle: %v", oldExists)
			}
			if expected == 200 {
				rows := s.Rows("SELECT expires FROM oauth WHERE kind='client' AND id='desktop'")
				if num(rows[0]["expires"]) != 0 {
					t.Fatal("offline client has fixed expiry")
				}
				if mode == "new" && s.OAuthGet("refresh", digest("new")) == nil {
					t.Fatal("rotation missing")
				}
			}
		})
	}
}
func TestRotatedRefreshTokenReplaysWithinGrace(t *testing.T) {
	p, _ := fixture(t)
	s := p.Store
	s.OAuthPut("client", "desktop", D{"client_id": "desktop"}, 0)
	s.OAuthPut("client", "other", D{"client_id": "other"}, 0)
	s.OAuthPut("refresh", digest("old"), D{"client": "desktop", "offline": true}, 0)
	calls := 0
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		jsonResponse(w, 200, D{"access_token": "access", "refresh_token": "new", "refresh_expires_in": 0, "expires_in": 300, "scope": "openid offline_access"})
	}))
	defer issuer.Close()
	o := &OAuth{Store: s, Origin: "https://carrel.test", Issuer: issuer.URL, ClientID: "carrel-mcp", HTTP: issuer.Client(), Verifier: testVerifier{who: person("alice", false)}}
	refresh := func(cid, token string) *httptest.ResponseRecorder {
		return authRequest(o, "/oauth/token", url.Values{"client_id": {cid}, "grant_type": {"refresh_token"}, "refresh_token": {token}})
	}
	if w := refresh("desktop", "old"); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	w := refresh("desktop", "old")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"refresh_token":"new"`) || calls != 1 {
		t.Fatal("racing refresh not replayed", w.Code, w.Body, calls)
	}
	if w := refresh("other", "old"); w.Code != 400 {
		t.Fatal("replay crossed clients", w.Code)
	}
	o.replay[digest("old")] = rotated{client: "desktop", tokens: D{"refresh_token": "new"}, expires: time.Now().Add(-time.Second)}
	if w := refresh("desktop", "old"); w.Code != 400 {
		t.Fatal("expired grace accepted", w.Code)
	}
	o.remember(digest("old"), "desktop", D{"refresh_token": "new"})
	if w := authRequest(o, "/oauth/revoke", url.Values{"client_id": {"desktop"}, "token": {"new"}}); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := refresh("desktop", "old"); w.Code != 400 {
		t.Fatal("revoked token still replayed", w.Code)
	}
}
func TestCodeExchangeIsBoundToClientRedirectAndPKCE(t *testing.T) {
	p, _ := fixture(t)
	s := p.Store
	verifier := strings.Repeat("x", 50)
	client := D{"client_id": "desktop", "redirect_uris": []any{"http://localhost:1234/cb"}}
	s.OAuthPut("client", "desktop", client, clientTTL)
	s.OAuthPut("client", "other", merge(client, D{"client_id": "other"}), clientTTL)
	s.OAuthPut("code", digest("code"), D{"client": "desktop", "redirect": "http://localhost:1234/cb", "challenge": challenge(verifier)}, 120)
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("code_verifier") != verifier {
			t.Error("wrong upstream verifier")
		}
		jsonResponse(w, 200, D{"access_token": "access", "refresh_token": "refresh", "refresh_expires_in": 0, "scope": "offline_access"})
	}))
	defer issuer.Close()
	o := &OAuth{Store: s, Origin: "https://carrel.test", Issuer: issuer.URL, ClientID: "carrel-mcp", HTTP: issuer.Client(), Verifier: testVerifier{who: person("alice", false)}}
	base := url.Values{"client_id": {"desktop"}, "grant_type": {"authorization_code"}, "code": {"code"}, "code_verifier": {verifier}, "redirect_uri": {"http://localhost:1234/cb"}}
	for _, change := range [][2]string{{"client_id", "other"}, {"redirect_uri", "http://localhost:9999/other"}, {"code_verifier", strings.Repeat("z", 50)}} {
		values := url.Values{}
		for k, v := range base {
			values[k] = append([]string{}, v...)
		}
		values.Set(change[0], change[1])
		if w := authRequest(o, "/oauth/token", values); w.Code != 400 {
			t.Fatal(w.Code, w.Body)
		}
	}
	w := authRequest(o, "/oauth/token", base)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if s.OAuthGet("code", digest("code")) != nil {
		t.Fatal("authorization code replay possible")
	}
	if w := authRequest(o, "/oauth/token", base); w.Code != 400 {
		t.Fatal("consumed code accepted")
	}
	s.PurgeOAuth()
	if s.OAuthGet("refresh", digest("refresh")) == nil {
		t.Fatal("offline refresh missing")
	}
}
func TestOAuthRedirectAndConsentBoundaries(t *testing.T) {
	o := &OAuth{Hosted: []string{"https://chatgpt.com/connector_platform/oauth/callback"}}
	for _, s := range []string{"http://localhost:1234/cb", "http://127.0.0.1:3/cb", "http://[::1]:9/cb", o.Hosted[0]} {
		if !o.allowedRedirect(s) {
			t.Fatal("valid callback refused", s)
		}
	}
	for _, s := range []string{"https://evil.test/cb", "http://localhost/cb", "http://user@localhost:1234/cb", "http://localhost:1/cb#token", "http://localhost:99999/", "http://[::1%25zone]:8/"} {
		if o.allowedRedirect(s) {
			t.Fatal("unsafe callback accepted", s)
		}
	}
	w := httptest.NewRecorder()
	consentPage(w, `<script>alert(1)</script>`, "http://[::1]:1234/cb", "nonce")
	if strings.Contains(w.Body.String(), "<script>") || !strings.Contains(w.Header().Get("Content-Security-Policy"), "http://[::1]:1234") {
		t.Fatal("unsafe consent page")
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "font-src 'self'") || strings.Contains(csp, "script-src") {
		t.Fatal("consent page CSP", csp)
	}
}
func TestOAuthIssuerOutageDoesNotInvalidateLogin(t *testing.T) {
	p, _ := fixture(t)
	p.Store.OAuthPut("client", "desktop", D{"client_id": "desktop"}, 0)
	p.Store.OAuthPut("refresh", digest("refresh"), D{"client": "desktop", "offline": true}, 0)
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, D{"access_token": "access", "refresh_token": "next", "refresh_expires_in": 0, "scope": "offline_access"})
	}))
	defer issuer.Close()
	o := &OAuth{Store: p.Store, Origin: "https://carrel.test", Issuer: issuer.URL, ClientID: "carrel-mcp", HTTP: issuer.Client(), Verifier: testVerifier{err: IssuerUnavailable{errors.New("offline")}}}
	w := authRequest(o, "/oauth/token", url.Values{"client_id": {"desktop"}, "grant_type": {"refresh_token"}, "refresh_token": {"refresh"}})
	if w.Code != 503 || p.Store.OAuthGet("refresh", digest("refresh")) == nil {
		t.Fatal("issuer outage discarded login", w.Code, w.Body)
	}
}
func TestOAuthStatePersistenceAcrossDatabaseReopen(t *testing.T) {
	p, _ := fixture(t)
	s := p.Store
	path := str(s.Rows("PRAGMA database_list")[0]["file"])
	s.OAuthPut("client", "client", D{"client_id": "client"}, 0)
	s.OAuthPut("refresh", digest("opaque-token"), D{"client": "client", "offline": true}, 0)
	must(s.DB.Close())
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.DB.Close()
	reopened.PurgeOAuth()
	if reopened.OAuthGet("client", "client") == nil || reopened.OAuthGet("refresh", digest("opaque-token")) == nil {
		t.Fatal("login did not survive reopen")
	}
	var data D
	must(json.Unmarshal(encoded(reopened.OAuthGet("refresh", digest("opaque-token"))), &data))
	if data["client"] != "client" {
		t.Fatal(data)
	}
}
