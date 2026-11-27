package carrel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// provider stands in for a non-Keycloak OIDC provider: its keys and
// endpoints live where its discovery document says, not on Keycloak paths.
func provider(t *testing.T, key *rsa.PrivateKey, doc func(base string) D) *httptest.Server {
	t.Helper()
	var s *httptest.Server
	s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			jsonResponse(w, 200, doc(s.URL))
		case "/keys":
			jsonResponse(w, 200, D{"keys": []D{{"kid": "k1", "kty": "RSA", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func discovery(base string) D {
	return D{"issuer": base, "jwks_uri": base + "/keys", "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token", "revocation_endpoint": base + "/revoke"}
}

func signed(t *testing.T, key *rsa.PrivateKey, c D) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(c))
	token.Header["kid"] = "k1"
	s, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAnotherProviderSignsMembersIn(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	p := provider(t, key, discovery)
	oidc := OIDCConfig{Audience: "api://carrel", ClientID: "carrel-web", UsernameClaim: "email", GroupsClaim: "roles", AdminGroups: []string{"ops"}, MemberGroups: []string{"staff/*"}, ProjectGroupPrefix: "proj-"}
	if err := oidc.Validate(); err != nil {
		t.Fatal(err)
	}
	ep := newEndpoints(p.URL)
	v := NewVerifier(p.URL, oidc, ep)
	now := time.Now().Unix()
	// RFC 9068 style: no azp, the client in client_id.
	base := D{"iss": p.URL, "aud": "api://carrel", "client_id": "carrel-web", "sub": "u1", "iat": now, "exp": now + 300, "email": "ann@lab.example", "roles": []any{"staff/phd", "proj-alpha", "proj-a/b"}}
	who, err := v.Verify(context.Background(), signed(t, key, base))
	if err != nil {
		t.Fatal(err)
	}
	if who["username"] != "ann@lab.example" || who["admin"] != false || !equal(who["projects"], []string{"winlab-projects/alpha"}) {
		t.Fatalf("identity: %s", encoded(who))
	}
	if who, err := v.Verify(context.Background(), signed(t, key, merge(base, D{"roles": []any{"ops"}}))); err != nil || who["admin"] != true {
		t.Fatalf("admin: %v %v", who, err)
	}
	for _, change := range []D{
		{"aud": "carrel-mcp"},                     // WinLab's audience is not this site's
		{"client_id": "other"},                    // another client
		{"azp": "other"},                          // azp, when present, decides
		{"roles": []any{"staff/phd/old"}},         // "*" does not cross a "/"
		{"roles": []any{"lab-member/master"}},     // WinLab's groups mean nothing here
		{"email": nil, "preferred_username": "x"}, // the configured username claim is required
		{"roles": nil, "groups": []any{"ops"}},    // and the configured groups claim
	} {
		if _, err := v.Verify(context.Background(), signed(t, key, merge(base, change))); err == nil {
			t.Fatalf("accepted %v", change)
		}
	}

	// The OAuth proxy uses the discovered endpoints too.
	o := &OAuth{Issuer: p.URL, endpoints: ep}
	if u := o.authorizeURL(url.Values{"a": {"1"}}); u != p.URL+"/authorize?a=1" {
		t.Fatal(u)
	}
	if ep.url(p.URL, "token_endpoint") != p.URL+"/token" || ep.url(p.URL, "revocation_endpoint") != p.URL+"/revoke" {
		t.Fatal("token or revocation endpoint not from discovery")
	}
}

func TestDiscoveryThatCannotBeTrustedFallsBackToKeycloakPaths(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, doc := range map[string]func(string) D{
		"another issuer": func(base string) D { return merge(discovery(base), D{"issuer": "https://evil.test"}) },
		"plain http": func(base string) D {
			return D{"issuer": base, "token_endpoint": strings.Replace(base, "http:", "ftp:", 1) + "/token"}
		},
		"no document": nil,
	} {
		var p *httptest.Server
		if doc == nil {
			p = httptest.NewServer(http.NotFoundHandler())
			t.Cleanup(p.Close)
		} else {
			p = provider(t, key, doc)
		}
		ep := newEndpoints(p.URL)
		if u := ep.url(p.URL, "token_endpoint"); u != p.URL+"/protocol/openid-connect/token" {
			t.Fatalf("%s: %s", name, u)
		}
	}
	// No endpoints at all, as in tests that build OAuth by hand.
	var none *endpoints
	if u := none.url("https://auth.test/realms/x", "jwks_uri"); u != "https://auth.test/realms/x/protocol/openid-connect/certs" {
		t.Fatal(u)
	}
}

func TestOIDCConfigDefaultsAreWinLabsAndPatternsAreChecked(t *testing.T) {
	d := OIDCConfig{}.WithDefaults()
	if d.Audience != "carrel-mcp" || d.ClientID != "carrel-mcp" || d.ProjectGroupPrefix != "winlab-projects/" || !equal(d.AdminGroups, []string{"winlab-admin"}) || len(d.MemberGroups) != 9 {
		t.Fatalf("defaults: %+v", d)
	}
	for _, bad := range []OIDCConfig{{AdminGroups: []string{"["}}, {MemberGroups: []string{"/lab-member/*"}}, {ProjectGroupPrefix: "/proj-"}, {ProjectGroupPrefix: "proj-*"}} {
		if bad.Validate() == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

func TestCallbackRequiresIssOnlyWhenDiscoveryPromisesIt(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	without := provider(t, key, discovery)
	with := provider(t, key, func(b string) D {
		return merge(discovery(b), D{"authorization_response_iss_parameter_supported": true})
	})
	for _, c := range []struct {
		p    *httptest.Server
		q    url.Values
		deny bool
	}{
		{without, url.Values{}, false},
		{without, url.Values{"iss": {"https://evil.test"}}, true},
		{without, url.Values{"iss": {without.URL + "/"}}, false},
		{with, url.Values{}, true},
		{with, url.Values{"iss": {with.URL}}, false},
	} {
		o := &OAuth{Issuer: c.p.URL, endpoints: newEndpoints(c.p.URL)}
		if o.badIss(c.q) != c.deny {
			t.Fatalf("%s %v: deny=%v", c.p.URL, c.q, !c.deny)
		}
	}
}

func TestIssuerWithTrailingSlash(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	p := provider(t, key, func(b string) D { return merge(discovery(b), D{"issuer": b + "/"}) })
	ep := newEndpoints(p.URL)
	if ep.url(p.URL, "token_endpoint") != p.URL+"/token" {
		t.Fatal("discovery with a trailing slash issuer was dropped")
	}
	v := NewVerifier(p.URL, OIDCConfig{}, ep)
	now := time.Now().Unix()
	c := D{"iss": p.URL + "/", "aud": "carrel-mcp", "azp": "carrel-mcp", "sub": "u", "iat": now, "exp": now + 300, "preferred_username": "a", "groups": []any{"winlab-admin"}}
	if _, err := v.Verify(context.Background(), signed(t, key, c)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), signed(t, key, merge(c, D{"iss": "https://evil.test"}))); err == nil {
		t.Fatal("accepted another issuer")
	}
}

func TestNoRevocationEndpointSkipsUpstreamRevocation(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	p := provider(t, key, func(b string) D { d := discovery(b); delete(d, "revocation_endpoint"); return d })
	ep := newEndpoints(p.URL)
	if _, ok := ep.lookup(p.URL, "revocation_endpoint"); ok {
		t.Fatal("revocation fell back to Keycloak")
	}
	if _, ok := ep.lookup(p.URL, "token_endpoint"); !ok {
		t.Fatal("token endpoint lost")
	}
	gone := httptest.NewServer(http.NotFoundHandler())
	defer gone.Close()
	if u, ok := newEndpoints(gone.URL).lookup(gone.URL, "revocation_endpoint"); !ok || !strings.HasSuffix(u, "/revoke") {
		t.Fatal("no discovery must keep the Keycloak path")
	}
}

func TestUpstreamSendsSecretAndRefusesRedirects(t *testing.T) {
	var got url.Values
	hit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer target.Close()
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, target.URL, 307)
			return
		}
		_ = r.ParseForm()
		got = r.PostForm
		jsonResponse(w, 200, D{})
	}))
	defer idp.Close()
	secret := t.TempDir() + "/secret"
	if err := os.WriteFile(secret, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := &OAuth{Issuer: idp.URL, HTTP: &http.Client{CheckRedirect: noRedirect}, ClientSecretFile: secret}
	if _, _, err := o.upstream(context.Background(), "token_endpoint", url.Values{"code": {"c"}}); err != nil {
		// Keycloak path under idp answers 200 too.
		t.Fatal(err)
	}
	if got.Get("client_secret") != "s3cret" {
		t.Fatalf("secret not sent: %v", got)
	}
	o.endpoints = &endpoints{issuer: idp.URL, doc: map[string]string{"token_endpoint": idp.URL + "/redirect"}, tried: time.Now()}
	if _, status, _ := o.upstream(context.Background(), "token_endpoint", url.Values{"code": {"c"}}); status != 307 || hit {
		t.Fatalf("followed a redirect: %d %v", status, hit)
	}
	o.ClientSecretFile = secret + ".missing"
	if _, _, err := o.upstream(context.Background(), "token_endpoint", url.Values{}); err == nil {
		t.Fatal("sent without the secret")
	}
}

func TestIssuerMustBeHTTPS(t *testing.T) {
	c := Config{Origin: "https://carrel.winlab.tw", Issuer: "http://sso.test/realms/x", PublicAddress: "192.0.2.1", Database: "db", Nodes: []NodeConfig{{Name: "n1", Target: "n1"}}}
	if c.Validate() == nil {
		t.Fatal("accepted an http issuer")
	}
}
