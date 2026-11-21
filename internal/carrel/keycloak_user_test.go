package carrel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// keycloak stands in for the realm's token and admin users routes.
func keycloak(t *testing.T, p *Platform, users string, status int) {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/lab/protocol/openid-connect/token":
			_ = r.ParseForm()
			if r.PostForm.Get("client_id") != "carrel" || r.PostForm.Get("client_secret") != "s3cret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"tok"}`))
		case "/admin/realms/lab/users":
			if r.Header.Get("Authorization") != "Bearer tok" || r.URL.Query().Get("exact") != "true" || r.URL.Query().Get("username") != "alice" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if status != http.StatusOK {
				w.WriteHeader(status)
				return
			}
			_, _ = w.Write([]byte(users))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Close)
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p.HTTP = s.Client()
	p.Config.KeycloakURL, p.Config.KeycloakRealm = s.URL, "lab"
	p.Config.KeycloakClientID, p.Config.KeycloakClientSecretFile = "carrel", secret
}

func TestKeycloakSub(t *testing.T) {
	one := `[{"id":"sub-1","username":"alice"}]`
	cases := []struct {
		name, users string
		status      int
		want, err   string
	}{
		{"one hit", one, 200, "sub-1", ""},
		{"no hit", `[]`, 200, "", "no user"},
		{"two hits", `[{"id":"a","username":"alice"},{"id":"b","username":"alice"}]`, 200, "", "2 users"},
		{"other name", `[{"id":"a","username":"alicia"}]`, 200, "", "no user"},
		{"case differs", `[{"id":"a","username":"Alice"}]`, 200, "", "no user"},
		{"blank id", `[{"id":"","username":"alice"}]`, 200, "", "no id"},
		{"blank id and id", `[{"id":"","username":"alice"},{"id":"b","username":"alice"}]`, 200, "", "2 users"},
		{"oversized", `[{"id":"a","username":"alice"}]` + strings.Repeat(" ", keycloakMaxBody), 200, "", "too large"},
		{"server error", ``, 500, "", "status 500"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, _ := fixture(t)
			keycloak(t, p, c.users, c.status)
			sub, err := (&Execution{P: p, Ctx: context.Background()}).keycloakSub("Alice")
			if c.err == "" {
				if err != nil || sub != c.want {
					t.Fatalf("got %q, %v", sub, err)
				}
				return
			}
			if err == nil || sub != "" || !strings.Contains(err.Error(), c.err) {
				t.Fatalf("got %q, %v; want error containing %q", sub, err, c.err)
			}
		})
	}
}

func TestKeycloakSubNotConfigured(t *testing.T) {
	p, _ := fixture(t)
	sub, err := (&Execution{P: p, Ctx: context.Background()}).keycloakSub("alice")
	if err == nil || sub != "" {
		t.Fatalf("got %q, %v", sub, err)
	}
}

func TestKeycloakConfigIsAllOrNothing(t *testing.T) {
	c := Config{Origin: "https://carrel.example", Issuer: "https://sso.example/realms/lab", PublicAddress: "192.0.2.1", Database: "db", Nodes: []NodeConfig{{Name: "n1", Target: "n1"}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.KeycloakURL = "https://sso.example"
	if err := c.Validate(); err == nil {
		t.Fatal("partial keycloak config accepted")
	}
	c.KeycloakRealm, c.KeycloakClientID, c.KeycloakClientSecretFile = "lab", "carrel", "/x"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []struct{ name, url, realm, issuer string }{
		{"http", "http://sso.example", "lab", "http://sso.example/realms/lab"},
		{"bare question mark", "https://sso.example/?", "lab", "https://sso.example/?/realms/lab"},
		{"fragment", "https://sso.example/#x", "lab", "https://sso.example/#x/realms/lab"},
		{"dot segment", "https://sso.example/../x", "lab", "https://sso.example/../x/realms/lab"},
		{"realm slash", "https://sso.example", "a/b", "https://sso.example/realms/a/b"},
		{"realm dot", "https://sso.example", ".", "https://sso.example/realms/."},
		{"realm dotdot", "https://sso.example", "..", "https://sso.example/realms/.."},
		{"realm query", "https://sso.example", "lab?x", "https://sso.example/realms/lab?x"},
		{"other realm", "https://sso.example", "other", "https://sso.example/realms/lab"},
		{"other host", "https://sso.other", "lab", "https://sso.example/realms/lab"},
	}
	for _, b := range bad {
		t.Run(b.name, func(t *testing.T) {
			d := c
			d.KeycloakURL, d.KeycloakRealm, d.Issuer = b.url, b.realm, b.issuer
			if err := d.Validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	c.KeycloakURL = "https://sso.example/"
	if err := c.Validate(); err != nil {
		t.Fatalf("trailing slash: %v", err)
	}
	c.Issuer = "https://sso.example/realms/lab/"
	if err := c.Validate(); err != nil {
		t.Fatalf("issuer trailing slash: %v", err)
	}
}
