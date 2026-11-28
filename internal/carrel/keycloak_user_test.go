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
	keycloakFor(t, p, "alice", users, status)
}

// keycloakFor answers the admin users route for one username only.
func keycloakFor(t *testing.T, p *Platform, name, users string, status int) {
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
			if r.Header.Get("Authorization") != "Bearer tok" || r.URL.Query().Get("exact") != "true" || r.URL.Query().Get("username") != name {
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
	c := Config{Origin: "https://carrel.winlab.tw", Issuer: "https://sso.example/realms/lab", PublicAddress: "192.0.2.1", Database: "db", Nodes: []NodeConfig{{Name: "n1", Target: "n1"}}}
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
		{"realm semicolon", "https://sso.example", "lab;v=1", "https://sso.example/realms/lab;v=1"},
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

// keycloakMemberServer answers the token route and the per-user routes for sub "sub-1".
func keycloakMemberServer(t *testing.T, p *Platform, userStatus int, user string, groupsStatus int, groups string) {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		answer := func(status int, body string) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}
		if r.URL.Path == "/realms/lab/protocol/openid-connect/token" {
			_, _ = w.Write([]byte(`{"access_token":"tok"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/admin/realms/lab/users/sub-1":
			answer(userStatus, user)
		case "/admin/realms/lab/users/sub-1/groups":
			answer(groupsStatus, groups)
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

func TestKeycloakMember(t *testing.T) {
	const on, off = `{"id":"sub-1","enabled":true}`, `{"id":"sub-1","enabled":false}`
	cases := []struct {
		name         string
		userStatus   int
		user         string
		groupsStatus int
		groups       string
		state        MemberState
		paths        []string
		err          string
	}{
		{"enabled member", 200, on, 200, `[{"path":"/lab-member"}]`, MemberEnabled, []string{"/lab-member"}, ""},
		{"disabled member", 200, off, 200, `[{"path":"/lab-member"}]`, MemberDisabled, []string{"/lab-member"}, ""},
		{"alumni only", 200, on, 200, `[{"path":"/lab-member/alumni"}]`, MemberEnabled, []string{"/lab-member/alumni"}, ""},
		{"not found", 404, ``, 200, `[]`, MemberDisabled, nil, ""},
		{"user server error", 500, ``, 200, `[]`, MemberUnknown, nil, "status 500"},
		{"no rights", 403, ``, 200, `[]`, MemberUnknown, nil, "status 403"},
		{"groups server error", 200, on, 500, ``, MemberUnknown, nil, "status 500"},
		{"wrong id", 200, `{"id":"other","enabled":true}`, 200, `[]`, MemberUnknown, nil, "unexpected id"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, _ := fixture(t)
			keycloakMemberServer(t, p, c.userStatus, c.user, c.groupsStatus, c.groups)
			m, err := (&Execution{P: p, Ctx: context.Background()}).keycloakMember("sub-1")
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("got %v; want error containing %q", err, c.err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if m.State != c.state || strings.Join(m.Groups, ",") != strings.Join(c.paths, ",") {
				t.Fatalf("got %+v; want state %d groups %v", m, c.state, c.paths)
			}
		})
	}
}

func TestKeycloakMemberUnreachableAndNotConfigured(t *testing.T) {
	p, _ := fixture(t)
	keycloakMemberServer(t, p, 200, `{}`, 200, `[]`)
	p.Config.KeycloakURL = "https://127.0.0.1:1"
	m, err := (&Execution{P: p, Ctx: context.Background()}).keycloakMember("sub-1")
	if err == nil || m.State != MemberUnknown {
		t.Fatalf("unreachable: got %+v, %v", m, err)
	}
	p.Config.KeycloakURL = ""
	m, err = (&Execution{P: p, Ctx: context.Background()}).keycloakMember("sub-1")
	if err == nil || m.State != MemberUnknown {
		t.Fatalf("not configured: got %+v, %v", m, err)
	}
}
