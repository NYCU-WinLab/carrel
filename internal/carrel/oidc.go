package carrel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

// OIDCConfig names what the identity provider at Config.Issuer calls
// things, so a lab can run Carrel on the provider it already has (#654).
// An empty field keeps WinLab's Keycloak value.
type OIDCConfig struct {
	// Audience is the aud every access token must carry.
	Audience string `json:"audience,omitempty"`
	// ClientID is the client Carrel signs members in with, and the azp
	// (or, without azp, the client_id of RFC 9068) a token must name.
	ClientID      string `json:"client_id,omitempty"`
	UsernameClaim string `json:"username_claim,omitempty"`
	GroupsClaim   string `json:"groups_claim,omitempty"`
	// AdminGroups and MemberGroups are path.Match patterns over group
	// names with any leading "/" removed; "*" does not cross a "/".
	AdminGroups  []string `json:"admin_groups,omitempty"`
	MemberGroups []string `json:"member_groups,omitempty"`
	// ProjectGroupPrefix maps a group <prefix><name> to the project tenant
	// <name>.
	ProjectGroupPrefix string `json:"project_group_prefix,omitempty"`
}

// projectSubject is how a project tenant's subject is stored, whatever
// prefix the provider uses, so tenants keep their records if the prefix
// changes.
const projectSubject = "winlab-projects/"

var winlabMemberGroups = []string{"lab-member/112", "lab-member/113", "lab-member/114", "lab-member/115", "lab-member/master", "lab-member/doctoral", "lab-member/undergrad", "lab-member/assistant", "lab-member/teacher"}

func (c OIDCConfig) WithDefaults() OIDCConfig {
	def := func(v *string, d string) {
		if *v == "" {
			*v = d
		}
	}
	def(&c.Audience, "carrel-mcp")
	def(&c.ClientID, "carrel-mcp")
	def(&c.UsernameClaim, "preferred_username")
	def(&c.GroupsClaim, "groups")
	def(&c.ProjectGroupPrefix, projectSubject)
	if len(c.AdminGroups) == 0 {
		c.AdminGroups = []string{"winlab-admin"}
	}
	if len(c.MemberGroups) == 0 {
		c.MemberGroups = winlabMemberGroups
	}
	return c
}

func (c OIDCConfig) Validate() error {
	for _, p := range append(append([]string{}, c.AdminGroups...), c.MemberGroups...) {
		if _, err := path.Match(p, ""); err != nil || p == "" || strings.HasPrefix(p, "/") {
			return fmt.Errorf("oidc: group pattern %q is not a valid pattern without a leading /", p)
		}
	}
	if strings.HasPrefix(c.ProjectGroupPrefix, "/") || strings.ContainsAny(c.ProjectGroupPrefix, "*?[") {
		return errors.New("oidc: project_group_prefix is a plain prefix without a leading /")
	}
	return nil
}

func matchesAny(patterns []string, g string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, g); ok {
			return true
		}
	}
	return false
}

// identity turns verified claims into a member, or refuses someone who is
// neither an admin nor a current member.
func (c OIDCConfig) identity(claims D) (D, error) {
	groups, ok := claims[c.GroupsClaim].([]any)
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
		admin = admin || matchesAny(c.AdminGroups, g)
		active = active || matchesAny(c.MemberGroups, g)
		if name, ok := strings.CutPrefix(g, c.ProjectGroupPrefix); ok && name != "" && !strings.Contains(name, "/") {
			projects = append(projects, projectSubject+name)
		}
	}
	username, ok := claims[c.UsernameClaim].(string)
	if !ok || username == "" || str(claims["sub"]) == "" || (!admin && !active) {
		return nil, errors.New("current lab membership required")
	}
	return D{"sub": claims["sub"], "username": username, "admin": admin, "projects": projects}, nil
}

// endpoints reads the provider's discovery document once and keeps it for
// the life of the process. A provider without one, or a discovery that
// fails, gets Keycloak's paths under the issuer, as before #654; a failed
// read is tried again after 30 seconds.
type endpoints struct {
	issuer string
	http   *http.Client
	mu     sync.Mutex
	doc    map[string]string
	tried  time.Time
}

var keycloakPaths = map[string]string{"jwks_uri": "certs", "authorization_endpoint": "auth", "token_endpoint": "token", "revocation_endpoint": "revoke"}

func newEndpoints(issuer string) *endpoints {
	return &endpoints{issuer: issuer, http: &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// url is the endpoint name (a discovery field such as token_endpoint) of
// issuer. A nil endpoints, as in tests that build OAuth by hand, always
// gets the Keycloak path.
func (p *endpoints) url(issuer, name string) string {
	if p != nil && p.issuer == issuer {
		p.mu.Lock()
		if p.doc == nil && time.Since(p.tried) > 30*time.Second {
			p.tried = time.Now()
			p.doc = p.load()
		}
		u := p.doc[name]
		p.mu.Unlock()
		if u != "" {
			return u
		}
	}
	return issuer + "/protocol/openid-connect/" + keycloakPaths[name]
}

func (p *endpoints) load() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", p.issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil
	}
	r, err := p.http.Do(req)
	if err != nil {
		return nil
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil
	}
	var doc map[string]any
	if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&doc) != nil || doc["issuer"] != p.issuer {
		return nil
	}
	issuer, _ := url.Parse(p.issuer)
	out := map[string]string{}
	for name := range keycloakPaths {
		s, _ := doc[name].(string)
		// An endpoint uses the issuer's scheme: discovery never moves a
		// token or a code to plain http.
		if u, err := url.Parse(s); err == nil && u.Scheme == issuer.Scheme && u.Host != "" && u.User == nil {
			out[name] = s
		}
	}
	return out
}
