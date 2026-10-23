package carrel

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Zones (PLAN 6.10): the DNS zones special domains can live in. The site's
// own zone, winlab.tw, comes from the configuration and is open to every
// tenant. Admins add others with zone_add: the zone's Cloudflare token is a
// server secret, kept in a 0600 file under zone_dir and never in the
// database, the audit log or a result. A zone is open to every tenant or to
// the tenants it names.

// zoneAccess is what a DNS call needs.
type zoneAccess struct {
	Name  string
	ID    string
	Token string
}

// zoneRecord is an added zone, kept in the site table.
type zoneRecord struct {
	AddedAt int64  `json:"added_at"`
	AddedBy string `json:"added_by"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	Tenants []int  `json:"tenants,omitempty"`
}

var zonePattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// siteZone is the site's own zone.
func (e *Execution) siteZone() zoneAccess {
	return zoneAccess{Name: specialZone, ID: str(e.P.Config["cloudflare_zone"]), Token: str(e.P.Config["cloudflare_token"])}
}

func (e *Execution) zones() []zoneRecord {
	out := []zoneRecord{}
	for _, d := range e.S.SiteRows("zone") {
		var z zoneRecord
		must(json.Unmarshal(encoded(d), &z))
		out = append(out, z)
	}
	return out
}

func (e *Execution) zoneDir() string { return textAt(e.P.Config, "zone_dir", "/var/lib/carrel/zones") }

func (e *Execution) zoneTokenPath(name string) string {
	return filepath.Join(e.zoneDir(), name+".token")
}

// zoneNamed gives the access of a managed zone by its name.
func (e *Execution) zoneNamed(name string) zoneAccess {
	if name == "" || name == specialZone {
		return e.siteZone()
	}
	for _, z := range e.zones() {
		if z.Name == name {
			token, err := os.ReadFile(e.zoneTokenPath(z.Name))
			if err != nil {
				fail("backend_unavailable", "The zone's DNS token is missing", D{"component": "cloudflare", "backend_code": "zone_token_missing", "recovery": "retry_infrastructure"})
			}
			return zoneAccess{Name: z.Name, ID: z.ID, Token: strings.TrimSpace(string(token))}
		}
	}
	fail("not_found", "This zone is not managed by carrel")
	return zoneAccess{}
}

// zoneOf names the managed zone name belongs to: the longest zone it equals
// or sits under. ok is false outside every managed zone.
func (e *Execution) zoneOf(name string) (zone string, ok bool) {
	name = strings.TrimPrefix(name, "*.")
	if under(name, specialZone) {
		zone, ok = specialZone, true
	}
	for _, z := range e.zones() {
		if under(name, z.Name) && len(z.Name) > len(zone) {
			zone, ok = z.Name, true
		}
	}
	return zone, ok
}

// zoneFor gives the access of the zone name belongs to.
func (e *Execution) zoneFor(name string) zoneAccess {
	zone, ok := e.zoneOf(name)
	if !ok {
		fail("invalid", "This name is in no zone carrel manages", D{"recovery": "revise_request"})
	}
	return e.zoneNamed(zone)
}

// zoneOpen reports whether tenant n may request names in zone.
func (e *Execution) zoneOpen(zone string, n int) bool {
	if zone == specialZone {
		return true
	}
	for _, z := range e.zones() {
		if z.Name == zone {
			return len(z.Tenants) == 0 || slices.Contains(z.Tenants, n)
		}
	}
	return false
}

// publicZone is a zone as zone_list shows it: no id beyond Cloudflare's, no
// token.
func (e *Execution) publicZone(z zoneRecord) D {
	tenants := []any{}
	for _, n := range z.Tenants {
		if t := e.S.TenantN(n); t != nil {
			tenants = append(tenants, t["slug"])
		}
	}
	p := D{"name": z.Name, "zone_id": z.ID, "open_to": "all", "added_at": z.AddedAt}
	if len(tenants) > 0 {
		p["open_to"] = tenants
	}
	return p
}

// ZoneAction runs zone_add, zone_list and zone_remove.
func (e *Execution) ZoneAction(tool string, a, w D) D {
	dry := boolean(a["dry_run"])
	switch tool {
	case "zone_list":
		out := []D{{"name": specialZone, "open_to": "all", "site": true}}
		for _, z := range e.zones() {
			out = append(out, e.publicZone(z))
		}
		return D{"zones": out}
	case "zone_remove":
		name := strings.ToLower(str(a["name"]))
		if strings.ToLower(str(a["confirm"])) != name {
			fail("invalid", "confirm must equal the zone name")
		}
		if name == specialZone {
			fail("invalid", "The site's own zone cannot be removed")
		}
		if find(e.S.SiteRows("zone"), func(d D) bool { return d["name"] == name }) == nil {
			fail("not_found", "This zone is not managed by carrel")
		}
		for _, g := range e.grants() {
			if g.zone() == name {
				fail("conflict", "Special domains in this zone are still granted: "+g.Name, D{"recovery": "resolve_prerequisite"})
			}
		}
		for _, r := range e.S.Objects("requests") {
			if r["kind"] == "domain" && r["status"] == "pending" && r["zone"] == name {
				fail("conflict", "A pending request asks for a name in this zone", D{"recovery": "resolve_prerequisite"})
			}
		}
		if !dry {
			e.S.SiteRemove("zone", name)
			_ = os.Remove(e.zoneTokenPath(name))
		}
		return D{"zone": D{"name": name, "state": "removed"}, "dry_run": dry}
	}
	// zone_add: a new zone, or a new token and tenant list for one.
	name := strings.ToLower(strings.TrimSuffix(str(a["name"]), "."))
	if !zonePattern.MatchString(name) || len(name) > 253 {
		fail("invalid", "Give the zone as its lowercase DNS name")
	}
	if under(name, specialZone) || under(specialZone, name) {
		fail("invalid", "The site's own zone is configured, not added")
	}
	for _, z := range e.zones() {
		if z.Name != name && (under(name, z.Name) || under(z.Name, name)) {
			fail("conflict", "This zone overlaps the managed zone "+z.Name)
		}
	}
	old := e.S.SiteGet("zone", name)
	tenants := []int{}
	if old != nil && a["tenants"] == nil {
		// A new token alone keeps the zone's tenants.
		for _, n := range arr(old["tenants"]) {
			tenants = append(tenants, integer(n))
		}
	}
	for _, slug := range arr(a["tenants"]) {
		t := find(e.S.Tenants(), func(t D) bool { return t["slug"] == slug })
		if t == nil {
			fail("not_found", "Tenant not found: "+str(slug))
		}
		if !slices.Contains(tenants, integer(t["n"])) {
			tenants = append(tenants, integer(t["n"]))
		}
	}
	// The token comes as an argument, or, so that it never passes through
	// a client, from zone_dir/<zone>.token placed by an admin over SSH
	// (issue #161).
	token, fromFile := strings.TrimSpace(str(a["token"])), false
	if token == "" {
		b, err := os.ReadFile(e.zoneTokenPath(name))
		if err != nil {
			fail("invalid", "Give token, or first place it on the control plane as "+name+".token in the zone directory (zone_dir, /var/lib/carrel/zones by default)", D{"recovery": "resolve_prerequisite"})
		}
		token, fromFile = strings.TrimSpace(string(b)), true
	}
	if !matches(`^[A-Za-z0-9_-]{20,200}$`, token) {
		fail("invalid", "The token is not a Cloudflare API token", D{"recovery": "revise_request"})
	}
	// The token must find exactly this zone and read its records. A token
	// Cloudflare refuses is the caller's to fix, not a retry.
	var found []D
	if err := attempt(func() { found = dicts(e.cloudflare(token, "GET", "/zones?name="+url.QueryEscape(name), nil)["result"]) }); err != nil {
		if f, ok := err.(Failure); ok && integer(obj(f.Result["error"])["http_status"]) >= 400 && integer(obj(f.Result["error"])["http_status"]) < 500 {
			fail("invalid", "Cloudflare refused the token", D{"recovery": "revise_request"})
		}
		panic(err)
	}
	if len(found) != 1 || found[0]["name"] != name {
		fail("conflict", "The token does not see exactly this zone in Cloudflare")
	}
	if found[0]["status"] != nil && found[0]["status"] != "active" {
		fail("conflict", "The zone is not active in Cloudflare yet; finish its name servers first")
	}
	z := zoneRecord{ID: str(found[0]["id"]), Name: name, Tenants: tenants, AddedBy: str(w["sub"]), AddedAt: time.Now().Unix()}
	if !matches(`^[0-9a-f]{32}$`, z.ID) {
		fail("conflict", "Cloudflare returned an unexpected zone id")
	}
	if old != nil && str(old["id"]) != z.ID {
		for _, g := range e.grants() {
			if g.zone() == name {
				fail("conflict", "The token sees another Cloudflare zone of this name while names in it are granted", D{"recovery": "resolve_prerequisite"})
			}
		}
	}
	access := zoneAccess{Name: name, ID: z.ID, Token: token}
	e.cfIn(access, "GET", "?per_page=1", nil)
	if !dry {
		// A probe record proves the token may write; it goes at once. One
		// that a failed run left behind goes first.
		for _, r := range dicts(e.cfIn(access, "GET", "?type=TXT&name=_carrel-probe."+name, nil)["result"]) {
			if r["comment"] == "carrel:zone-probe" {
				e.cfIn(access, "DELETE", "/"+str(r["id"]), nil)
			}
		}
		probe := e.cfIn(access, "POST", "", D{"type": "TXT", "name": "_carrel-probe." + name, "content": "carrel zone check", "ttl": 60, "proxied": false, "comment": "carrel:zone-probe"})
		e.cfIn(access, "DELETE", "/"+str(obj(probe["result"])["id"]), nil)
		must(os.MkdirAll(e.zoneDir(), 0700))
		path := e.zoneTokenPath(name)
		if !fromFile {
			must(os.WriteFile(path+".next", []byte(token+"\n"), 0600))
			must(os.Rename(path+".next", path))
		}
		must(os.Chmod(path, 0600))
		if old != nil {
			z.AddedAt, z.AddedBy = int64(num(old["added_at"])), str(old["added_by"])
		}
		e.S.SitePut("zone", name, decode(string(encoded(z))))
	}
	return D{"zone": e.publicZone(z), "dry_run": dry}
}
