package carrel

import (
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Environment sets (#639): a member stores environment variables once and
// grants them to apps. Each app's carrel-deployd holds a key pair it made
// itself and registers only the public key. An upload is sealed to every
// granted app's public key with HPKE (RFC 9180) and the plain values are
// dropped, so the control plane's database and configuration together
// open none of them. The agent opens its copy and writes a root-only
// environment file for the app's unit.
//
// Known limit: a control plane under an attacker's control can register a
// false key for an app and read values uploaded after that. A key that
// changes after the first one waits for a member's env_trust, so a leaked
// agent token alone cannot do it.

const (
	envSetLinkTTL    = 15 * 60
	maxEnvSets       = 20
	maxEnvRecipients = 20
	envInfoPrefix    = "carrel-env/v1"
)

// The suite: hybrid ML-KEM-768 with X25519, so values stored today stay
// closed to a future quantum computer, then HKDF-SHA256 and AES-256-GCM.
var (
	envSetKEM  = hpke.MLKEM768X25519()
	envSetKDF  = hpke.HKDFSHA256()
	envSetAEAD = hpke.AES256GCM()
)

func envSetID(n int, name string) string { return fmt.Sprintf("%d-%s", n, name) }

// envInfo binds a sealed copy to its app, set and version: a copy cannot
// be served as another set's or another version's.
func envInfo(app, set string, version int) []byte {
	return []byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d", envInfoPrefix, app, set, version))
}

func keyFingerprint(public string) string {
	raw, _ := base64.StdEncoding.DecodeString(public)
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func (e *Execution) envSet(t D, name any) D {
	s := e.S.Get("env_sets", envSetID(integer(t["n"]), str(name)))
	if s == nil {
		fail("not_found", "Environment set not found")
	}
	return s
}

func envRecipients(s D) D {
	if r := obj(s["recipients"]); r != nil {
		return r
	}
	return D{}
}

func envSealed(s D) D {
	if r := obj(s["sealed"]); r != nil {
		return r
	}
	return D{}
}

// publicEnvSet shows names, versions and who reads them, never a value.
func (e *Execution) publicEnvSet(s D) D {
	out := pick(s, "name", "version", "keys", "created_at", "updated_at", "updated_by")
	sealed := envSealed(s)
	readers := []D{}
	ids := []string{}
	for id := range envRecipients(s) {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := obj(envRecipients(s)[id])
		state := "current"
		app := e.S.Get("apps", id)
		held := obj(sealed[id])
		switch {
		case app == nil:
			state = "app_unlinked"
		case str(app["env_key"]) == "":
			state = "waiting_for_key"
		case len(held) == 0 || integer(held["version"]) != integer(s["version"]):
			state = "waiting_for_upload"
		case str(app["env_key_pending"]) != "":
			state = "key_changed"
		}
		readers = append(readers, D{"app": r["app"], "state": state, "granted_at": r["granted_at"]})
	}
	out["apps"] = readers
	return out
}

// EnvTool runs env_list, env_upload, env_access, env_trust and env_remove.
func (e *Execution) EnvTool(tool string, a, w, t D) D {
	n, dry := integer(t["n"]), boolean(a["dry_run"])
	switch tool {
	case "env_list":
		sets := e.S.Objects("env_sets", n)
		sort.Slice(sets, func(i, j int) bool { return str(sets[i]["name"]) < str(sets[j]["name"]) })
		out := []D{}
		for _, s := range sets {
			out = append(out, e.publicEnvSet(s))
		}
		return D{"sets": out}
	case "env_upload":
		name := str(a["set"])
		s := e.S.Get("env_sets", envSetID(n, name))
		if s == nil {
			if len(e.S.Objects("env_sets", n)) >= maxEnvSets {
				fail("quota_exceeded", fmt.Sprintf("A tenant has at most %d environment sets", maxEnvSets))
			}
			s = D{"id": envSetID(n, name), "name": name, "tenant_n": n, "version": 0, "keys": []string{}, "recipients": D{}, "created_at": now()}
		}
		if dry {
			return D{"dry_run": true, "set": e.publicEnvSet(s)}
		}
		for _, l := range e.S.Objects("env_set_links", n) {
			if num(l["expires"]) < now() {
				e.S.Remove("env_set_links", l["id"])
			}
		}
		token := "cen_" + random(32)
		expires := now() + envSetLinkTTL
		e.Transaction(func(tx *Execution) {
			tx.S.Put("env_sets", s["id"], n, s)
			tx.S.Put("env_set_links", digest(token), n, D{"id": digest(token), "tenant_n": n, "set": s["id"], "sub": w["sub"], "expires": expires})
		})
		url := strings.TrimRight(e.P.Config.Origin, "/") + "/apps/v1/env/" + token
		next := "Run the upload line in the directory of the environment file. Its values replace the whole set and are sealed to each granted app that has registered its key. Never paste the values into a tool argument."
		if len(envRecipients(s)) == 0 {
			next = "Grant apps first with env_access: an upload is sealed only to apps already granted, and is refused when none can receive it. " + next
		}
		return D{"set": e.publicEnvSet(s), "url": url, "expires_at": expires, "single_use": true,
			"upload":      "curl --fail-with-body -X PUT --data-binary @.env " + url,
			"next_action": next}
	case "env_access":
		s := e.envSet(t, a["set"])
		recipients := envRecipients(s)
		sealed := envSealed(s)
		granted, revoked := []any{}, []any{}
		for _, name := range arr(a["revoke"]) {
			id := appID(n, str(name))
			if recipients[id] == nil {
				fail("not_found", "The app "+str(name)+" is not granted this set")
			}
			delete(recipients, id)
			delete(sealed, id)
			revoked = append(revoked, name)
		}
		for _, name := range arr(a["grant"]) {
			app := e.App(t, name)
			if recipients[str(app["id"])] == nil {
				recipients[str(app["id"])] = D{"app": app["name"], "granted_at": now()}
				granted = append(granted, app["name"])
			}
		}
		if len(recipients) > maxEnvRecipients {
			fail("quota_exceeded", fmt.Sprintf("A set is granted to at most %d apps", maxEnvRecipients))
		}
		s["recipients"], s["sealed"] = recipients, sealed
		if !dry {
			e.S.Put("env_sets", s["id"], n, s)
		}
		out := D{"dry_run": dry, "set": e.publicEnvSet(s), "granted": granted, "revoked": revoked}
		if len(granted) > 0 {
			out["next_action"] = "A granted app gets the values at the next upload: carrel holds no plain value to seal for it now. Call env_upload and upload the file again."
		}
		return out
	case "env_trust":
		app := e.App(t, a["app"])
		pending := str(app["env_key_pending"])
		if pending == "" {
			fail("conflict", "This app's agent has registered no new key")
		}
		if want := keyFingerprint(pending); str(a["fingerprint"]) != want {
			fail("invalid", "The fingerprint does not match the new key; compare it with the one carrel-deployd logged on the machine", D{"fingerprint": want})
		}
		if dry {
			return D{"dry_run": true, "app": app["name"], "fingerprint": keyFingerprint(pending)}
		}
		e.Transaction(func(tx *Execution) {
			app["env_key"], app["env_key_at"] = pending, now()
			delete(app, "env_key_pending")
			delete(app, "env_failed")
			tx.S.Put("apps", app["id"], n, app)
			// Copies sealed to the old key are no use to the new one.
			for _, s := range tx.S.Objects("env_sets", n) {
				if sealed := envSealed(s); sealed[str(app["id"])] != nil {
					delete(sealed, str(app["id"]))
					s["sealed"] = sealed
					tx.S.Put("env_sets", s["id"], n, s)
				}
			}
		})
		return D{"app": app["name"], "fingerprint": keyFingerprint(pending), "next_action": "Upload each set this app reads again with env_upload: values are sealed to the new key from the next upload."}
	case "env_remove":
		s := e.envSet(t, a["set"])
		if str(a["confirm"]) != str(s["name"]) {
			fail("invalid", "confirm must repeat the set name")
		}
		if !dry {
			e.Transaction(func(tx *Execution) {
				for _, l := range tx.S.Objects("env_set_links", n) {
					if l["set"] == s["id"] {
						tx.S.Remove("env_set_links", l["id"])
					}
				}
				tx.S.Remove("env_sets", s["id"])
			})
		}
		return D{"dry_run": dry, "removed": s["name"], "next_action": "Each app drops the set's values from its environment file at its next poll and restarts."}
	}
	fail("invalid", "Unknown tool")
	return nil
}

// dropEnvRecipients removes apps from every set they were granted, so a
// new app of the same name is not granted by accident.
func (e *Execution) dropEnvRecipients(n int, ids map[string]bool) {
	for _, s := range e.S.Objects("env_sets", n) {
		recipients, sealed, changed := envRecipients(s), envSealed(s), false
		for id := range ids {
			if recipients[id] != nil || sealed[id] != nil {
				delete(recipients, id)
				delete(sealed, id)
				changed = true
			}
		}
		if changed {
			s["recipients"], s["sealed"] = recipients, sealed
			e.S.Put("env_sets", s["id"], n, s)
		}
	}
}

// sealEnv seals pairs to one app's registered key.
func sealEnv(app D, set string, version int, pairs []string) string {
	raw, err := base64.StdEncoding.DecodeString(str(app["env_key"]))
	must(err)
	public, err := envSetKEM.NewPublicKey(raw)
	must(err)
	plain, err := json.Marshal(pairs)
	must(err)
	box, err := hpke.Seal(public, envSetKDF, envSetAEAD, envInfo(str(app["name"]), set, version), plain)
	must(err)
	return base64.StdEncoding.EncodeToString(box)
}

// ReceiveEnvSet takes an upload to an env_upload link. The plain values
// live only in this call: what is stored is one sealed copy per app.
func (p *Platform) ReceiveEnvSet(ctx context.Context, token string, body io.Reader) D {
	if !strings.HasPrefix(token, "cen_") {
		fail("not_found", "Unknown or used link")
	}
	content, err := io.ReadAll(io.LimitReader(body, maxFunctionEnv+1))
	if err != nil {
		fail("invalid", "Upload did not complete")
	}
	// Parse first: a file with a mistake leaves the link usable.
	pairs := parseFunctionEnv(content)
	e := p.execution(ctx)
	p.writer.Lock()
	defer p.writer.Unlock()
	link := e.S.Get("env_set_links", digest(token))
	if link == nil || num(link["expires"]) < now() {
		fail("not_found", "Unknown, used or expired link; ask env_upload for a new one")
	}
	n := integer(link["tenant_n"])
	if t := e.S.TenantN(n); t == nil || t["status"] != "active" {
		fail("forbidden", "Tenant is suspended")
	}
	s := e.S.Get("env_sets", str(link["set"]))
	if s == nil {
		e.S.Remove("env_set_links", link["id"])
		fail("not_found", "The set was removed")
	}
	version := integer(s["version"]) + 1
	sealed := D{}
	to, waiting := []string{}, []string{}
	for id, r := range envRecipients(s) {
		app := e.S.Get("apps", id)
		if app == nil || str(app["env_key"]) == "" {
			waiting = append(waiting, str(obj(r)["app"]))
			continue
		}
		sealed[id] = D{"version": version, "box": sealEnv(app, str(s["name"]), version, pairs)}
		to = append(to, str(app["name"]))
	}
	sort.Strings(to)
	sort.Strings(waiting)
	if len(to) == 0 {
		fail("conflict", "No granted app has registered its key, so nothing could be stored: grant apps with env_access, wait until their carrel-deployd has started, then upload again", D{"waiting_for_key": waiting})
	}
	s["version"], s["keys"], s["sealed"], s["updated_at"], s["updated_by"] = version, envKeys(pairs), sealed, now(), link["sub"]
	e.Transaction(func(tx *Execution) {
		tx.S.Put("env_sets", s["id"], n, s)
		tx.S.Remove("env_set_links", link["id"])
	})
	p.Store.Log(str(link["sub"]), n, "env_upload", D{"set": s["name"], "version": version, "keys": s["keys"], "sealed_to": to}, "ok")
	return D{"set": s["name"], "version": version, "keys": s["keys"], "sealed_to": to, "waiting_for_key": waiting}
}

// envFor is what an app's agent should hold: each set sealed to its key,
// in name order, and a revision naming that content.
func (p *Platform) envFor(app D) (string, []D) {
	sets := p.Store.Objects("env_sets", integer(app["tenant_n"]))
	sort.Slice(sets, func(i, j int) bool { return str(sets[i]["name"]) < str(sets[j]["name"]) })
	out, names := []D{}, []string{}
	for _, s := range sets {
		held := obj(envSealed(s)[str(app["id"])])
		if len(held) == 0 || envRecipients(s)[str(app["id"])] == nil {
			continue
		}
		out = append(out, D{"set": s["name"], "version": held["version"], "box": held["box"]})
		names = append(names, fmt.Sprintf("%s:%d", s["name"], integer(held["version"])))
	}
	if len(names) == 0 {
		return "", out
	}
	return digest(strings.Join(names, "\n"))[:16], out
}

// pendingEnv is the environment an agent with a registered key should
// apply now, or nil. A revision the agent failed to apply is not sent
// again until it changes.
func (p *Platform) pendingEnv(app D) D {
	if str(app["env_key"]) == "" {
		return nil
	}
	revision, sets := p.envFor(app)
	if revision == str(app["env_applied"]) || revision == str(app["env_failed"]) {
		return nil
	}
	return D{"revision": revision, "sets": sets}
}

// AgentEnvKey registers the public key an app's agent made. The first key
// is taken; a different one waits for env_trust.
func (p *Platform) AgentEnvKey(ctx context.Context, token string, body D) D {
	app := p.agentApp(token)
	if integer(body["kem"]) != int(envSetKEM.ID()) {
		fail("invalid", fmt.Sprintf("The key must be for HPKE KEM %#04x", envSetKEM.ID()))
	}
	public := str(body["public"])
	raw, err := base64.StdEncoding.DecodeString(public)
	if err != nil {
		fail("invalid", "The public key is not base64")
	}
	if _, err := envSetKEM.NewPublicKey(raw); err != nil {
		fail("invalid", "The public key is not valid")
	}
	p.writer.Lock()
	defer p.writer.Unlock()
	app = p.Store.Get("apps", str(app["id"]))
	if app == nil {
		fail("forbidden", "App was unlinked")
	}
	n := integer(app["tenant_n"])
	state := "trusted"
	switch str(app["env_key"]) {
	case public:
	case "":
		app["env_key"], app["env_key_at"] = public, now()
		p.Store.Put("apps", app["id"], n, app)
		p.Store.Log("agent:"+str(app["name"]), n, "env_key_register", D{"app": app["name"], "fingerprint": keyFingerprint(public)}, "ok")
	default:
		state = "pending"
		if str(app["env_key_pending"]) != public {
			app["env_key_pending"] = public
			p.Store.Put("apps", app["id"], n, app)
			p.Store.Log("agent:"+str(app["name"]), n, "env_key_changed", D{"app": app["name"], "fingerprint": keyFingerprint(public)}, "ok")
		}
	}
	return D{"state": state, "fingerprint": keyFingerprint(public)}
}

// AgentEnvReport records whether the agent applied a revision. A read of
// the values is the agent opening them, so it goes to the audit log here.
func (p *Platform) AgentEnvReport(ctx context.Context, token string, body D) D {
	app := p.agentApp(token)
	p.writer.Lock()
	defer p.writer.Unlock()
	app = p.Store.Get("apps", str(app["id"]))
	if app == nil {
		fail("forbidden", "App was unlinked")
	}
	n := integer(app["tenant_n"])
	revision := str(body["revision"])
	if message := str(body["error"]); message != "" {
		app["env_failed"], app["env_error"] = revision, truncate(message, 500)
		p.Store.Put("apps", app["id"], n, app)
		p.Store.Log("agent:"+str(app["name"]), n, "env_apply", D{"app": app["name"], "revision": revision, "error": app["env_error"]}, "error")
		return D{}
	}
	current, sets := p.envFor(app)
	if revision != current {
		// An older revision finished after a newer one was sent: keep asking.
		return D{}
	}
	app["env_applied"] = revision
	delete(app, "env_failed")
	delete(app, "env_error")
	p.Store.Put("apps", app["id"], n, app)
	read := []string{}
	for _, s := range sets {
		read = append(read, fmt.Sprintf("%s:%d", s["set"], integer(s["version"])))
	}
	p.Store.Log("agent:"+str(app["name"]), n, "env_read", D{"app": app["name"], "sets": read}, "ok")
	return D{}
}

// publicAppEnv is the app's key and delivery state for app_get, or nil
// for an agent that predates environment sets.
func publicAppEnv(app D) D {
	if str(app["env_key"]) == "" {
		return nil
	}
	out := D{"fingerprint": keyFingerprint(str(app["env_key"]))}
	if pending := str(app["env_key_pending"]); pending != "" {
		out["new_key_fingerprint"] = keyFingerprint(pending)
		out["next_action"] = "The agent registered a different key. If the machine was rebuilt, compare the fingerprint with carrel-deployd's log and call env_trust."
	}
	if e := str(app["env_error"]); e != "" {
		out["error"] = e
	}
	return out
}
