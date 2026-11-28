package carrel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A service's environment (PLAN 7.11) never travels in tool arguments:
// service_env gives a single-use link, the member's agent pipes an
// environment file to it, and the values are kept encrypted with
// service_env_key. Each upload makes a new version from the current one,
// because the values are part of its snapshot. A version keeps the
// environment it was built with, so a rollback brings back its values too.
// The host gets the values in its desired state and writes them into the
// version's root file system.

const (
	serviceEnvLinkTTL = 15 * 60
	maxServiceEnv     = 64 << 10
	maxServiceEnvVars = 200
)

var serviceEnvKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// reservedServiceEnv are set by the platform for every service.
var reservedServiceEnv = map[string]bool{"PORT": true, "HOME": true}

// parseServiceEnv reads an environment file: KEY=VALUE lines, blank lines,
// comments, an optional "export " and one pair of matching quotes around a
// value. It returns the pairs in file order, a key given twice keeping its
// last value.
func parseServiceEnv(content []byte) []string {
	if len(content) > maxServiceEnv {
		fail("invalid", "The environment file exceeds 64 KiB")
	}
	if !utf8.Valid(content) {
		fail("invalid", "The environment file is not UTF-8")
	}
	values, order := map[string]string{}, []string{}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 4096), maxServiceEnv+1)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r"))
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		text = strings.TrimPrefix(text, "export ")
		key, value, ok := strings.Cut(text, "=")
		key = strings.TrimSpace(key)
		if !ok || !serviceEnvKeyRE.MatchString(key) {
			fail("invalid", "Line "+strconv.Itoa(line)+" is not KEY=VALUE with a key of letters, digits and _")
		}
		if reservedServiceEnv[key] {
			fail("invalid", key+" is set by the platform")
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if strings.IndexFunc(value, func(r rune) bool { return r < 0x20 && r != '\t' || r == 0x7f }) >= 0 {
			fail("invalid", "Line "+strconv.Itoa(line)+" holds a control character")
		}
		if _, seen := values[key]; !seen {
			order = append(order, key)
		}
		values[key] = value
	}
	if scanner.Err() != nil {
		fail("invalid", "The environment file could not be read")
	}
	if len(order) > maxServiceEnvVars {
		fail("invalid", "The environment file holds more than 200 variables")
	}
	pairs := []string{}
	for _, key := range order {
		pairs = append(pairs, key+"="+values[key])
	}
	return pairs
}

func envKeys(pairs []string) []string {
	keys := []string{}
	for _, pair := range pairs {
		key, _, _ := strings.Cut(pair, "=")
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (p *Platform) serviceEnvAEAD() cipher.AEAD {
	aead := envAEAD(p.Config.ServiceEnvKey)
	if aead == nil {
		fail("unavailable", "Service environments are not configured on this platform")
	}
	return aead
}

// envAEAD is the cipher for one key, or nil for a key that is not 32 bytes
// in standard base64.
func envAEAD(encoded string) cipher.AEAD {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if encoded == "" || err != nil || len(key) != 32 {
		return nil
	}
	block, err := aes.NewCipher(key)
	must(err)
	aead, err := cipher.NewGCM(block)
	must(err)
	return aead
}

// sealValue encrypts v under service_env_key. aad binds it to its place:
// a sealed value cannot be moved to another service or another use.
func (p *Platform) sealValue(aad string, v any) string {
	aead := p.serviceEnvAEAD()
	plain, err := json.Marshal(v)
	must(err)
	nonce := make([]byte, aead.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	must(err)
	return base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, []byte(aad)))
}

// openValue decrypts a value sealed by sealValue, with service_env_key or
// one of service_env_old_keys. A value no key opens fails with conflict:
// asking again does not help, so the service host gives up on the version.
func (p *Platform) openValue(aad, sealed string, out any) {
	aead := p.serviceEnvAEAD()
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil || len(raw) < aead.NonceSize() {
		fail("conflict", "A sealed service value is damaged; upload it again")
	}
	nonce, box := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, box, []byte(aad))
	for _, old := range p.Config.ServiceEnvOldKeys {
		if err == nil {
			break
		}
		if o := envAEAD(old); o != nil {
			plain, err = o.Open(nil, nonce, box, []byte(aad))
		}
	}
	if err != nil {
		slog.Error("service_value_open_failed", "aad", aad)
		fail("conflict", "A sealed service value cannot be decrypted with any configured key; upload it again")
	}
	if json.Unmarshal(plain, out) != nil {
		fail("conflict", "A sealed service value is damaged; upload it again")
	}
}

// sealServiceEnv encrypts pairs for one service, bound to its id.
func (p *Platform) sealServiceEnv(fid string, pairs []string) string {
	return p.sealValue(fid, pairs)
}

func (p *Platform) openServiceEnv(fid, sealed string) []string {
	if sealed == "" {
		return nil
	}
	var pairs []string
	p.openValue(fid, sealed, &pairs)
	return pairs
}

// serviceEnv runs service_env: a link to upload a new environment, or
// clear, which builds a version without one.
func (e *Execution) serviceEnv(a, w, t D) D {
	n, dry := integer(t["n"]), boolean(a["dry_run"])
	f := e.Service(t, a["service"])
	if e.P.hostEnvKey(e.S, str(f["host"])) == "" {
		e.P.serviceEnvAEAD()
	}
	if boolean(a["clear"]) {
		return e.newServiceVersion(t, f, nil, "", dry)
	}
	if dry {
		return D{"dry_run": true, "service": f["name"]}
	}
	for _, l := range e.S.Objects("service_env_links", n) {
		if num(l["expires"]) < now() {
			e.S.Remove("service_env_links", l["id"])
		}
	}
	token := "cfe_" + random(32)
	expires := now() + serviceEnvLinkTTL
	e.S.Put("service_env_links", digest(token), n, D{"id": digest(token), "tenant_n": n, "service": f["id"], "sub": w["sub"], "expires": expires})
	url := strings.TrimRight(e.P.Config.Origin, "/") + "/services/v1/env/" + token
	return D{
		"service": f["name"], "url": url, "expires_at": expires, "single_use": true,
		"upload":      "curl --fail-with-body -X PUT --data-binary @.env " + url,
		"next_action": "Run the upload line in the directory of the environment file. Its values replace the service's whole environment and a new version builds; follow it with service_get and wait_seconds. Never paste the values into a tool argument.",
	}
}

// newServiceVersion builds a version from the service's current spec
// with a new environment: env is the sealed environment, keys its names.
func (e *Execution) newServiceVersion(t, f D, keys []string, env string, dry bool, also ...func(*Execution)) D {
	if str(f["pending"]) != "" {
		fail("conflict", "A build of this service is in progress; follow it with service_get and wait_seconds", D{"pending": f["pending"]})
	}
	var base D
	for _, v := range e.ServiceVersions(f) {
		if v["version"] == f["current"] || (base == nil && str(f["current"]) == "") {
			base = v
		}
	}
	if base == nil {
		fail("conflict", "The service has no version to rebuild; deploy it first", D{"recovery": "resolve_prerequisite"})
	}
	spec := pick(base, serviceSpecKeys...)
	if keys == nil {
		keys = []string{}
	}
	return e.startServiceVersion(t, f, spec, D{}, D{"env": env, "env_keys": keys}, dry, also...)
}

// ReceiveServiceEnv takes an upload to a service_env link.
func (p *Platform) ReceiveServiceEnv(ctx context.Context, token string, body io.Reader) D {
	if !strings.HasPrefix(token, "cfe_") {
		fail("not_found", "Unknown or used link")
	}
	content, err := io.ReadAll(io.LimitReader(body, maxServiceEnv+1))
	if err != nil {
		fail("invalid", "Upload did not complete")
	}
	// Parse first: a file with a mistake leaves the link usable.
	pairs := parseServiceEnv(content)
	e := p.execution(ctx)
	p.writer.Lock()
	defer p.writer.Unlock()
	link := e.S.Get("service_env_links", digest(token))
	if link == nil || link["purpose"] != nil || num(link["expires"]) < now() {
		fail("not_found", "Unknown, used or expired link; ask service_env for a new one")
	}
	n := integer(link["tenant_n"])
	t := e.S.TenantN(n)
	if t == nil || t["status"] != "active" {
		fail("forbidden", "Tenant is suspended")
	}
	f := e.S.Get("services", str(link["service"]))
	if f == nil {
		e.S.Remove("service_env_links", link["id"])
		fail("not_found", "The service was removed")
	}
	sealed := p.sealServiceEnvFor(e.S, f, pairs)
	// The link goes in the same transaction as the version: no crash
	// between them leaves a used link that still works.
	r := e.newServiceVersion(t, f, envKeys(pairs), sealed, false, func(tx *Execution) {
		tx.S.Remove("service_env_links", link["id"])
	})
	p.Store.Log(str(link["sub"]), n, "service_env_upload", D{"service": f["name"], "keys": envKeys(pairs)}, "ok")
	return merge(r, D{"keys": envKeys(pairs)})
}

// ServiceEnvFor gives a host the values of one version it builds. Only the
// host the service runs on gets them.
func (p *Platform) ServiceEnvFor(token, source, service, version string) D {
	host := p.serviceHostOf(token, source)
	for _, f := range p.Store.Objects("services") {
		if f["host"] != host.Name || serviceHostID(integer(f["tenant_n"]), str(f["name"])) != service {
			continue
		}
		v := p.Store.Get("service_versions", serviceVersionID(str(f["id"]), version))
		if v == nil {
			break
		}
		if sealed := str(v["env"]); hostSealed(sealed) {
			// Only the host opens it.
			return D{"env_box": strings.TrimPrefix(sealed, hostEnvPrefix)}
		}
		env := p.openServiceEnv(str(f["id"]), str(v["env"]))
		if env == nil {
			env = []string{}
		}
		return D{"env": env}
	}
	fail("not_found", "No such version on this host")
	return nil
}

// sealedKey says which configured key opens a sealed value: "current", the
// index of an old key as "old:0", or "none".
func (p *Platform) sealedKey(aad, sealed string) string {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	keys := append([]string{p.Config.ServiceEnvKey}, p.Config.ServiceEnvOldKeys...)
	for i, k := range keys {
		aead := envAEAD(k)
		if aead == nil || err != nil || len(raw) < aead.NonceSize() {
			continue
		}
		if _, e := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(aad)); e == nil {
			if i == 0 {
				return "current"
			}
			return "old:" + strconv.Itoa(i-1)
		}
	}
	return "none"
}

// ResealServiceValues counts every stored sealed value per key: version
// environments and registry credentials. Unless dry, it seals again with
// service_env_key each value an old key opens, so that old key can be
// dropped once its count is zero. A value no key opens is counted as
// "none" and left alone.
func (p *Platform) ResealServiceValues(dry bool) (result D, err error) {
	if problem := attempt(func() { result = p.resealServiceValues(dry) }); problem != nil {
		return nil, fmt.Errorf("%v", problem)
	}
	return result, nil
}

func (p *Platform) resealServiceValues(dry bool) D {
	p.writer.Lock()
	defer p.writer.Unlock()
	counts := D{}
	resealed := 0
	reseal := func(s *Store, kind string, id any, n int, rec D, field, aad string) {
		sealed := str(rec[field])
		if sealed == "" {
			return
		}
		if hostSealed(sealed) {
			// Sealed to a service host's key: no configured key is involved.
			counts["host"] = integer(counts["host"]) + 1
			return
		}
		which := p.sealedKey(aad, sealed)
		counts[which] = integer(counts[which]) + 1
		if dry || !strings.HasPrefix(which, "old:") {
			return
		}
		var plain any
		p.openValue(aad, sealed, &plain)
		rec[field] = p.sealValue(aad, plain)
		s.Put(kind, id, n, rec)
		resealed++
	}
	p.serviceEnvAEAD()
	p.Store.Transaction(func(s *Store) {
		tenants := map[string]int{}
		for _, f := range s.Objects("services") {
			tenants[str(f["id"])] = integer(f["tenant_n"])
			reseal(s, "services", f["id"], integer(f["tenant_n"]), f, "registry_auth", str(f["id"])+"#registry")
		}
		for _, v := range s.Objects("service_versions") {
			fid := str(v["service"])
			if n, ok := tenants[fid]; ok {
				reseal(s, "service_versions", v["id"], n, v, "env", fid)
			}
		}
		for _, h := range s.Objects("webhooks") {
			id, n := str(h["id"]), integer(h["tenant_n"])
			reseal(s, "webhooks", id, n, h, "secret", "webhook:"+id)
			reseal(s, "webhooks", id, n, h, "previous_secret", "webhook:"+id+"#previous")
		}
	})
	slog.Info("service_values_resealed", "dry_run", dry, "counts", counts, "resealed", resealed)
	return D{"dry_run": dry, "counts": counts, "resealed": resealed}
}
