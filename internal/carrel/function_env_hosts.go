package carrel

import (
	"context"
	"crypto/hpke"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
)

// Function environments sealed to the host (#639). The function host's
// agent makes an HPKE key pair (the suite of env_sets.go) and registers
// only the public key. A function_env upload is then sealed to the key of
// the host the function runs on, so carrel's database and configuration
// together open none of it. A value sealed this way is stored in the
// version's env field as "hpke1:<base64>": versions copy that field as
// they always did, and a rollback brings its values back.
//
// Values sealed under function_env_key before a host registered are
// sealed again to its key when it registers, while carrel can still open
// them. A host that registered no key gets values under function_env_key,
// as before.

const hostEnvPrefix = "hpke1:"

// functionEnvInfo binds a sealed environment to its function, by the id the
// host knows it by (functionHostID).
func functionEnvInfo(hostID string) []byte { return []byte("carrel-fn-env/v1\x00" + hostID) }

func hostIDOf(f D) string { return functionHostID(integer(f["tenant_n"]), str(f["name"])) }

// registryInfo binds sealed registry credentials to the function and the
// registry they are for.
func registryInfo(hostID, registry string) []byte {
	return []byte("carrel-fn-registry/v1\x00" + hostID + "\x00" + registry)
}

func hostSealed(sealed string) bool { return strings.HasPrefix(sealed, hostEnvPrefix) }

// hostEnvKey is the public key a function host registered, or "".
func (p *Platform) hostEnvKey(s *Store, host string) string {
	return str(s.SiteGet("function_host_keys", host)["public"])
}

// sealToHost seals pairs for a function, named by its host id, to a host's public key.
func sealToHost(public, hostID string, pairs []string) string {
	return sealBox(public, functionEnvInfo(hostID), pairs)
}

// sealBox seals v as JSON to a host's public key under info.
func sealBox(public string, info []byte, v any) string {
	raw, err := base64.StdEncoding.DecodeString(public)
	must(err)
	key, err := envSetKEM.NewPublicKey(raw)
	must(err)
	plain, err := json.Marshal(v)
	must(err)
	box, err := hpke.Seal(key, envSetKDF, envSetAEAD, info, plain)
	must(err)
	return hostEnvPrefix + base64.StdEncoding.EncodeToString(box)
}

// hostRegistryKey is the host's public key when its agent said it opens
// registry credentials too; an agent of #783 registered a key for
// environments only.
func (p *Platform) hostRegistryKey(s *Store, host string) string {
	rec := s.SiteGet("function_host_keys", host)
	if !boolean(rec["registry"]) {
		return ""
	}
	return str(rec["public"])
}

// sealRegistryFor seals a function's registry credentials: to its host's
// key when the host's agent opens them, else under function_env_key.
func (p *Platform) sealRegistryFor(s *Store, f D, auth D) string {
	if public := p.hostRegistryKey(s, str(f["host"])); public != "" {
		return sealBox(public, registryInfo(hostIDOf(f), str(auth["registry"])), auth)
	}
	return p.sealValue(str(f["id"])+"#registry", auth)
}

// sealFunctionEnvFor seals pairs for f: to its host's key when the host
// registered one, else under function_env_key.
func (p *Platform) sealFunctionEnvFor(s *Store, f D, pairs []string) string {
	if public := p.hostEnvKey(s, str(f["host"])); public != "" {
		return sealToHost(public, hostIDOf(f), pairs)
	}
	return p.sealFunctionEnv(str(f["id"]), pairs)
}

// AgentHostKey registers the public key of a function host. The first key
// is taken, and the host's values under function_env_key are sealed again
// to it. A different key is refused until an operator runs
// carrel -trust-function-host-key: values sealed to the old key do not open
// with it, so each function's environment must be uploaded again.
func (p *Platform) AgentHostKey(ctx context.Context, token, source string, body D) D {
	host := p.functionHostOf(token, source)
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
	registry := false
	for _, c := range arr(body["opens"]) {
		registry = registry || c == "registry"
	}
	p.writer.Lock()
	defer p.writer.Unlock()
	rec := p.Store.SiteGet("function_host_keys", host.Name)
	switch str(rec["public"]) {
	case public:
		moved := 0
		p.Store.Transaction(func(s *Store) {
			if rec["pending"] != nil || boolean(rec["registry"]) != registry {
				// The host came back with its trusted key: a key it no longer
				// uses must not be trusted later. What its agent opens
				// follows the agent's release.
				delete(rec, "pending")
				rec["registry"] = registry
				s.SitePut("function_host_keys", host.Name, rec)
			}
			// Values sealed under function_env_key since, or by a release
			// that sealed only environments, move now.
			moved = p.sealHostValues(s, host.Name, public)
		})
		if moved > 0 || boolean(rec["scrub"]) {
			scrubbed := p.scrubDatabase() == nil
			p.noteScrub(host.Name, scrubbed)
			p.Store.Log("host:"+host.Name, nil, "function_host_values_resealed", D{"host": host.Name, "resealed": moved, "scrubbed": scrubbed}, "ok")
		}
		return D{"state": "trusted", "fingerprint": keyFingerprint(public), "resealed": moved}
	case "":
	default:
		if str(rec["pending"]) != public {
			rec["pending"] = public
			p.Store.SitePut("function_host_keys", host.Name, rec)
			p.Store.Log("host:"+host.Name, nil, "function_host_key_changed", D{"host": host.Name, "fingerprint": keyFingerprint(public)}, "ok")
			slog.Error("function_host_key_changed", "host", host.Name, "fingerprint", keyFingerprint(public))
		}
		return D{"state": "pending", "fingerprint": keyFingerprint(public)}
	}
	moved := 0
	p.Store.Transaction(func(s *Store) {
		s.SitePut("function_host_keys", host.Name, D{"name": host.Name, "public": public, "at": now(), "registry": registry})
		moved = p.sealHostValues(s, host.Name, public)
	})
	scrubbed := moved == 0 || p.scrubDatabase() == nil
	p.noteScrub(host.Name, scrubbed)
	p.Store.Log("host:"+host.Name, nil, "function_host_key_register", D{"host": host.Name, "fingerprint": keyFingerprint(public), "resealed": moved, "scrubbed": scrubbed}, "ok")
	return D{"state": "trusted", "fingerprint": keyFingerprint(public), "resealed": moved}
}

// noteScrub records a scrub that failed, so the host's next registration
// runs it again.
func (p *Platform) noteScrub(host string, scrubbed bool) {
	rec := p.Store.SiteGet("function_host_keys", host)
	if rec == nil || boolean(rec["scrub"]) == !scrubbed {
		return
	}
	if scrubbed {
		delete(rec, "scrub")
	} else {
		rec["scrub"] = true
	}
	p.Store.SitePut("function_host_keys", host, rec)
}

// scrubDatabase removes copies of replaced rows from the database files:
// the write-ahead log keeps old frames after a commit, and a page freed by
// an update keeps its bytes. VACUUM rewrites the database, and a TRUNCATE
// checkpoint empties the log before and after. Backups taken earlier still
// hold the old values; they open only with function_env_key.
func (p *Platform) scrubDatabase() error {
	checkpoint := func() error {
		// A reader in another process (a backup) holds frames back: the
		// answer says so in its first column, not as an error.
		var busy, frames, done int
		if err := p.Store.DB.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &frames, &done); err != nil {
			return err
		}
		if busy != 0 {
			return fmt.Errorf("a reader kept the write-ahead log")
		}
		return nil
	}
	for _, step := range []func() error{checkpoint, func() error { _, err := p.Store.DB.Exec("VACUUM"); return err }, checkpoint} {
		if err := step(); err != nil {
			slog.Error("database_scrub_failed", "error", err, "next_action", "run sqlite3 <database> 'VACUUM; PRAGMA wal_checkpoint(TRUNCATE)' with no backup running")
			return err
		}
	}
	return nil
}

// sealHostValues seals every version environment of the host's functions
// still under function_env_key to public, and drops the old copy. A value
// no configured key opens is left as it is.
func (p *Platform) sealHostValues(s *Store, host, public string) int {
	if envAEAD(p.Config.FunctionEnvKey) == nil {
		return 0
	}
	moved := 0
	for _, f := range s.Objects("functions") {
		if str(f["host"]) != host {
			continue
		}
		fid, n := str(f["id"]), integer(f["tenant_n"])
		if sealed := str(f["registry_auth"]); sealed != "" && !hostSealed(sealed) && boolean(s.SiteGet("function_host_keys", host)["registry"]) {
			var auth D
			if attempt(func() { p.openValue(fid+"#registry", sealed, &auth) }) == nil && str(auth["registry"]) == str(f["registry"]) {
				f["registry_auth"] = sealBox(public, registryInfo(hostIDOf(f), str(f["registry"])), auth)
				s.Put("functions", fid, n, f)
				moved++
			}
		}
		for _, v := range s.Objects("function_versions", n) {
			sealed := str(v["env"])
			if str(v["function"]) != fid || sealed == "" || hostSealed(sealed) {
				continue
			}
			var pairs []string
			if attempt(func() { p.openValue(fid, sealed, &pairs) }) != nil {
				continue
			}
			v["env"] = sealToHost(public, hostIDOf(f), pairs)
			s.Put("function_versions", v["id"], n, v)
			moved++
		}
	}
	return moved
}

// TrustFunctionHostKey accepts the key a host registered after its first
// one, when the fingerprint matches. Run by an operator from the command
// line: a function host is the platform's, not a member's.
func (p *Platform) TrustFunctionHostKey(host, fingerprint string) (result D, err error) {
	if problem := attempt(func() {
		p.writer.Lock()
		defer p.writer.Unlock()
		rec := p.Store.SiteGet("function_host_keys", host)
		pending := str(rec["pending"])
		if pending == "" {
			fail("conflict", "The host "+host+" registered no new key")
		}
		if keyFingerprint(pending) != fingerprint {
			fail("invalid", "The fingerprint does not match the host's new key")
		}
		// What the new agent opens is known at its next registration.
		p.Store.SitePut("function_host_keys", host, D{"name": host, "public": pending, "at": now()})
		p.Store.Log("operator", nil, "function_host_key_trust", D{"host": host, "fingerprint": fingerprint}, "ok")
		result = D{"host": host, "fingerprint": fingerprint}
	}); problem != nil {
		return nil, fmt.Errorf("%v", problem)
	}
	return result, nil
}
