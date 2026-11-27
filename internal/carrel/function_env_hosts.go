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

func hostSealed(sealed string) bool { return strings.HasPrefix(sealed, hostEnvPrefix) }

// hostEnvKey is the public key a function host registered, or "".
func (p *Platform) hostEnvKey(s *Store, host string) string {
	return str(s.SiteGet("function_host_keys", host)["public"])
}

// sealToHost seals pairs for a function, named by its host id, to a host's public key.
func sealToHost(public, hostID string, pairs []string) string {
	raw, err := base64.StdEncoding.DecodeString(public)
	must(err)
	key, err := envSetKEM.NewPublicKey(raw)
	must(err)
	plain, err := json.Marshal(pairs)
	must(err)
	box, err := hpke.Seal(key, envSetKDF, envSetAEAD, functionEnvInfo(hostID), plain)
	must(err)
	return hostEnvPrefix + base64.StdEncoding.EncodeToString(box)
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
	p.writer.Lock()
	defer p.writer.Unlock()
	rec := p.Store.SiteGet("function_host_keys", host.Name)
	switch str(rec["public"]) {
	case public:
		return D{"state": "trusted", "fingerprint": keyFingerprint(public)}
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
		s.SitePut("function_host_keys", host.Name, D{"name": host.Name, "public": public, "at": now()})
		moved = p.sealHostValues(s, host.Name, public)
	})
	p.Store.Log("host:"+host.Name, nil, "function_host_key_register", D{"host": host.Name, "fingerprint": keyFingerprint(public), "resealed": moved}, "ok")
	return D{"state": "trusted", "fingerprint": keyFingerprint(public), "resealed": moved}
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
		p.Store.SitePut("function_host_keys", host, D{"name": host, "public": pending, "at": now()})
		p.Store.Log("operator", nil, "function_host_key_trust", D{"host": host, "fingerprint": fingerprint}, "ok")
		result = D{"host": host, "fingerprint": fingerprint}
	}); problem != nil {
		return nil, fmt.Errorf("%v", problem)
	}
	return result, nil
}
