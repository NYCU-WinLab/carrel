package carrel

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/google/go-containerregistry/pkg/name"
)

// Private registries (PLAN 7.11): a service's host pulls its image with
// credentials the member gives through a single-use link, as for the
// environment, so a token never passes through tool arguments. The
// credentials are kept sealed on the service, bound to one registry: the
// host sends them only to that registry, whatever image a later deploy
// names. Credentials are no part of a snapshot, so a change builds nothing;
// the next build uses them.

const maxRegistryUpload = 16 << 10

// registryOf is the registry host of an image reference, as the host's
// puller names it (docker.io is index.docker.io).
func registryOf(image string) string {
	ref, err := name.ParseReference(image)
	if err != nil {
		fail("invalid", "Invalid image reference")
	}
	return ref.Context().RegistryStr()
}

func (e *Execution) serviceRegistry(a, w, t D) D {
	n, dry := integer(t["n"]), boolean(a["dry_run"])
	f := e.Service(t, a["service"])
	if e.P.hostEnvKey(e.S, str(f["host"])) == "" {
		e.P.serviceEnvAEAD()
	}
	if boolean(a["clear"]) {
		cleared := f["registry"]
		if !dry {
			delete(f, "registry")
			delete(f, "registry_auth")
			e.Transaction(func(tx *Execution) {
				tx.Put("services", f["id"], n, f)
				// A link not used yet must not bring the credentials back.
				for _, l := range tx.S.Objects("service_env_links", n) {
					if l["service"] == f["id"] && l["purpose"] == "registry" {
						tx.S.Remove("service_env_links", l["id"])
					}
				}
				tx.bumpServices()
			})
		}
		return D{"dry_run": dry, "service": f["name"], "cleared": cleared}
	}
	registry := str(a["registry"])
	if registry == "" {
		image := ""
		for _, v := range e.ServiceVersions(f) {
			if image == "" || v["version"] == f["current"] {
				image = str(v["image"])
			}
		}
		if image == "" {
			fail("invalid", "Give registry, such as ghcr.io")
		}
		registry = registryOf(image)
	} else {
		registry = registryOf(registry + "/x/y")
	}
	if dry {
		return D{"dry_run": true, "service": f["name"], "registry": registry}
	}
	for _, l := range e.S.Objects("service_env_links", n) {
		if num(l["expires"]) < now() {
			e.S.Remove("service_env_links", l["id"])
		}
	}
	token := "cfr_" + random(32)
	expires := now() + serviceEnvLinkTTL
	e.S.Put("service_env_links", digest(token), n, D{"id": digest(token), "tenant_n": n, "service": f["id"], "sub": w["sub"], "expires": expires, "purpose": "registry", "registry": registry})
	url := strings.TrimRight(e.P.Config.Origin, "/") + "/services/v1/registry/" + token
	return D{
		"service": f["name"], "registry": registry, "url": url, "expires_at": expires, "single_use": true,
		// jq quotes any password; printf, the fallback, breaks on a quote or a
		// backslash (the upload then answers 400, nothing leaks).
		"upload":      `{ if command -v jq >/dev/null; then jq -n --arg u "$REGISTRY_USER" --arg p "$REGISTRY_TOKEN" '{username:$u,password:$p}'; else printf '{"username":"%s","password":"%s"}' "$REGISTRY_USER" "$REGISTRY_TOKEN"; fi; } | curl --fail-with-body -X PUT --data-binary @- ` + url,
		"next_action": "Check that registry names the registry you mean: without registry it is the current image's, which any member of the tenant can set. Set REGISTRY_USER and REGISTRY_TOKEN in the shell (for ghcr.io: a GitHub user and a token with read:packages, such as `gh auth token` when it has that scope), then run the upload line. Never paste the token into a tool argument. Then deploy, or deploy again if a build failed to pull.",
	}
}

// ReceiveServiceRegistry takes an upload to a service_registry link.
func (p *Platform) ReceiveServiceRegistry(ctx context.Context, token string, body io.Reader) D {
	if !strings.HasPrefix(token, "cfr_") {
		fail("not_found", "Unknown or used link")
	}
	content, err := io.ReadAll(io.LimitReader(body, maxRegistryUpload+1))
	if err != nil || len(content) > maxRegistryUpload {
		fail("invalid", "The upload must be at most 16 KiB")
	}
	var auth struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.Unmarshal(content, &auth) != nil || auth.Username == "" || auth.Password == "" ||
		!utf8.ValidString(auth.Username+auth.Password) || strings.ContainsAny(auth.Username+auth.Password, "\x00\r\n") {
		fail("invalid", `Send {"username": "...", "password": "..."} with both set`)
	}
	e := p.execution(ctx)
	p.writer.Lock()
	defer p.writer.Unlock()
	link := e.S.Get("service_env_links", digest(token))
	if link == nil || link["purpose"] != "registry" || num(link["expires"]) < now() {
		fail("not_found", "Unknown, used or expired link; ask service_registry for a new one")
	}
	n := integer(link["tenant_n"])
	if t := e.S.TenantN(n); t == nil || t["status"] != "active" {
		fail("forbidden", "Tenant is suspended")
	}
	f := e.S.Get("services", str(link["service"]))
	if f == nil {
		e.S.Remove("service_env_links", link["id"])
		fail("not_found", "The service was removed")
	}
	registry := str(link["registry"])
	f["registry"] = registry
	f["registry_auth"] = p.sealRegistryFor(e.S, f, D{"registry": registry, "username": auth.Username, "password": auth.Password})
	e.Transaction(func(tx *Execution) {
		tx.Put("services", f["id"], n, f)
		tx.S.Remove("service_env_links", link["id"])
		tx.bumpServices()
	})
	p.Store.Log(str(link["sub"]), n, "service_registry_upload", D{"service": f["name"], "registry": registry}, "ok")
	return D{"service": f["name"], "registry": registry}
}

// serviceAuthFor is what a version's build sends to the registry: the
// service's credentials when its image is on their registry, else nil.
func (p *Platform) serviceAuthFor(f, v D) D {
	sealed := str(f["registry_auth"])
	if sealed == "" {
		return nil
	}
	ref, err := name.ParseReference(str(v["image"]))
	if err != nil || ref.Context().RegistryStr() != str(f["registry"]) {
		return nil
	}
	var auth D
	p.openValue(str(f["id"])+"#registry", sealed, &auth)
	if str(auth["registry"]) != str(f["registry"]) {
		return nil
	}
	return auth
}

// hasServiceAuth says, without opening them, whether the service's
// credentials go with v's image.
func hasServiceAuth(f, v D) bool {
	ref, err := name.ParseReference(str(v["image"]))
	return str(f["registry_auth"]) != "" && err == nil && ref.Context().RegistryStr() == str(f["registry"])
}

// ServiceAuthFor gives a host the credentials to pull one version's image.
func (p *Platform) ServiceAuthFor(token, source, service, version string) D {
	host := p.serviceHostOf(token, source)
	for _, f := range p.Store.Objects("services") {
		if f["host"] != host.Name || serviceHostID(integer(f["tenant_n"]), str(f["name"])) != service {
			continue
		}
		v := p.Store.Get("service_versions", serviceVersionID(str(f["id"]), version))
		if sealed := str(f["registry_auth"]); v != nil && hostSealed(sealed) && hasServiceAuth(f, v) {
			// Only the host opens it.
			return D{"auth_box": strings.TrimPrefix(sealed, hostEnvPrefix), "registry": f["registry"]}
		}
		if auth := p.serviceAuthFor(f, obj(v)); v != nil && auth != nil {
			return D{"auth": pick(auth, "registry", "username", "password")}
		}
		break
	}
	fail("not_found", "No credentials for this version on this host")
	return nil
}
