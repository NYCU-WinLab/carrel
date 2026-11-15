package carrel

import (
	"context"
	"io"
	"net/url"
	"regexp"
	"strings"
)

// Pull mode (issue #266) deploys from any git repository, with no CI and no
// OIDC. carrel-deployd on the machine watches the linked branch with git
// ls-remote, every minute or as soon as the app's webhook is called, fetches
// a new commit as the app user, runs the build command there and uploads the
// result as a release. From there a release is a release: carrel stores it,
// the agent switches it, app_deploy and app_rollback work as in push mode.
//
// The webhook only says that something changed; the branch of the linked
// URL is still what gets built, so calling it cannot deploy anything else.
// carrel never clones: a control plane that fetched any URL a member names
// would reach into the platform network. The deploy key is made on the
// machine, so carrel only ever sees its public half.

var (
	shaRE       = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	cloneURLRE  = regexp.MustCompile(`^(https://|ssh://)[A-Za-z0-9._~@:/+-]+$`)
	scpLikeRE   = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[A-Za-z0-9._~/+-]+$`)
	ownerNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)
	deployKeyRE = regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/]{68}(==?)?( [A-Za-z0-9@._-]{0,64})?$`)
	maxBuildLog = 8192
)

// parseCloneURL reads a pull-mode repo: an https or ssh clone URL, the
// scp-like user@host:path form, or a GitHub owner/name. Local paths and git's
// other transports (file://, ext::) are refused: the agent runs git as the
// app user, and a URL must name a remote.
func parseCloneURL(raw string) string {
	u := strings.TrimSpace(raw)
	switch {
	case ownerNameRE.MatchString(u):
		return "https://github.com/" + strings.ToLower(u) + ".git"
	case scpLikeRE.MatchString(u):
		return u
	case cloneURLRE.MatchString(u):
		parsed, err := url.Parse(u)
		if err != nil || parsed.Host == "" || strings.HasPrefix(parsed.Host, "-") || strings.Trim(parsed.Path, "/") == "" || strings.Contains(u, "..") {
			break
		}
		if _, hasPassword := parsed.User.Password(); hasPassword || (parsed.Scheme == "https" && parsed.User != nil) {
			fail("invalid", "Put no credentials in the URL. For a private repository use an ssh URL and the deploy key app_get shows after install.")
		}
		return u
	}
	fail("invalid", "repo must be a clone URL: https://host/path, ssh://user@host/path or user@host:path")
	return ""
}

func pullNextSteps(app D) []string {
	return []string{
		"Run install on the machine over SSH with the agent token on its standard input, from the client: printf '%s\\n' <agent_token> | ssh <machine> <install, quoted for the remote shell>. It needs sudo.",
		"For a private repository, add the deploy key that app_get shows after install to the repository as a read-only deploy key. A public https URL needs none.",
		"The agent checks the branch every minute. For a deploy within seconds, have the repository call webhook_url (POST, any body) on push. Keep webhook_url secret: anyone with it can make the agent check, though only the linked branch is ever built.",
		"Write runtime secrets to /srv/apps/" + str(app["name"]) + "/env on the machine; they never pass through carrel.",
		"Publish the port with domain_add when the app should answer on HTTPS.",
	}
}

// Poke marks a pull-mode app for a check now. An unknown token is not found.
func (p *Platform) Poke(token string) {
	if !strings.HasPrefix(token, "cdh_") {
		fail("not_found", "Webhook not found")
	}
	h := digest(token)
	p.writer.Lock()
	defer p.writer.Unlock()
	app := find(p.Store.Objects("apps"), func(a D) bool { return a["mode"] == "pull" && secureEqual(str(a["hook_token"]), h) })
	if app == nil {
		fail("not_found", "Webhook not found")
	}
	if t := p.Store.TenantN(integer(app["tenant_n"])); t == nil || t["status"] != "active" {
		fail("not_found", "Webhook not found")
	}
	app["poked_at"] = now()
	p.Store.Put("apps", app["id"], integer(app["tenant_n"]), app)
}

func (p *Platform) clearPoke(app D) {
	p.writer.Lock()
	defer p.writer.Unlock()
	if current := p.Store.Get("apps", str(app["id"])); current != nil {
		current["poked_at"] = 0
		p.Store.Put("apps", current["id"], integer(current["tenant_n"]), current)
	}
}

// AgentSource tells a pull-mode agent what to watch and build. The agent
// asks again on every check, so app changes reach it without a reinstall.
func (p *Platform) AgentSource(token string) D {
	app := p.agentApp(token)
	if app["mode"] != "pull" {
		return D{"mode": "push"}
	}
	return D{"mode": "pull", "url": app["repo"], "branch": app["branch"], "build": app["build"]}
}

// ReceiveAgentRelease stores what a pull-mode agent built from commit sha.
func (p *Platform) ReceiveAgentRelease(ctx context.Context, token, sha string, length int64, body io.Reader) D {
	if !shaRE.MatchString(sha) {
		fail("invalid", "X-Carrel-Sha must be the full commit hash")
	}
	e := p.execution(ctx)
	find := func() D {
		app := p.agentApp(token)
		if app["mode"] != "pull" {
			fail("forbidden", "Only a pull-mode app takes releases from its agent")
		}
		return app
	}
	app := find()
	meta := D{"sha": sha, "ref": "refs/heads/" + str(app["branch"]), "source": "machine"}
	return p.storeRelease(e, find, meta, "agent:"+str(app["id"]), "", length, body)
}

func (p *Platform) reportDeployKey(ctx context.Context, app D, key string) D {
	if !deployKeyRE.MatchString(key) {
		fail("invalid", "deploy_key must be one ssh-ed25519 public key")
	}
	p.writer.Lock()
	defer p.writer.Unlock()
	app = p.Store.Get("apps", str(app["id"]))
	if app == nil {
		fail("forbidden", "App was unlinked")
	}
	app["deploy_key"], app["agent_seen_at"] = key, now()
	p.Store.Put("apps", app["id"], integer(app["tenant_n"]), app)
	return D{"ok": true}
}

// reportFailedBuild records a commit whose fetch or build failed on the
// machine, so app_get shows why nothing was deployed. It has no artifact.
func (p *Platform) reportFailedBuild(ctx context.Context, app D, body D) D {
	sha := str(body["sha"])
	if !shaRE.MatchString(sha) {
		fail("invalid", "sha must be the full commit hash")
	}
	p.writer.Lock()
	defer p.writer.Unlock()
	e := p.execution(ctx)
	app = p.Store.Get("apps", str(app["id"]))
	if app == nil || app["mode"] != "pull" {
		fail("forbidden", "Only a pull-mode app reports builds")
	}
	n := integer(app["tenant_n"])
	id := randomID()[:16]
	r := D{"id": id, "app": app["id"], "vmid": app["vmid"], "sha": sha, "ref": "refs/heads/" + str(app["branch"]), "source": "machine", "size": 0, "state": "failed", "error": truncate(str(body["error"]), 256), "log": truncate(str(body["log"]), maxBuildLog), "created_at": now()}
	app["agent_seen_at"] = now()
	e.Transaction(func(tx *Execution) {
		tx.S.Put("releases", id, n, r)
		tx.S.Put("apps", app["id"], n, app)
	})
	e.pruneReleases(app)
	e.S.Log("agent:"+str(app["id"]), n, "app_build_failed", D{"app": app["name"], "sha": sha}, "ok")
	return D{"ok": true}
}
