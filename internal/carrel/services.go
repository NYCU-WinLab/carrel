package carrel

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Services run a tenant's container image only while it has work (PLAN
// 7.11). The control plane keeps what each service should be; a service
// host's agent (carrel-svcd serve -control) asks for its desired state, builds
// what it lacks and reports what it holds. carrel never connects to a
// service host; the agent only makes outbound requests, as for apps.

const (
	serviceAgentWait    = 30 * time.Second
	keptServiceVersions = 3
	serviceHostOffline  = 90
	serviceWaitMax      = 55
	serviceTokenPrefix  = "cfh_"
	maxServiceReport    = 4 << 20
)

// ServiceHostConfig is one service host: the router's address the gateway
// sends requests to, and the SHA-256 of the host's token in hex.
type ServiceHostConfig struct {
	Name        string `json:"name"`
	Router      string `json:"router"`
	TokenSHA256 string `json:"token_sha256"`
}

var (
	serviceHostName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	// The host agent accepts these and nothing else (internal/svc).
	serviceVersionRE = regexp.MustCompile(`^v[0-9]{1,9}$`)
	// A service's name on its host goes into the gateway's configuration.
	serviceHostPattern = regexp.MustCompile(`^t[0-9]{1,6}-[a-z][a-z0-9-]{0,31}$`)
)

func serviceID(n int, name string) string { return appID(n, name) }

// serviceHostID names a service on its host: t<tenant>-<name>.
func serviceHostID(n int, name string) string { return fmt.Sprintf("t%d-%s", n, name) }

func serviceVersionID(fid, version string) string { return fid + "/" + version }

func (e *Execution) Service(t D, name any) D {
	f := e.S.Get("services", serviceID(integer(t["n"]), str(name)))
	if f == nil {
		fail("not_found", "Service not found in this tenant")
	}
	return f
}

// ServiceVersions lists a service's versions, newest first.
func (e *Execution) ServiceVersions(f D) []D {
	vs := filter(e.S.Objects("service_versions", integer(f["tenant_n"])), func(v D) bool { return v["service"] == f["id"] })
	sort.Slice(vs, func(i, j int) bool { return integer(vs[i]["seq"]) > integer(vs[j]["seq"]) })
	return vs
}

var serviceSpecKeys = []string{"image", "port", "memory_mb", "instance", "idle_seconds", "timeout_seconds", "max_instances", "wake_path"}

func publicServiceVersion(v D) D {
	out := pick(v, append([]string{"version", "digest", "state", "error", "created_at", "ready_at", "env_keys", "sha", "run_url"}, serviceSpecKeys...)...)
	if b := num(v["bytes"]); b > 0 {
		out["size_mb"] = int(b/MiB + 0.5)
	}
	return out
}

func (e *Execution) serviceHostState(name string) string {
	h := e.S.SiteGet("service_hosts", name)
	switch {
	case h == nil:
		return "not_connected"
	case now()-num(h["seen_at"]) > serviceHostOffline:
		return "offline"
	}
	return "connected"
}

func (e *Execution) PublicService(f D) D {
	out := pick(f, "name", "current", "previous", "pending", "created_at", "deployed_at", "registry", "repo", "branch", "schedules", "previews", "pr", "head_ref")
	if parent := str(f["preview_of"]); parent != "" {
		_, out["preview_of"], _ = strings.Cut(parent, "-")
	} else if boolean(f["previews"]) {
		names := []any{}
		for _, pf := range e.previewsOf(f) {
			names = append(names, pf["name"])
		}
		out["open_previews"] = names
	}
	versions := e.ServiceVersions(f)
	public := []D{}
	for _, v := range versions {
		public = append(public, publicServiceVersion(v))
		if v["version"] == f["current"] {
			for _, k := range append(serviceSpecKeys, "env_keys") {
				if v[k] != nil {
					out[k] = v[k]
				}
			}
		}
	}
	out["versions"] = public
	switch {
	case str(f["pending"]) != "":
		out["state"] = "building"
	case str(f["current"]) != "":
		// Asleep or awake: the host wakes it on a request.
		out["state"] = "deployed"
	case len(versions) > 0 && versions[0]["state"] == "failed":
		out["state"] = "failed"
	default:
		out["state"] = "not_deployed"
	}
	out["host"] = e.serviceHostState(str(f["host"]))
	if names := e.serviceDomains(f, true); len(names) > 0 {
		urls := []string{}
		for _, name := range names {
			if !strings.HasPrefix(name, "*.") {
				urls = append(urls, "https://"+name)
			}
		}
		out["urls"] = urls
	}
	if live := str(f["live"]); live != str(f["current"]) && str(f["current"]) != "" {
		out["switching_to"] = f["current"]
	}
	return out
}

// serviceHost picks the host a new service runs on. Version 1 has one.
func (p *Platform) serviceHost() ServiceHostConfig {
	if len(p.Config.ServiceHosts) == 0 {
		fail("capacity_exhausted", "No service host is configured")
	}
	return p.Config.ServiceHosts[0]
}

// bumpServices tells the hosts' agents their desired state changed.
func (e *Execution) bumpServices() {
	r := e.S.SiteGet("services", "revision")
	e.S.SitePut("services", "revision", D{"revision": integer(obj(r)["revision"]) + 1})
}

func (s *Store) serviceRevision() int64 {
	return int64(integer(obj(s.SiteGet("services", "revision"))["revision"]))
}

// serviceSpec reads and checks the deploy arguments against PLAN 7.11's
// limits. The contract checks types and ranges; this fills the defaults.
func serviceSpec(a D) D {
	spec := D{
		"image":           str(a["image"]),
		"port":            intAt(a, "port", 8080),
		"memory_mb":       intAt(a, "memory_mb", 512),
		"instance":        textAt(a, "instance", "reuse"),
		"idle_seconds":    intAt(a, "idle_seconds", 300),
		"timeout_seconds": intAt(a, "timeout_seconds", 300),
		"wake_path":       str(a["wake_path"]),
	}
	switch spec["instance"] {
	case "reuse":
		spec["max_instances"] = 1
	case "fresh":
		spec["max_instances"] = intAt(a, "max_instances", 10)
	default:
		fail("invalid", "instance must be reuse or fresh")
	}
	if p := integer(spec["port"]); p < 1 || p > 65535 {
		fail("invalid", "port must be 1 to 65535")
	}
	if m := integer(spec["memory_mb"]); m < 128 || m > 2048 {
		fail("invalid", "memory_mb must be 128 to 2048")
	}
	if s := integer(spec["timeout_seconds"]); s < 1 || s > 3600 {
		fail("invalid", "timeout_seconds must be 1 to 3600")
	}
	if s := integer(spec["idle_seconds"]); s < 1 || s > 86400 {
		fail("invalid", "idle_seconds must be 1 to 86400")
	}
	if n := integer(spec["max_instances"]); n < 1 || n > 10 {
		fail("invalid", "max_instances must be 1 to 10")
	}
	if w := str(spec["wake_path"]); w != "" && !strings.HasPrefix(w, "/") {
		fail("invalid", "wake_path must start with /")
	}
	return spec
}

// buildReserve is what a version holds against service_gb until its host
// reports the real size: the largest image (PLAN 7.11) and its snapshot's memory.
func buildReserve(memoryMB int) float64 { return 2*GiB + float64(memoryMB)*MiB }

// serviceBytes is the disk a tenant's kept versions use on service hosts,
// with a reserve for each version still building.
func (e *Execution) serviceBytes(n int) float64 {
	total := 0.0
	for _, v := range e.S.Objects("service_versions", n) {
		if v["state"] == "building" {
			total += buildReserve(integer(v["memory_mb"]))
		} else {
			total += num(v["bytes"])
		}
	}
	return total
}

// nextServiceVersion numbers versions across every service and every
// removal: a service removed and deployed again under its name must not
// meet a version of the old one that a host still holds or reports.
func (e *Execution) nextServiceVersion() int {
	r := e.S.SiteGet("services", "version")
	next := integer(obj(r)["version"]) + 1
	e.S.SitePut("services", "version", D{"version": next})
	return next
}

func (e *Execution) ServiceTool(tool string, a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	switch tool {
	case "service_list":
		out := []D{}
		for _, f := range e.S.Objects("services", n) {
			out = append(out, e.PublicService(f))
		}
		return D{"services": out}
	case "service_get":
		f := e.Service(t, a["service"])
		// Waiting for a build reads without the writer lock: a deploy returns
		// at once, and this is how an agent follows it.
		deadline := time.Now().Add(time.Duration(min(intAt(a, "wait_seconds", 0), serviceWaitMax)) * time.Second)
		for str(f["pending"]) != "" && time.Now().Before(deadline) && sleep(e.Ctx, time.Second) {
			if f = e.S.Get("services", str(f["id"])); f == nil {
				fail("not_found", "Service was removed")
			}
		}
		return D{"service": e.PublicService(f)}
	case "service_logs":
		return e.serviceLogs(e.Service(t, a["service"]), a)
	case "service_deploy":
		name := str(a["name"])
		spec := serviceSpec(a)
		f := e.S.Get("services", serviceID(n, name))
		delta := D{}
		if f == nil {
			delta["services"] = 1
			f = D{"id": serviceID(n, name), "name": name, "tenant_n": n, "host": e.P.serviceHost().Name, "seq": 0, "created_at": now()}
		} else if str(f["pending"]) != "" {
			fail("conflict", "A build of this service is in progress; follow it with service_get and wait_seconds", D{"pending": f["pending"]})
		}
		// A deploy keeps the environment of the live version.
		env := D{}
		if cur := e.S.Get("service_versions", serviceVersionID(str(f["id"]), str(f["current"]))); cur != nil {
			env = D{"env": str(cur["env"]), "env_keys": cur["env_keys"]}
		}
		return e.startServiceVersion(t, f, spec, delta, env, dry)
	case "service_rollback":
		f := e.Service(t, a["service"])
		target := str(f["previous"])
		if target == "" {
			fail("conflict", "No previous version to roll back to")
		}
		if str(f["pending"]) != "" {
			fail("conflict", "A build of this service is in progress", D{"pending": f["pending"]})
		}
		v := e.S.Get("service_versions", serviceVersionID(str(f["id"]), target))
		if v == nil || v["state"] != "ready" {
			fail("conflict", "The previous version is no longer kept")
		}
		if !dry {
			f["previous"], f["current"], f["deployed_at"] = f["current"], target, now()
			e.Transaction(func(tx *Execution) {
				tx.Put("services", f["id"], n, f)
				tx.bumpServices()
			})
		}
		return D{"dry_run": dry, "service": e.PublicService(f)}
	case "service_schedule":
		return e.serviceSchedule(e.Service(t, a["service"]), a, dry)
	case "service_remove":
		f := e.Service(t, a["service"])
		if a["confirm"] != f["name"] {
			fail("invalid", "confirm must equal the service name")
		}
		// A preview's own domain goes with it; a parent's previews go with
		// the parent.
		if names := e.serviceDomains(f, false); len(names) > 0 && f["preview_of"] == nil {
			fail("conflict", "Domains still point at this service; remove them with domain_remove first", D{"domains": names, "recovery": "resolve_prerequisite"})
		}
		previews := append([]D{f}, e.previewsOf(f)...)
		if f["preview_of"] != nil {
			previews = []D{f}
		}
		// A dry run counts the removal; a real one counts what is left.
		after := D{"services": -len(previews)}
		removed := D{"name": f["name"]}
		if len(previews) > 1 {
			names := []any{}
			for _, pf := range previews[1:] {
				names = append(names, pf["name"])
			}
			removed["previews"] = names
		}
		if !dry {
			if len(previews) > 1 || f["preview_of"] != nil {
				e.removePreviews(previews)
			} else {
				e.removeServices(previews)
			}
			after = nil
		}
		return D{"dry_run": dry, "quota_after": e.Quota(t, after), "removed": removed}
	}
	fail("invalid", "Unknown tool")
	return nil
}

// startServiceVersion records a version to build from spec, with the
// environment in env (its sealed values and their names) and, for a deploy
// from GitHub, the commit (sha, ref, run_url).
func (e *Execution) startServiceVersion(t, f, spec, delta, env D, dry bool, also ...func(*Execution)) D {
	n := integer(t["n"])
	quota := e.Quota(t, delta)
	reserve := buildReserve(integer(spec["memory_mb"]))
	if limit := num(obj(t["quota"])["service_gb"]) * GiB; e.serviceBytes(n)+reserve > limit {
		fail("quota_exceeded", "Kept and building service versions would exceed service_gb; a build holds 2 GiB plus its memory until its size is known. Remove a service or wait for builds", D{"dimension": "service_gb"})
	}
	keys := env["env_keys"]
	if keys == nil {
		keys = []any{}
	}
	r := D{"dry_run": dry, "quota_after": quota}
	if dry {
		r["service"] = merge(pick(f, "name"), spec, D{"state": "building", "env_keys": keys})
		return r
	}
	seq := e.nextServiceVersion()
	version := "v" + strconv.Itoa(seq)
	v := merge(spec, D{"id": serviceVersionID(str(f["id"]), version), "service": f["id"], "version": version, "seq": seq, "state": "building", "created_at": now(), "env_keys": keys})
	f["seq"], f["pending"] = seq, version
	// Only versions hold an environment: the service's is its live
	// version's, so a rollback brings back the values that version had.
	if sealed := str(env["env"]); sealed != "" {
		v["env"] = sealed
	}
	// A version deployed from GitHub names the commit and run it came from.
	for _, k := range []string{"sha", "ref", "run_url"} {
		if s := str(env[k]); s != "" {
			v[k] = s
		}
	}
	e.Transaction(func(tx *Execution) {
		tx.Put("service_versions", v["id"], n, v)
		tx.Put("services", f["id"], n, f)
		tx.pruneServiceVersions(f)
		tx.bumpServices()
		for _, step := range also {
			step(tx)
		}
	})
	r["service"] = e.PublicService(f)
	r["state"] = "building"
	r["next_action"] = "Call service_get with wait_seconds=55 until state is no longer building. A build takes about 10 seconds for a 100 MB image and up to a few minutes for a large one."
	return r
}

// pruneServiceVersions keeps the newest versions plus the current, previous
// and pending ones. The host removes what the state no longer names.
func (e *Execution) pruneServiceVersions(f D) {
	keep := map[string]bool{str(f["current"]): true, str(f["previous"]): true, str(f["pending"]): true}
	for i, v := range e.ServiceVersions(f) {
		if i < keptServiceVersions || keep[str(v["version"])] {
			continue
		}
		e.S.Remove("service_versions", v["id"])
	}
}

// removeServices deletes service records and their versions. The hosts
// delete the files on their next pass.
func (e *Execution) removeServices(fs []D) {
	e.Transaction(func(tx *Execution) { tx.dropServices(fs) })
}

// dropServices is removeServices inside the caller's transaction.
func (tx *Execution) dropServices(fs []D) {
	for _, f := range fs {
		for _, v := range tx.ServiceVersions(f) {
			tx.S.Remove("service_versions", v["id"])
		}
		tx.S.Remove("services", f["id"])
		// A link must not outlive its service into one of the same name.
		for _, l := range tx.S.Objects("service_env_links", integer(f["tenant_n"])) {
			if l["service"] == f["id"] {
				tx.S.Remove("service_env_links", l["id"])
			}
		}
	}
	tx.bumpServices()
}

// serviceDomains are the names of the domains that point at a service,
// only the serving ones when ready is set.
func (e *Execution) serviceDomains(f D, ready bool) []string {
	names := []string{}
	for _, d := range e.domains(integer(f["tenant_n"])) {
		if d.Service == str(f["id"]) && (!ready || d.State == "ready") {
			names = append(names, d.Name)
		}
	}
	sort.Strings(names)
	return names
}

// serviceRoutes tell the gateway where each service's host listens. A
// tenant that is not active gets no route, so its names answer 503: a
// service wakes on any request, unlike a machine that suspension stopped.
func (e *Execution) serviceRoutes() []D {
	routers := map[string]string{}
	for _, h := range e.P.Config.ServiceHosts {
		routers[h.Name] = h.Router
	}
	out := []D{}
	for _, f := range e.S.Objects("services") {
		if t := e.S.TenantN(integer(f["tenant_n"])); t == nil || t["status"] != "active" {
			continue
		}
		if router := routers[str(f["host"])]; router != "" {
			out = append(out, D{"id": f["id"], "tenant_n": f["tenant_n"], "router": router, "host_id": serviceHostID(integer(f["tenant_n"]), str(f["name"]))})
		}
	}
	return out
}

// Host side

// serviceHostOf finds the host a token belongs to. The request must also
// come from that host's address: the infra gate admits tenant machines too.
func (p *Platform) serviceHostOf(token, source string) ServiceHostConfig {
	if !strings.HasPrefix(token, serviceTokenPrefix) {
		fail("forbidden", "Invalid service host token")
	}
	h := digest(token)
	for _, host := range p.Config.ServiceHosts {
		if secureEqual(host.TokenSHA256, h) {
			router, err := netip.ParseAddrPort(host.Router)
			if from, perr := netip.ParseAddr(source); err != nil || perr != nil || from.Unmap() != router.Addr() {
				fail("forbidden", "Invalid service host token")
			}
			return host
		}
	}
	fail("forbidden", "Invalid service host token")
	return ServiceHostConfig{}
}

func (p *Platform) touchServiceHost(host ServiceHostConfig) {
	p.writer.Lock()
	defer p.writer.Unlock()
	p.Store.SitePut("service_hosts", host.Name, D{"name": host.Name, "seen_at": now()})
}

// ServiceState long-polls for a desired state newer than since.
func (p *Platform) ServiceState(ctx context.Context, token, source string, since int64) D {
	host := p.serviceHostOf(token, source)
	p.touchServiceHost(host)
	deadline := time.Now().Add(serviceAgentWait)
	for p.Store.serviceRevision() <= since && time.Now().Before(deadline) && sleep(ctx, time.Second) {
	}
	return p.desiredServices(host)
}

func (p *Platform) desiredServices(host ServiceHostConfig) D {
	revision := p.Store.serviceRevision()
	e := p.execution(context.Background())
	services := []D{}
	for _, f := range p.Store.Objects("services") {
		if f["host"] != host.Name {
			continue
		}
		versions := []D{}
		for _, v := range e.ServiceVersions(f) {
			if v["state"] != "building" && v["state"] != "ready" {
				continue
			}
			versions = append(versions, D{
				"version": v["version"], "image": v["image"], "port": v["port"], "memory_mb": v["memory_mb"],
				"mode": v["instance"], "idle_seconds": v["idle_seconds"], "timeout_seconds": v["timeout_seconds"],
				"max_instances": v["max_instances"], "wake_path": v["wake_path"],
				// The agent fetches the values when it builds the version
				// (ServiceEnvFor): the state stays small whatever they hold.
				"has_env": str(v["env"]) != "",
				// Likewise the registry's credentials (ServiceAuthFor).
				"has_auth": hasServiceAuth(f, v),
			})
		}
		entry := D{"id": serviceHostID(integer(f["tenant_n"]), str(f["name"])), "versions": versions}
		if s := arr(f["schedules"]); len(s) > 0 {
			entry["schedules"] = s
		}
		if c := str(f["current"]); c != "" {
			entry["current"] = c
		}
		services = append(services, entry)
	}
	return D{"revision": revision, "services": services}
}

// ServiceReport takes a host's inventory. A version the host built becomes
// ready, and current when it was the pending deploy; a version that failed
// records its error.
func (p *Platform) ServiceReport(ctx context.Context, token, source string, body D) D {
	host := p.serviceHostOf(token, source)
	p.writer.Lock()
	defer p.writer.Unlock()
	e := p.execution(ctx)
	byHostID := map[string]D{}
	for _, f := range p.Store.Objects("services") {
		if f["host"] == host.Name {
			byHostID[serviceHostID(integer(f["tenant_n"]), str(f["name"]))] = f
		}
	}
	changed := false
	e.Transaction(func(tx *Execution) {
		for _, held := range arr(body["services"]) {
			h := obj(held)
			f := byHostID[str(h["id"])]
			if f == nil {
				continue // removed since the host asked, or another host's
			}
			n := integer(f["tenant_n"])
			dirty := false
			if live := str(h["current"]); live != str(f["live"]) && (live == "" || serviceVersionRE.MatchString(live)) {
				f["live"], dirty = live, true
			}
			for _, hv := range arr(h["versions"]) {
				held := obj(hv)
				version := str(held["version"])
				if !serviceVersionRE.MatchString(version) {
					continue
				}
				v := tx.S.Get("service_versions", serviceVersionID(str(f["id"]), version))
				if v == nil {
					continue
				}
				switch {
				case held["state"] == "ready" && v["state"] == "building":
					v["state"], v["ready_at"] = "ready", now()
					tx.emit(n, "service.version.ready", D{"service": f["name"], "version": version, "live": f["pending"] == version})
					if f["pending"] == version {
						if c := str(f["current"]); c != "" {
							f["previous"] = c
						}
						f["current"], f["pending"], f["deployed_at"] = version, nil, now()
						changed = true
					}
					dirty = true
				case held["state"] == "failed" && v["state"] == "building":
					v["state"], v["error"] = "failed", truncate(str(held["error"]), 1000)
					tx.emit(n, "service.version.failed", D{"service": f["name"], "version": version, "error": v["error"]})
					if f["pending"] == version {
						f["pending"] = nil
					}
					// The host keeps no failed version: the state stops naming it.
					changed, dirty = true, true
				}
				if held["state"] == "ready" {
					if b := num(held["bytes"]); b >= 0 && b <= 64*GiB {
						v["bytes"] = b
					}
					if d := str(held["digest"]); strings.HasPrefix(d, "sha256:") && len(d) == 71 {
						v["digest"] = d
					}
				}
				tx.Put("service_versions", v["id"], n, v)
			}
			if dirty {
				tx.Put("services", f["id"], n, f)
			}
		}
		if changed {
			tx.bumpServices()
		}
		tx.S.SitePut("service_hosts", host.Name, D{"name": host.Name, "seen_at": now()})
	})
	p.events.notify()
	return D{"revision": p.Store.serviceRevision()}
}
