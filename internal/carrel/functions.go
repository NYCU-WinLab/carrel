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

// Functions run a tenant's container image only while it has work (PLAN
// 7.11). The control plane keeps what each function should be; a function
// host's agent (carrel-fnd serve -control) asks for its desired state, builds
// what it lacks and reports what it holds. carrel never connects to a
// function host; the agent only makes outbound requests, as for apps.

const (
	functionAgentWait    = 30 * time.Second
	keptFunctionVersions = 3
	functionHostOffline  = 90
	functionWaitMax      = 55
	functionTokenPrefix  = "cfh_"
	maxFunctionReport    = 4 << 20
)

// FunctionHostConfig is one function host: the router's address the gateway
// sends requests to, and the SHA-256 of the host's token in hex.
type FunctionHostConfig struct {
	Name        string `json:"name"`
	Router      string `json:"router"`
	TokenSHA256 string `json:"token_sha256"`
}

var (
	functionHostName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	// The host agent accepts these and nothing else (internal/fn).
	functionVersionRE = regexp.MustCompile(`^v[0-9]{1,9}$`)
)

func functionID(n int, name string) string { return appID(n, name) }

// functionHostID names a function on its host: t<tenant>-<name>.
func functionHostID(n int, name string) string { return fmt.Sprintf("t%d-%s", n, name) }

func functionVersionID(fid, version string) string { return fid + "/" + version }

func (e *Execution) Function(t D, name any) D {
	f := e.S.Get("functions", functionID(integer(t["n"]), str(name)))
	if f == nil {
		fail("not_found", "Function not found in this tenant")
	}
	return f
}

// FunctionVersions lists a function's versions, newest first.
func (e *Execution) FunctionVersions(f D) []D {
	vs := filter(e.S.Objects("function_versions", integer(f["tenant_n"])), func(v D) bool { return v["function"] == f["id"] })
	sort.Slice(vs, func(i, j int) bool { return integer(vs[i]["seq"]) > integer(vs[j]["seq"]) })
	return vs
}

var functionSpecKeys = []string{"image", "port", "memory_mb", "instance", "idle_seconds", "timeout_seconds", "max_instances", "wake_path"}

func publicFunctionVersion(v D) D {
	out := pick(v, append([]string{"version", "digest", "state", "error", "created_at", "ready_at"}, functionSpecKeys...)...)
	if b := num(v["bytes"]); b > 0 {
		out["size_mb"] = int(b/MiB + 0.5)
	}
	return out
}

func (e *Execution) functionHostState(name string) string {
	h := e.S.SiteGet("function_hosts", name)
	switch {
	case h == nil:
		return "not_connected"
	case now()-num(h["seen_at"]) > functionHostOffline:
		return "offline"
	}
	return "connected"
}

func (e *Execution) PublicFunction(f D) D {
	out := pick(f, "name", "current", "previous", "pending", "created_at", "deployed_at")
	versions := e.FunctionVersions(f)
	public := []D{}
	for _, v := range versions {
		public = append(public, publicFunctionVersion(v))
		if v["version"] == f["current"] {
			for _, k := range functionSpecKeys {
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
	out["host"] = e.functionHostState(str(f["host"]))
	if live := str(f["live"]); live != str(f["current"]) && str(f["current"]) != "" {
		out["switching_to"] = f["current"]
	}
	return out
}

// functionHost picks the host a new function runs on. Version 1 has one.
func (p *Platform) functionHost() FunctionHostConfig {
	if len(p.Config.FunctionHosts) == 0 {
		fail("capacity_exhausted", "No function host is configured")
	}
	return p.Config.FunctionHosts[0]
}

// bumpFunctions tells the hosts' agents their desired state changed.
func (e *Execution) bumpFunctions() {
	r := e.S.SiteGet("functions", "revision")
	e.S.SitePut("functions", "revision", D{"revision": integer(obj(r)["revision"]) + 1})
}

func (s *Store) functionRevision() int64 {
	return int64(integer(obj(s.SiteGet("functions", "revision"))["revision"]))
}

// functionSpec reads and checks the deploy arguments against PLAN 7.11's
// limits. The contract checks types and ranges; this fills the defaults.
func functionSpec(a D) D {
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

// buildReserve is what a version holds against function_gb until its host
// reports the real size: the largest image (PLAN 7.11) and its snapshot's memory.
func buildReserve(memoryMB int) float64 { return 2*GiB + float64(memoryMB)*MiB }

// functionBytes is the disk a tenant's kept versions use on function hosts,
// with a reserve for each version still building.
func (e *Execution) functionBytes(n int) float64 {
	total := 0.0
	for _, v := range e.S.Objects("function_versions", n) {
		if v["state"] == "building" {
			total += buildReserve(integer(v["memory_mb"]))
		} else {
			total += num(v["bytes"])
		}
	}
	return total
}

// nextFunctionVersion numbers versions across every function and every
// removal: a function removed and deployed again under its name must not
// meet a version of the old one that a host still holds or reports.
func (e *Execution) nextFunctionVersion() int {
	r := e.S.SiteGet("functions", "version")
	next := integer(obj(r)["version"]) + 1
	e.S.SitePut("functions", "version", D{"version": next})
	return next
}

func (e *Execution) FunctionTool(tool string, a, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	switch tool {
	case "function_list":
		out := []D{}
		for _, f := range e.S.Objects("functions", n) {
			out = append(out, e.PublicFunction(f))
		}
		return D{"functions": out}
	case "function_get":
		f := e.Function(t, a["function"])
		// Waiting for a build reads without the writer lock: a deploy returns
		// at once, and this is how an agent follows it.
		deadline := time.Now().Add(time.Duration(min(intAt(a, "wait_seconds", 0), functionWaitMax)) * time.Second)
		for str(f["pending"]) != "" && time.Now().Before(deadline) && sleep(e.Ctx, time.Second) {
			if f = e.S.Get("functions", str(f["id"])); f == nil {
				fail("not_found", "Function was removed")
			}
		}
		return D{"function": e.PublicFunction(f)}
	case "function_deploy":
		name := str(a["name"])
		spec := functionSpec(a)
		f := e.S.Get("functions", functionID(n, name))
		delta := D{}
		if f == nil {
			delta["functions"] = 1
			f = D{"id": functionID(n, name), "name": name, "tenant_n": n, "host": e.P.functionHost().Name, "seq": 0, "created_at": now()}
		} else if str(f["pending"]) != "" {
			fail("conflict", "A build of this function is in progress; follow it with function_get and wait_seconds", D{"pending": f["pending"]})
		}
		quota := e.Quota(t, delta)
		reserve := buildReserve(integer(spec["memory_mb"]))
		if limit := num(obj(t["quota"])["function_gb"]) * GiB; e.functionBytes(n)+reserve > limit {
			fail("quota_exceeded", "Kept and building function versions would exceed function_gb; a build holds 2 GiB plus its memory until its size is known. Remove a function or wait for builds", D{"dimension": "function_gb"})
		}
		r := D{"dry_run": dry, "quota_after": quota}
		if dry {
			r["function"] = merge(pick(f, "name"), spec, D{"state": "building"})
			return r
		}
		seq := e.nextFunctionVersion()
		version := "v" + strconv.Itoa(seq)
		v := merge(spec, D{"id": functionVersionID(str(f["id"]), version), "function": f["id"], "version": version, "seq": seq, "state": "building", "created_at": now()})
		f["seq"], f["pending"] = seq, version
		e.Transaction(func(tx *Execution) {
			tx.Put("function_versions", v["id"], n, v)
			tx.Put("functions", f["id"], n, f)
			tx.pruneFunctionVersions(f)
			tx.bumpFunctions()
		})
		r["function"] = e.PublicFunction(f)
		r["state"] = "building"
		r["next_action"] = "Call function_get with wait_seconds=55 until state is no longer building. A build takes about 10 seconds for a 100 MB image and up to a few minutes for a large one."
		return r
	case "function_rollback":
		f := e.Function(t, a["function"])
		target := str(f["previous"])
		if target == "" {
			fail("conflict", "No previous version to roll back to")
		}
		if str(f["pending"]) != "" {
			fail("conflict", "A build of this function is in progress", D{"pending": f["pending"]})
		}
		v := e.S.Get("function_versions", functionVersionID(str(f["id"]), target))
		if v == nil || v["state"] != "ready" {
			fail("conflict", "The previous version is no longer kept")
		}
		if !dry {
			f["previous"], f["current"], f["deployed_at"] = f["current"], target, now()
			e.Transaction(func(tx *Execution) {
				tx.Put("functions", f["id"], n, f)
				tx.bumpFunctions()
			})
		}
		return D{"dry_run": dry, "function": e.PublicFunction(f)}
	case "function_remove":
		f := e.Function(t, a["function"])
		if a["confirm"] != f["name"] {
			fail("invalid", "confirm must equal the function name")
		}
		if !dry {
			e.removeFunctions([]D{f})
		}
		return D{"dry_run": dry, "quota_after": e.Quota(t, D{"functions": -1}), "removed": D{"name": f["name"]}}
	}
	fail("invalid", "Unknown tool")
	return nil
}

// pruneFunctionVersions keeps the newest versions plus the current, previous
// and pending ones. The host removes what the state no longer names.
func (e *Execution) pruneFunctionVersions(f D) {
	keep := map[string]bool{str(f["current"]): true, str(f["previous"]): true, str(f["pending"]): true}
	for i, v := range e.FunctionVersions(f) {
		if i < keptFunctionVersions || keep[str(v["version"])] {
			continue
		}
		e.S.Remove("function_versions", v["id"])
	}
}

// removeFunctions deletes function records and their versions. The hosts
// delete the files on their next pass.
func (e *Execution) removeFunctions(fs []D) {
	e.Transaction(func(tx *Execution) {
		for _, f := range fs {
			for _, v := range tx.FunctionVersions(f) {
				tx.S.Remove("function_versions", v["id"])
			}
			tx.S.Remove("functions", f["id"])
		}
		tx.bumpFunctions()
	})
}

// Host side

// functionHostOf finds the host a token belongs to. The request must also
// come from that host's address: the infra gate admits tenant machines too.
func (p *Platform) functionHostOf(token, source string) FunctionHostConfig {
	if !strings.HasPrefix(token, functionTokenPrefix) {
		fail("forbidden", "Invalid function host token")
	}
	h := digest(token)
	for _, host := range p.Config.FunctionHosts {
		if secureEqual(host.TokenSHA256, h) {
			router, err := netip.ParseAddrPort(host.Router)
			if from, perr := netip.ParseAddr(source); err != nil || perr != nil || from.Unmap() != router.Addr() {
				fail("forbidden", "Invalid function host token")
			}
			return host
		}
	}
	fail("forbidden", "Invalid function host token")
	return FunctionHostConfig{}
}

func (p *Platform) touchFunctionHost(host FunctionHostConfig) {
	p.writer.Lock()
	defer p.writer.Unlock()
	p.Store.SitePut("function_hosts", host.Name, D{"name": host.Name, "seen_at": now()})
}

// FunctionState long-polls for a desired state newer than since.
func (p *Platform) FunctionState(ctx context.Context, token, source string, since int64) D {
	host := p.functionHostOf(token, source)
	p.touchFunctionHost(host)
	deadline := time.Now().Add(functionAgentWait)
	for p.Store.functionRevision() <= since && time.Now().Before(deadline) && sleep(ctx, time.Second) {
	}
	return p.desiredFunctions(host)
}

func (p *Platform) desiredFunctions(host FunctionHostConfig) D {
	revision := p.Store.functionRevision()
	e := p.execution(context.Background())
	functions := []D{}
	for _, f := range p.Store.Objects("functions") {
		if f["host"] != host.Name {
			continue
		}
		versions := []D{}
		for _, v := range e.FunctionVersions(f) {
			if v["state"] != "building" && v["state"] != "ready" {
				continue
			}
			versions = append(versions, D{
				"version": v["version"], "image": v["image"], "port": v["port"], "memory_mb": v["memory_mb"],
				"mode": v["instance"], "idle_seconds": v["idle_seconds"], "timeout_seconds": v["timeout_seconds"],
				"max_instances": v["max_instances"], "wake_path": v["wake_path"],
			})
		}
		entry := D{"id": functionHostID(integer(f["tenant_n"]), str(f["name"])), "versions": versions}
		if c := str(f["current"]); c != "" {
			entry["current"] = c
		}
		functions = append(functions, entry)
	}
	return D{"revision": revision, "functions": functions}
}

// FunctionReport takes a host's inventory. A version the host built becomes
// ready, and current when it was the pending deploy; a version that failed
// records its error.
func (p *Platform) FunctionReport(ctx context.Context, token, source string, body D) D {
	host := p.functionHostOf(token, source)
	p.writer.Lock()
	defer p.writer.Unlock()
	e := p.execution(ctx)
	byHostID := map[string]D{}
	for _, f := range p.Store.Objects("functions") {
		if f["host"] == host.Name {
			byHostID[functionHostID(integer(f["tenant_n"]), str(f["name"]))] = f
		}
	}
	changed := false
	e.Transaction(func(tx *Execution) {
		for _, held := range arr(body["functions"]) {
			h := obj(held)
			f := byHostID[str(h["id"])]
			if f == nil {
				continue // removed since the host asked, or another host's
			}
			n := integer(f["tenant_n"])
			dirty := false
			if live := str(h["current"]); live != str(f["live"]) && (live == "" || functionVersionRE.MatchString(live)) {
				f["live"], dirty = live, true
			}
			for _, hv := range arr(h["versions"]) {
				held := obj(hv)
				version := str(held["version"])
				if !functionVersionRE.MatchString(version) {
					continue
				}
				v := tx.S.Get("function_versions", functionVersionID(str(f["id"]), version))
				if v == nil {
					continue
				}
				switch {
				case held["state"] == "ready" && v["state"] == "building":
					v["state"], v["ready_at"] = "ready", now()
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
				tx.Put("function_versions", v["id"], n, v)
			}
			if dirty {
				tx.Put("functions", f["id"], n, f)
			}
		}
		if changed {
			tx.bumpFunctions()
		}
		tx.S.SitePut("function_hosts", host.Name, D{"name": host.Name, "seen_at": now()})
	})
	return D{"revision": p.Store.functionRevision()}
}
