package carrel

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"time"
)

// PublicStatus is what carrel.winlab.tw shows without signing in: how busy
// the node is, what admission has committed of what it admits (Carrel
// machines plus running guests Carrel does not manage), and each tenant's
// share. A tenant is named only when its slug is already public: it is
// active and serves at least one ready *.<slug>.winlab.tw domain. Every
// other tenant with machines is summed into "others" without a name.
// Machine names, addresses, keys and domains are never listed.
func (e *Execution) PublicStatus() D {
	c := e.Capacity(nil, true)
	physical := obj(c["physical"])
	cpu, memory, disk := obj(physical["cpu"]), obj(physical["memory"]), obj(physical["disk"])
	tenants := []D{}
	others := D{"tenants": 0, "machines": 0.0, "vcpu": 0.0, "memory_gib": 0.0, "disk_gib": 0.0}
	for _, t := range e.S.Tenants() {
		u := e.Usage(t)
		if num(u["machines"]) == 0 {
			continue
		}
		share := D{
			"machines":   num(u["machines"]),
			"vcpu":       num(u["vcpu"]),
			"memory_gib": num(u["memory_mb"]) / 1024,
			"disk_gib":   num(u["disk_gb"]),
		}
		if t["status"] == "active" && publicSlug(e.S.Objects("domains", integer(t["n"]))) {
			tenants = append(tenants, merge(D{"name": t["slug"]}, share))
			continue
		}
		others["tenants"] = integer(others["tenants"]) + 1
		for k, v := range share {
			others[k] = num(others[k]) + num(v)
		}
	}
	sort.SliceStable(tenants, func(i, j int) bool {
		if num(tenants[i]["vcpu"]) != num(tenants[j]["vcpu"]) {
			return num(tenants[i]["vcpu"]) > num(tenants[j]["vcpu"])
		}
		return str(tenants[i]["name"]) < str(tenants[j]["name"])
	})
	return D{
		"checked_at": c["checked_at"],
		"node": D{
			"cpu":        D{"logical_cpus": cpu["logical_cpus"], "utilization": cpu["utilization"]},
			"memory_gib": D{"total": memory["total"], "used": memory["used"]},
			"disk_gib":   D{"total": disk["total"], "used": disk["used"]},
		},
		"allocated": c["allocatable"],
		"tenants":   tenants,
		"others":    others,
	}
}

// publicSlug reports whether a tenant's slug is already published by one of
// its domains.
func publicSlug(domains []D) bool {
	for _, d := range domains {
		if d["state"] == "ready" {
			return true
		}
	}
	return false
}

// statusCache answers repeated page loads from memory for a few seconds, so
// an unauthenticated endpoint cannot drive node inventory calls.
type statusCache struct {
	mu     sync.Mutex
	at     time.Time
	body   D
	failed bool
}

const (
	statusTTL     = 15 * time.Second
	statusFailTTL = 5 * time.Second
	statusTimeout = 10 * time.Second
)

func (a *App) statusRoute(mux *http.ServeMux, p *Platform) {
	cache := &statusCache{}
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		ttl := statusTTL
		if cache.failed {
			ttl = statusFailTTL
		}
		if (cache.body == nil && !cache.failed) || time.Since(cache.at) > ttl {
			// The inventory fetch is shared with members' capacity_get, so a
			// visitor who disconnects must not cancel it.
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), statusTimeout)
			var body D
			err := attempt(func() { body = p.execution(ctx).PublicStatus() })
			cancel()
			cache.at, cache.failed = time.Now(), err != nil
			if err == nil {
				cache.body = body
			}
		}
		if cache.failed {
			jsonResponse(w, 503, D{"error": "temporarily_unavailable"})
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=15")
		jsonResponse(w, 200, cache.body)
	})
}
