package carrel

import (
	"net/http"
	"sort"
	"sync"
	"time"
)

// PublicStatus is what carrel.winlab.tw shows without signing in: how busy
// the node is, how much Carrel machines have taken of what it admits, and
// each tenant's share. Tenants appear by slug, which is already public in
// their *.<slug>.winlab.tw domains; machine names, addresses, keys and
// domains are not listed.
func (e *Execution) PublicStatus() D {
	c := e.Capacity(nil, true)
	physical := obj(c["physical"])
	cpu, memory, disk := obj(physical["cpu"]), obj(physical["memory"]), obj(physical["disk"])
	tenants := []D{}
	for _, t := range e.S.Tenants() {
		u := e.Usage(t)
		if num(u["machines"]) == 0 {
			continue
		}
		tenants = append(tenants, D{
			"name":       t["slug"],
			"machines":   u["machines"],
			"vcpu":       u["vcpu"],
			"memory_gib": num(u["memory_mb"]) / 1024,
			"disk_gib":   u["disk_gb"],
		})
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
	}
}

// statusCache answers repeated page loads from memory for a few seconds, so
// an unauthenticated endpoint cannot drive node inventory calls.
type statusCache struct {
	mu   sync.Mutex
	at   time.Time
	body D
}

const statusTTL = 15 * time.Second

func (a *App) statusRoute(mux *http.ServeMux, p *Platform) {
	cache := &statusCache{}
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		if cache.body == nil || time.Since(cache.at) > statusTTL {
			var body D
			if err := attempt(func() { body = p.execution(r.Context()).PublicStatus() }); err != nil {
				jsonResponse(w, 503, D{"error": "temporarily_unavailable"})
				return
			}
			cache.body, cache.at = body, time.Now()
		}
		w.Header().Set("Cache-Control", "public, max-age=15")
		jsonResponse(w, 200, cache.body)
	})
}
