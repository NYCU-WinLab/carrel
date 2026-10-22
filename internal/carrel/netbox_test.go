package carrel

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeNetBox keeps objects per API path and answers the few filters the sync
// uses. It refuses what NetBox refuses: a VRF still referenced, a custom
// field that does not exist.
type fakeNetBox struct {
	mu      sync.Mutex
	objects map[string][]D
	next    int
	auth    string
	writes  []string
	fields  map[string]bool
}

var nbRefs = map[string]bool{"cluster": true, "vrf": true, "virtual_machine": true, "group": true, "primary_ip4": true}
var nbChoices = map[string]bool{"status": true, "role": true}

func newFakeNetBox(t *testing.T) (*fakeNetBox, *httptest.Server) {
	f := &fakeNetBox{objects: map[string][]D{}, next: 100, fields: map[string]bool{"vmid": true}}
	f.objects["virtualization/clusters/"] = []D{{"id": 1, "name": "carrel"}}
	f.objects["users/owners/"] = []D{{"id": 7, "name": "carrel"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeNetBox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = r.Header.Get("Authorization")
	path := strings.TrimPrefix(r.URL.Path, "/api/")
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	var id int
	if parts := strings.Split(strings.TrimSuffix(path, "/"), "/"); len(parts) > 0 {
		if n, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
			id, path = n, strings.TrimSuffix(path, strconv.Itoa(n)+"/")
		}
	}
	var body D
	if r.Method == "POST" || r.Method == "PATCH" {
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.writes = append(f.writes, r.Method+" "+path)
		for k, v := range body {
			switch {
			case nbRefs[k]:
				if n, ok := v.(float64); ok {
					body[k] = D{"id": n}
				}
			case nbChoices[k]:
				body[k] = D{"value": v}
			case k == "owner":
				body[k] = D{"id": 7, "name": obj(v)["name"]}
			case k == "custom_fields":
				for name := range obj(v) {
					if !f.fields[name] {
						reply(400, D{"custom_fields": "unknown field " + name})
						return
					}
				}
			}
		}
	}
	switch r.Method {
	case "GET":
		out := []any{}
		for _, o := range f.objects[path] {
			if f.matches(o, r.URL.Query()) {
				out = append(out, o)
			}
		}
		reply(200, D{"count": len(out), "next": nil, "results": out})
	case "POST":
		f.next++
		body["id"] = f.next
		f.objects[path] = append(f.objects[path], body)
		reply(201, body)
	case "PATCH":
		for _, o := range f.objects[path] {
			if integer(o["id"]) == id {
				maps.Copy(o, body)
				reply(200, o)
				return
			}
		}
		reply(404, D{"detail": "not found"})
	case "DELETE":
		if path == "ipam/vrfs/" {
			for _, kind := range []string{"ipam/prefixes/", "ipam/ip-addresses/"} {
				for _, o := range f.objects[kind] {
					if integer(obj(o["vrf"])["id"]) == id {
						reply(409, D{"detail": "vrf still referenced"})
						return
					}
				}
			}
		}
		f.writes = append(f.writes, "DELETE "+path)
		kept := []D{}
		for _, o := range f.objects[path] {
			if integer(o["id"]) != id {
				kept = append(kept, o)
			}
		}
		f.objects[path] = kept
		w.WriteHeader(204)
	}
}

func (f *fakeNetBox) matches(o D, q map[string][]string) bool {
	for k, v := range q {
		switch {
		case k == "limit" || k == "offset":
		case strings.HasSuffix(k, "_id"):
			field := strings.TrimSuffix(k, "_id")
			if str(nbScalar(o[field])) != v[0] && strconv.Itoa(integer(nbScalar(o[field]))) != v[0] {
				return false
			}
		default:
			if str(o[k]) != v[0] {
				return false
			}
		}
	}
	return true
}

func (f *fakeNetBox) all(path string) []D {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]D{}, f.objects[path]...)
}

func (f *fakeNetBox) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = nil
}

func netboxPlatform(t *testing.T) (*Platform, *fakeNetBox, *httptest.Server) {
	p, _ := fixture(t)
	f, srv := newFakeNetBox(t)
	p.Config["netbox"] = D{"enabled": true, "url": srv.URL, "token": "nbt_secret", "cluster": "carrel", "owner": "carrel"}
	return p, f, srv
}

func syncNetBox(t *testing.T, p *Platform) nbResult {
	t.Helper()
	cfg, ok, err := p.netboxConfig()
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	return p.execution(context.Background()).SyncNetBox(cfg)
}

func seedNetBoxWorld(p *Platform) {
	web := seedMachine(p, "web", 10100)
	web["power_state"] = "running"
	web["nics"] = []D{{"index": 1, "network": "p00101", "mode": "managed", "mac": "02:cb:01:00:01:01", "ip": "10.64.0.10", "prefix": 25}}
	p.Store.Put("machines", 10100, 1, web)
	p.Store.Put("machines", 10101, 1, D{"name": "db", "vmid": 10101, "tenant_n": 1, "kind": "ct", "cpu": 1, "memory_mb": 1024, "disk_gb": 10, "state": "ready", "power_state": "stopped", "ip": "10.200.1.11", "mac": "02:ca:01:01:00:01", "nics": []D{}})
	p.Store.Put("networks", "p00101", 1, D{"id": "p00101", "tenant_n": 1, "serial": 1, "name": "back", "mode": "managed", "cidr": "10.64.0.0/25"})
	p.Store.Put("networks", "p00102", 1, D{"id": "p00102", "tenant_n": 1, "serial": 2, "name": "lab", "mode": "raw_l2", "cidr": "192.168.50.0/24"})
	db := p.Store.Get("machines", "10101")
	db["nics"] = []D{{"index": 1, "network": "p00102", "mode": "raw_l2", "mac": "02:cc:01:01:01:01"}}
	p.Store.Put("machines", 10101, 1, db)
	p.Store.Put("ports", "a", 1, D{"id": "a", "tenant_n": 1, "vmid": 10100, "ip": "10.200.1.10", "port": 22, "proto": "tcp", "public_port": 20010})
	p.Store.Put("domains", "d", 1, D{"id": "d", "tenant_n": 1, "vmid": 10100, "name": "app.alice.winlab.tw", "sub": "app", "slug": "alice", "target_port": 8080, "state": "ready"})
	p.Store.Put("vips", "v", 1, D{"id": "v", "tenant_n": 1, "name": "ha", "address": "10.200.1.251", "vmids": []int{10100, 10101}})
}

func TestNetBoxStaysOffUnlessConfigured(t *testing.T) {
	p, _ := fixture(t)
	if _, ok, err := p.netboxConfig(); ok || err != nil {
		t.Fatal(ok, err)
	}
	p.Config["netbox"] = D{"enabled": true, "url": "https://nb.test"}
	if _, ok, err := p.netboxConfig(); ok || err == nil {
		t.Fatal("an incomplete section was accepted")
	}
	m := seedMachine(p, "web", 10100)
	if pub := p.execution(context.Background()).PublicMachine(m, nil); pub["netbox"] != nil {
		t.Fatal(pub["netbox"])
	}
}

func TestNetBoxSyncCreatesOwnedObjects(t *testing.T) {
	p, f, _ := netboxPlatform(t)
	seedNetBoxWorld(p)
	if r := syncNetBox(t, p); len(r.Errors) > 0 {
		t.Fatal(r.Errors)
	}
	if f.auth != "Bearer nbt_secret" {
		t.Fatal(f.auth)
	}
	vms := f.all("virtualization/virtual-machines/")
	if len(vms) != 2 {
		t.Fatal(vms)
	}
	web := find(vms, func(v D) bool { return v["name"] == "web.alice" })
	if web == nil || obj(web["custom_fields"])["vmid"] != float64(10100) || obj(web["status"])["value"] != "active" || web["vcpus"] != float64(2) || web["disk"] != float64(20480) || obj(web["primary_ip4"])["id"] == nil {
		t.Fatal(web)
	}
	if db := find(vms, func(v D) bool { return v["name"] == "db.alice" }); obj(db["status"])["value"] != "offline" || obj(db["custom_fields"])["vmid"] != float64(10101) {
		t.Fatal(db)
	}
	// The tenant segment shares one VRF; a private network has its own.
	vrfs := f.all("ipam/vrfs/")
	shared, private := find(vrfs, func(v D) bool { return v["name"] == "carrel" }), find(vrfs, func(v D) bool { return v["name"] == "carrel-alice-back" })
	if len(vrfs) != 2 || shared == nil || private == nil {
		t.Fatal(vrfs)
	}
	for _, ip := range f.all("ipam/ip-addresses/") {
		want := shared["id"]
		if ip["address"] == "10.64.0.10/25" {
			want = private["id"]
		}
		if integer(obj(ip["vrf"])["id"]) != integer(want) {
			t.Fatal("address in the wrong VRF", ip)
		}
	}
	if p := find(f.all("ipam/prefixes/"), func(v D) bool { return v["prefix"] == "10.64.0.0/25" }); integer(obj(p["vrf"])["id"]) != integer(private["id"]) {
		t.Fatal(p)
	}
	prefixes := f.all("ipam/prefixes/")
	if len(prefixes) != 2 || find(prefixes, func(v D) bool { return v["prefix"] == "10.64.0.0/25" }) == nil || find(prefixes, func(v D) bool { return v["prefix"] == "10.200.1.0/24" }) == nil {
		t.Fatal(prefixes)
	}
	ips := f.all("ipam/ip-addresses/")
	vip := find(ips, func(v D) bool { return v["address"] == "10.200.1.251/24" })
	if len(ips) != 4 || vip == nil || obj(vip["role"])["value"] != "vip" || vip["assigned_object_type"] != nbGroupType {
		t.Fatal(ips)
	}
	if len(f.all("virtualization/interfaces/")) != 4 {
		t.Fatal(f.all("virtualization/interfaces/"))
	}
	services := f.all("ipam/services/")
	ssh := find(services, func(v D) bool { return v["name"] == "public-tcp-20010" })
	https := find(services, func(v D) bool { return v["name"] == "https://app.alice.winlab.tw" })
	if len(services) != 2 || ssh == nil || https == nil || ssh["port_mappings"].([]any)[0] != "tcp/22" || https["port_mappings"].([]any)[0] != "tcp/8080" || ssh["parent_object_type"] != nbVMType {
		t.Fatal(services)
	}
	if groups := f.all("ipam/fhrp-groups/"); len(groups) != 1 || groups[0]["name"] != "ha.alice" || groups[0]["protocol"] != "other" {
		t.Fatal(groups)
	}
	if len(f.all("ipam/fhrp-group-assignments/")) != 2 {
		t.Fatal(f.all("ipam/fhrp-group-assignments/"))
	}
	// A raw_l2 segment records only the attachment: no prefix, VRF or address.
	lab := find(f.all("virtualization/interfaces/"), func(v D) bool { return strings.Contains(str(v["description"]), "(raw_l2)") })
	if lab == nil || lab["vrf"] != nil || find(prefixes, func(v D) bool { return v["prefix"] == "192.168.50.0/24" }) != nil {
		t.Fatal(lab, prefixes)
	}
	// Every object that can carry the owner has it from the first write.
	for _, path := range []string{"ipam/vrfs/", "ipam/prefixes/", "ipam/ip-addresses/", "virtualization/interfaces/", "virtualization/virtual-machines/", "ipam/services/", "ipam/fhrp-groups/"} {
		for _, o := range f.all(path) {
			if obj(o["owner"])["name"] != "carrel" {
				t.Fatal(path, o)
			}
		}
	}
	// machine_get shows the sync status.
	m := p.Store.Get("machines", "10100")
	status := obj(p.execution(context.Background()).PublicMachine(m, nil)["netbox"])
	if status["last_synced"] == nil || status["last_error"] != nil {
		t.Fatal(status)
	}
}

func TestNetBoxSyncIsIdempotentAndFollowsChanges(t *testing.T) {
	p, f, _ := netboxPlatform(t)
	seedNetBoxWorld(p)
	syncNetBox(t, p)
	f.reset()
	if r := syncNetBox(t, p); len(r.Errors) > 0 || r.Writes != 0 || len(f.writes) != 0 {
		t.Fatal("a second pass changed NetBox", r, f.writes)
	}
	web := p.Store.Get("machines", "10100")
	web["power_state"], web["cpu"] = "stopped", 4
	p.Store.Put("machines", 10100, 1, web)
	syncNetBox(t, p)
	vm := find(f.all("virtualization/virtual-machines/"), func(v D) bool { return v["name"] == "web.alice" })
	if obj(vm["status"])["value"] != "offline" || vm["vcpus"] != float64(4) {
		t.Fatal(vm)
	}
	// Closing the port and the domain removes their services; a VIP loses a member.
	p.Store.Remove("ports", "a")
	p.Store.Remove("domains", "d")
	p.Store.Put("vips", "v", 1, D{"id": "v", "tenant_n": 1, "name": "ha", "address": "10.200.1.251", "vmids": []int{10101}})
	syncNetBox(t, p)
	if len(f.all("ipam/services/")) != 0 || len(f.all("ipam/fhrp-group-assignments/")) != 1 {
		t.Fatal(f.all("ipam/services/"), f.all("ipam/fhrp-group-assignments/"))
	}
}

func TestNetBoxSyncDeletesDependentsFirst(t *testing.T) {
	p, f, _ := netboxPlatform(t)
	seedNetBoxWorld(p)
	syncNetBox(t, p)
	for _, id := range []string{"10100", "10101"} {
		p.Store.Remove("machines", id)
	}
	p.Store.Remove("vips", "v")
	p.Store.Remove("networks", "p00101")
	p.Store.Remove("networks", "p00102")
	if r := syncNetBox(t, p); len(r.Errors) > 0 {
		t.Fatal(r.Errors)
	}
	for _, path := range []string{"virtualization/virtual-machines/", "virtualization/interfaces/", "ipam/ip-addresses/", "ipam/services/", "ipam/fhrp-groups/", "ipam/fhrp-group-assignments/", "ipam/prefixes/", "ipam/vrfs/"} {
		if left := f.all(path); len(left) != 0 {
			t.Fatal(path, left)
		}
	}
	if len(p.Store.Objects("netbox_sync")) != 0 {
		t.Fatal("status of deleted machines stayed")
	}
}

func TestNetBoxSyncLeavesForeignObjectsAlone(t *testing.T) {
	p, f, _ := netboxPlatform(t)
	seedNetBoxWorld(p)
	foreign := D{"id": 50, "name": "web.alice", "cluster": D{"id": 1}}
	other := D{"id": 51, "name": "hand-made", "cluster": D{"id": 1}}
	f.objects["virtualization/virtual-machines/"] = []D{foreign, other}
	r := syncNetBox(t, p)
	if len(r.Errors) != 1 || !strings.Contains(r.Errors[0], "web.alice") {
		t.Fatal(r.Errors)
	}
	vms := f.all("virtualization/virtual-machines/")
	if find(vms, func(v D) bool { return v["id"] == 50 }) == nil || find(vms, func(v D) bool { return v["id"] == 51 }) == nil || obj(foreign)["owner"] != nil {
		t.Fatal("a foreign virtual machine was touched", vms)
	}
	// The other machine synced; the failure shows on the one that failed.
	web := obj(p.execution(context.Background()).PublicMachine(p.Store.Get("machines", "10100"), nil)["netbox"])
	db := obj(p.execution(context.Background()).PublicMachine(p.Store.Get("machines", "10101"), nil)["netbox"])
	if web["last_error"] == nil || db["last_error"] != nil || db["last_synced"] == nil {
		t.Fatal(web, db)
	}
	if len(p.Store.Rows("SELECT * FROM audit WHERE tool='netbox_sync'")) == 0 {
		t.Fatal("failure missing from the audit log")
	}
}

func TestNetBoxFailedMachineKeepsItsObjects(t *testing.T) {
	p, f, _ := netboxPlatform(t)
	seedNetBoxWorld(p)
	syncNetBox(t, p)
	// The custom field disappears: updating a machine now fails.
	f.mu.Lock()
	f.fields = map[string]bool{}
	f.mu.Unlock()
	web := p.Store.Get("machines", "10100")
	web["cpu"] = 8
	p.Store.Put("machines", 10100, 1, web)
	p.Store.Remove("ports", "a")
	if r := syncNetBox(t, p); len(r.Errors) == 0 {
		t.Fatal("no error")
	}
	if len(f.all("virtualization/virtual-machines/")) != 2 || len(f.all("virtualization/interfaces/")) != 4 || len(f.all("ipam/services/")) != 2 {
		t.Fatal("a machine that could not sync lost objects")
	}
}

func TestNetBoxNeedsAnExistingOwner(t *testing.T) {
	p, f, _ := netboxPlatform(t)
	seedNetBoxWorld(p)
	f.objects["users/owners/"] = nil
	r := syncNetBox(t, p)
	if len(r.Errors) != 1 || !strings.Contains(r.Errors[0], "owner carrel does not exist") || len(f.writes) != 0 {
		t.Fatal(r.Errors, f.writes)
	}
	delete(obj(p.Config["netbox"]), "owner")
	if _, ok, err := p.netboxConfig(); ok || err == nil {
		t.Fatal("a section without an owner was accepted")
	}
}

func TestNetBoxOutageNeverBreaksMachineOperations(t *testing.T) {
	p, f, srv := netboxPlatform(t)
	seedNetBoxWorld(p)
	srv.Close()
	r := syncNetBox(t, p)
	if len(r.Errors) == 0 || strings.Contains(strings.Join(r.Errors, " "), "nbt_secret") {
		t.Fatal(r.Errors)
	}
	// The machine still reads, and the failure is on record.
	m := p.Store.Get("machines", "10100")
	if pub := p.execution(context.Background()).PublicMachine(m, nil); pub["name"] != "web" {
		t.Fatal(pub)
	}
	if st := p.Store.SiteGet("netbox", "status"); st == nil || st["last_error"] == nil {
		t.Fatal(st)
	}
	// NetBox comes back and the next pass catches up.
	back := httptest.NewServer(f)
	defer back.Close()
	p.Config["netbox"] = merge(obj(p.Config["netbox"]), D{"url": back.URL})
	if r := syncNetBox(t, p); len(r.Errors) > 0 || len(f.all("virtualization/virtual-machines/")) != 2 {
		t.Fatal(r.Errors)
	}
}

func TestNetBoxKickNeverBlocks(t *testing.T) {
	p, _ := fixture(t)
	for range 5 {
		p.NetBoxKick()
	}
}
