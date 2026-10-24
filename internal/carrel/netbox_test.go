package carrel

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
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

var nbRefs = map[string]bool{"cluster": true, "vrf": true, "virtual_machine": true, "group": true, "primary_ip4": true, "platform": true, "device": true, "primary_mac_address": true, "nat_inside": true}
var nbChoices = map[string]bool{"status": true, "role": true, "start_on_boot": true}

func newFakeNetBox(t *testing.T) (*fakeNetBox, *httptest.Server) {
	f := &fakeNetBox{objects: map[string][]D{}, next: 100, fields: map[string]bool{"vmid": true}}
	f.objects["virtualization/clusters/"] = []D{{"id": 1, "name": "carrel"}}
	f.objects["users/owners/"] = []D{{"id": 7, "name": "carrel"}}
	f.objects["dcim/devices/"] = []D{{"id": 3, "name": "Carrel01", "cluster": D{"id": 1}}}
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
	// NetBox keeps platform names unique.
	if r.Method == "POST" || r.Method == "PATCH" {
		if path == "dcim/platforms/" {
			for _, field := range []string{"name", "slug"} {
				if v, ok := body[field]; ok {
					for _, o := range f.objects[path] {
						if o[field] == v && integer(o["id"]) != id {
							reply(400, D{field: "platform with this " + field + " already exists"})
							return
						}
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
	if web == nil || obj(web["custom_fields"])["vmid"] != float64(10100) || obj(web["status"])["value"] != "active" || web["vcpus"] != float64(2) || web["disk"] != nil || obj(web["start_on_boot"])["value"] != "on" || integer(obj(web["device"])["id"]) != 3 || obj(web["primary_ip4"])["id"] == nil {
		t.Fatal(web)
	}
	if db := find(vms, func(v D) bool { return v["name"] == "db.alice" }); obj(db["status"])["value"] != "offline" || obj(db["custom_fields"])["vmid"] != float64(10101) || obj(db["start_on_boot"])["value"] != "off" || db["platform"] != nil || db["device"] != nil {
		t.Fatal(db)
	}
	// The platform is carrel's own, named after the image.
	platforms := f.all("dcim/platforms/")
	if len(platforms) != 1 || platforms[0]["name"] != "Carrel: Debian 13" || platforms[0]["slug"] != "carrel-catalog-debian-13" || integer(obj(web["platform"])["id"]) != integer(platforms[0]["id"]) {
		t.Fatal(platforms, web["platform"])
	}
	// Each machine's disk is a virtual disk, in MiB.
	disks := f.all("virtualization/virtual-disks/")
	root, rootfs := find(disks, func(v D) bool { return v["name"] == "scsi0" }), find(disks, func(v D) bool { return v["name"] == "rootfs" })
	if len(disks) != 2 || root == nil || rootfs == nil || root["size"] != float64(20480) || rootfs["size"] != float64(10240) || integer(obj(root["virtual_machine"])["id"]) != integer(web["id"]) {
		t.Fatal(disks)
	}
	// Once a node reports the volume, the same disk takes its name (#175).
	webDB := p.Store.Get("machines", "10100")
	webDB["disk_volume"] = "local-zfs:base-9010-disk-0/vm-10100-disk-0"
	p.Store.Put("machines", 10100, 1, webDB)
	if r := syncNetBox(t, p); len(r.Errors) > 0 {
		t.Fatal(r.Errors)
	}
	renamed := find(f.all("virtualization/virtual-disks/"), func(v D) bool { return v["name"] == webDB["disk_volume"] })
	if len(f.all("virtualization/virtual-disks/")) != 2 || renamed == nil || renamed["id"] != root["id"] {
		t.Fatal(f.all("virtualization/virtual-disks/"))
	}
	// A MAC address is an object of its own and the interface's primary one.
	macs := f.all("dcim/mac-addresses/")
	eth0 := find(f.all("virtualization/interfaces/"), func(v D) bool {
		return v["name"] == "eth0" && integer(obj(v["virtual_machine"])["id"]) == integer(web["id"])
	})
	mac := find(macs, func(v D) bool { return v["mac_address"] == "02:CA:01:00:00:01" })
	if len(macs) != 4 || mac == nil || integer(mac["assigned_object_id"]) != integer(eth0["id"]) || integer(obj(eth0["primary_mac_address"])["id"]) != integer(mac["id"]) {
		t.Fatal(macs, eth0)
	}
	// The tenant segment shares one VRF; a private network has its own.
	vrfs := f.all("ipam/vrfs/")
	shared, private := find(vrfs, func(v D) bool { return v["name"] == "Carrel" }), find(vrfs, func(v D) bool { return v["name"] == "Carrel Alice back" })
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
		// Only the machine address carries the infra resolver's name.
		dns := ""
		if machine, ok := strings.CutPrefix(str(ip["description"]), "Carrel address of "); ok && integer(obj(ip["vrf"])["id"]) == integer(shared["id"]) {
			dns = machine + ".internal"
		}
		if str(ip["dns_name"]) != dns {
			t.Fatal("dns_name", ip)
		}
	}
	if ip := find(f.all("ipam/ip-addresses/"), func(v D) bool { return integer(v["id"]) == integer(obj(web["primary_ip4"])["id"]) }); ip["dns_name"] != "web.alice.internal" {
		t.Fatal("primary address", ip)
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
	for _, path := range []string{"ipam/vrfs/", "ipam/prefixes/", "ipam/ip-addresses/", "virtualization/interfaces/", "virtualization/virtual-machines/", "ipam/services/", "ipam/fhrp-groups/", "dcim/platforms/", "dcim/mac-addresses/", "virtualization/virtual-disks/"} {
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

// A public port or domain at a virtual address belongs to its FHRP group,
// not to a machine (issue #146).
func TestNetBoxServicesAtAVirtualAddressBelongToItsGroup(t *testing.T) {
	p, f, _ := netboxPlatform(t)
	seedNetBoxWorld(p)
	p.Store.Put("ports", "b", 1, D{"id": "b", "tenant_n": 1, "vmid": 0, "vip": "v", "ip": "10.200.1.251", "port": 6443, "proto": "tcp", "public_port": 20011})
	p.Store.Put("domains", "e", 1, D{"id": "e", "tenant_n": 1, "vmid": 0, "vip": "v", "name": "k8s.alice.winlab.tw", "sub": "k8s", "slug": "alice", "target_port": 443, "state": "ready"})
	for range 2 {
		if r := syncNetBox(t, p); len(r.Errors) > 0 {
			t.Fatal(r.Errors)
		}
	}
	group := f.all("ipam/fhrp-groups/")[0]
	services := f.all("ipam/services/")
	if len(services) != 4 {
		t.Fatal(services)
	}
	for _, name := range []string{"public-tcp-20011", "https://k8s.alice.winlab.tw"} {
		sv := find(services, func(v D) bool { return v["name"] == name })
		if sv == nil || sv["parent_object_type"] != nbGroupType || integer(sv["parent_object_id"]) != integer(group["id"]) {
			t.Fatal(name, services)
		}
	}
	// Closing them removes only the group's services.
	p.Store.Remove("ports", "b")
	p.Store.Remove("domains", "e")
	if r := syncNetBox(t, p); len(r.Errors) > 0 {
		t.Fatal(r.Errors)
	}
	if services := f.all("ipam/services/"); len(services) != 2 || find(services, func(v D) bool { return v["parent_object_type"] == nbGroupType }) != nil {
		t.Fatal(services)
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
	for _, path := range []string{"virtualization/virtual-machines/", "virtualization/interfaces/", "ipam/ip-addresses/", "ipam/services/", "ipam/fhrp-groups/", "ipam/fhrp-group-assignments/", "ipam/prefixes/", "ipam/vrfs/", "dcim/platforms/", "dcim/mac-addresses/", "virtualization/virtual-disks/"} {
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
	kept := func() []int {
		var n []int
		for _, path := range []string{"virtualization/virtual-machines/", "virtualization/interfaces/", "ipam/services/", "dcim/platforms/", "dcim/mac-addresses/", "virtualization/virtual-disks/"} {
			n = append(n, len(f.all(path)))
		}
		return n
	}
	before := kept()
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
	if after := kept(); fmt.Sprint(after) != fmt.Sprint(before) || before[0] != 2 || before[1] != 4 || before[2] != 2 {
		t.Fatal("a machine that could not sync lost objects", before, after)
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

func TestNetBoxOwnerMatchesByName(t *testing.T) {
	// A server that ignores ?name= returns whatever owners it has.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(D{"count": 1, "results": []D{{"id": 9, "name": "someone-else"}}})
	}))
	t.Cleanup(srv.Close)
	c := &nbClient{base: srv.URL, http: srv.Client(), ctx: context.Background(), marker: nbMarker{Value: "carrel"}}
	if err := attempt(c.prepare); err == nil || c.marker.owner != 0 {
		t.Fatal(err, c.marker.owner)
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

func TestNetBoxDeviceMatchesTheConfiguredField(t *testing.T) {
	p, f, _ := netboxPlatform(t)
	seedNetBoxWorld(p)
	f.objects["dcim/devices/"] = []D{{"id": 3, "name": "serverQ10", "cluster": D{"id": 1}, "custom_fields": D{"hostname": "carrel01"}}}
	device := func() any {
		vm := find(f.all("virtualization/virtual-machines/"), func(v D) bool { return v["name"] == "web.alice" })
		return vm["device"]
	}
	syncNetBox(t, p)
	if device() != nil {
		t.Fatal("a device matched by name although its name is not the node", device())
	}
	obj(p.Config["netbox"])["device_field"] = "hostname"
	syncNetBox(t, p)
	if integer(obj(device())["id"]) != 3 {
		t.Fatal(device())
	}
}

func TestNetBoxStartOnBootFollowsTheOwner(t *testing.T) {
	p, f, _ := netboxPlatform(t)
	seedNetBoxWorld(p)
	// A guest that shut itself down was not stopped by its owner: onboot stays 1.
	web := p.Store.Get("machines", "10100")
	web["power_state"], web["onboot"] = "stopped", true
	p.Store.Put("machines", 10100, 1, web)
	syncNetBox(t, p)
	vm := find(f.all("virtualization/virtual-machines/"), func(v D) bool { return v["name"] == "web.alice" })
	if obj(vm["start_on_boot"])["value"] != "on" {
		t.Fatal(vm["start_on_boot"])
	}
	// An owner stop clears it, whatever the machine observes afterwards.
	web["onboot"] = false
	p.Store.Put("machines", 10100, 1, web)
	syncNetBox(t, p)
	vm = find(f.all("virtualization/virtual-machines/"), func(v D) bool { return v["name"] == "web.alice" })
	if obj(vm["start_on_boot"])["value"] != "off" {
		t.Fatal(vm["start_on_boot"])
	}
}

func TestNetBoxImagesWithSimilarNamesKeepTheirOwnPlatform(t *testing.T) {
	p, f, _ := netboxPlatform(t)
	seedNetBoxWorld(p)
	web, db := p.Store.Get("machines", "10100"), p.Store.Get("machines", "10101")
	web["image"], db["image"] = "tenant:x", "tenant-x"
	p.Store.Put("machines", 10100, 1, web)
	p.Store.Put("machines", 10101, 1, db)
	syncNetBox(t, p)
	f.reset()
	platforms := f.all("dcim/platforms/")
	slugs := map[any]bool{}
	for _, o := range platforms {
		slugs[o["slug"]] = true
	}
	if len(platforms) != 2 || len(slugs) != 2 {
		t.Fatal(platforms)
	}
	if r := syncNetBox(t, p); len(r.Errors) > 0 || r.Writes != 0 {
		t.Fatal("platforms were rewritten", r, f.writes)
	}
}

func TestNetBoxTenantImagesAreNotSharedAcrossTenants(t *testing.T) {
	p, f, _ := netboxPlatform(t)
	seedNetBoxWorld(p)
	bob := p.Store.Tenant("user:bob")
	web := p.Store.Get("machines", "10100")
	web["image"] = "tenant:base"
	p.Store.Put("machines", 10100, 1, web)
	other := seedMachine(p, "app", 20100)
	p.Store.Remove("machines", "20100")
	other["tenant_n"], other["image"] = bob["n"], "tenant:base"
	p.Store.Put("machines", 20100, integer(bob["n"]), other)
	if r := syncNetBox(t, p); len(r.Errors) > 0 {
		t.Fatal(r.Errors)
	}
	names := []string{}
	for _, o := range f.all("dcim/platforms/") {
		names = append(names, str(o["name"]))
	}
	if len(names) != 2 || !slices.Contains(names, "Carrel: Alice/base") || !slices.Contains(names, "Carrel: Bob/base") {
		t.Fatal(names)
	}
}

func TestNetBoxTenantImageAndISOOfOneNameGetOwnPlatforms(t *testing.T) {
	p, f, _ := netboxPlatform(t)
	seedNetBoxWorld(p)
	web := p.Store.Get("machines", "10100")
	web["image"] = "tenant:win11"
	p.Store.Put("machines", 10100, 1, web)
	iso := seedMachine(p, "app", 10200)
	iso["image"] = "iso:win11"
	p.Store.Put("machines", 10200, 1, iso)
	if r := syncNetBox(t, p); len(r.Errors) > 0 {
		t.Fatal(r.Errors)
	}
	names := []string{}
	for _, o := range f.all("dcim/platforms/") {
		names = append(names, str(o["name"]))
	}
	if len(names) != 2 || !slices.Contains(names, "Carrel: Alice/win11") || !slices.Contains(names, "Carrel: Alice/win11 (ISO)") {
		t.Fatal(names)
	}
}

func TestNetBoxRenamesAVRFNamedTheOldWay(t *testing.T) {
	p, f, _ := netboxPlatform(t)
	seedNetBoxWorld(p)
	syncNetBox(t, p)
	ids := map[string]int{}
	old := map[string]string{"Carrel": "carrel", "Carrel Alice back": "carrel-alice-back"}
	for _, v := range f.all("ipam/vrfs/") {
		ids[old[str(v["name"])]] = integer(v["id"])
		v["name"] = old[str(v["name"])]
	}
	if len(ids) != 2 {
		t.Fatal(ids)
	}
	if r := syncNetBox(t, p); len(r.Errors) > 0 {
		t.Fatal(r.Errors)
	}
	vrfs := f.all("ipam/vrfs/")
	if len(vrfs) != 2 {
		t.Fatal("a VRF was replaced instead of renamed", vrfs)
	}
	for _, v := range vrfs {
		if _, still := ids[str(v["name"])]; still {
			t.Fatal("VRF kept the old name", v)
		}
	}
	for _, v := range vrfs {
		if v["name"] == "Carrel" && integer(v["id"]) != ids["carrel"] || v["name"] == "Carrel Alice back" && integer(v["id"]) != ids["carrel-alice-back"] {
			t.Fatal("VRF got a new id", v, ids)
		}
	}
}

func TestNetBoxVRFsOfSimilarTenantsStayApart(t *testing.T) {
	p, f, _ := netboxPlatform(t)
	seedNetBoxWorld(p)
	ab := p.Store.Register("user:alice-back", "alice-back")
	p.Store.Put("networks", "n1", 1, D{"id": "n1", "tenant_n": 1, "serial": 3, "name": "back-x", "mode": "managed", "cidr": "10.64.1.0/25"})
	p.Store.Put("networks", "n2", integer(ab["n"]), D{"id": "n2", "tenant_n": integer(ab["n"]), "serial": 4, "name": "x", "mode": "managed", "cidr": "10.64.2.0/25"})
	syncNetBox(t, p)
	f.reset()
	if r := syncNetBox(t, p); len(r.Errors) > 0 || r.Writes != 0 {
		t.Fatal("a second pass wrote", r, f.writes)
	}
	names := []string{}
	for _, v := range f.all("ipam/vrfs/") {
		names = append(names, str(v["name"]))
	}
	if !slices.Contains(names, "Carrel Alice back-x") || !slices.Contains(names, "Carrel Alice-back x") {
		t.Fatal(names)
	}
}

func TestNetBoxPlatformFromBeforeThePrefixIsRenamedInPlace(t *testing.T) {
	p, f, _ := netboxPlatform(t)
	seedNetBoxWorld(p)
	syncNetBox(t, p)
	platforms := f.all("dcim/platforms/")
	id := integer(platforms[0]["id"])
	platforms[0]["name"], platforms[0]["slug"] = "Catalog:debian-13", "catalog-debian-13"
	if r := syncNetBox(t, p); len(r.Errors) > 0 {
		t.Fatal(r.Errors)
	}
	got := f.all("dcim/platforms/")
	if len(got) != 1 || got[0]["name"] != "Carrel: Debian 13" || got[0]["slug"] != "carrel-catalog-debian-13" || integer(got[0]["id"]) != id {
		t.Fatal("the old platform was not renamed in place", got)
	}
	f.reset()
	if r := syncNetBox(t, p); len(r.Errors) > 0 || r.Writes != 0 {
		t.Fatal("a second pass wrote", r, f.writes)
	}
}

func TestNetBoxPlatformNameTakenByHandFailsOnlyThatImage(t *testing.T) {
	p, f, _ := netboxPlatform(t)
	seedNetBoxWorld(p)
	f.objects["dcim/platforms/"] = []D{{"id": 900, "name": "Carrel: Debian 13", "slug": "debian-13"}}
	r := syncNetBox(t, p)
	if len(r.Errors) != 1 || !strings.Contains(r.Errors[0], "web") {
		t.Fatal(r.Errors)
	}
	if vm := find(f.all("virtualization/virtual-machines/"), func(v D) bool { return v["name"] == "db.alice" }); vm == nil {
		t.Fatal("a machine without that image did not sync")
	}
	if got := f.all("dcim/platforms/"); len(got) != 1 || got[0]["slug"] != "debian-13" {
		t.Fatal("the platform made by hand was touched", got)
	}
}

// A renamed machine keeps its NetBox object: the VMID finds it, the name is
// patched (machine_rename).
func TestNetBoxRenameKeepsTheVirtualMachine(t *testing.T) {
	p, f, _ := netboxPlatform(t)
	seedNetBoxWorld(p)
	syncNetBox(t, p)
	before := find(f.all("virtualization/virtual-machines/"), func(v D) bool { return v["name"] == "web.alice" })
	web := p.Store.Get("machines", "10100")
	web["name"] = "site"
	p.Store.Put("machines", 10100, 1, web)
	if r := syncNetBox(t, p); len(r.Errors) > 0 {
		t.Fatal(r.Errors)
	}
	after := find(f.all("virtualization/virtual-machines/"), func(v D) bool { return v["name"] == "site.alice" })
	if before == nil || after == nil || before["id"] != after["id"] {
		t.Fatal("rename replaced the NetBox VM", before, after)
	}
	if find(f.all("virtualization/virtual-machines/"), func(v D) bool { return v["name"] == "web.alice" }) != nil {
		t.Fatal("the old name stayed")
	}
}

// The pool is the active ranges of the public tenant and role, and a bound
// address is recorded as the outside of its machine's primary address (#91).
func TestNetBoxReadsThePoolAndRecordsBoundAddresses(t *testing.T) {
	p, f, _ := netboxPlatform(t)
	seedNetBoxWorld(p)
	f.objects["ipam/ip-ranges/"] = []D{
		{"id": 1, "start_address": "140.113.60.163/27", "end_address": "140.113.60.165/27", "tenant": D{"name": "Carrel"}, "role": D{"name": "User"}, "status": D{"value": "active"}},
		{"id": 2, "start_address": "140.113.60.171/27", "end_address": "140.113.60.174/27", "tenant": D{"name": "Lab"}, "role": D{"name": "User"}, "status": D{"value": "active"}},
		{"id": 3, "start_address": "140.113.60.175/27", "end_address": "140.113.60.176/27", "tenant": D{"name": "Carrel"}, "role": D{"name": "User"}, "status": D{"value": "reserved"}},
	}
	p.Config["public_address"] = "140.113.60.184"
	if r := syncNetBox(t, p); len(r.Errors) > 0 {
		t.Fatal(r.Errors)
	}
	e := p.execution(context.Background())
	if pool := e.publicPool(); strings.Join(pool, " ") != "140.113.60.163 140.113.60.164 140.113.60.165" {
		t.Fatal(pool)
	}
	p.Store.Put("public_ips", "b", 1, publicIP{ID: "b", TenantN: 1, Address: "140.113.60.163", VMID: 10100, Ports: []string{"tcp/22"}}.D())
	if r := syncNetBox(t, p); len(r.Errors) > 0 {
		t.Fatal(r.Errors)
	}
	ips := f.all("ipam/ip-addresses/")
	outside := find(ips, func(o D) bool { return o["address"] == "140.113.60.163/27" })
	inside := find(ips, func(o D) bool { return o["address"] == "10.200.1.10/24" })
	if outside == nil || inside == nil || integer(obj(outside["nat_inside"])["id"]) != integer(inside["id"]) || outside["vrf"] != nil {
		t.Fatal(outside, inside)
	}
	// Unbound, the record goes.
	p.Store.Put("public_ips", "b", 1, publicIP{ID: "b", TenantN: 1, Address: "140.113.60.163"}.D())
	if r := syncNetBox(t, p); len(r.Errors) > 0 {
		t.Fatal(r.Errors)
	}
	if find(f.all("ipam/ip-addresses/"), func(o D) bool { return o["address"] == "140.113.60.163/27" }) != nil {
		t.Fatal("an unbound address stayed in NetBox")
	}
}
