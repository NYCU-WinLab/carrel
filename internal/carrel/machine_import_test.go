package carrel

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// importFake is a source with one running VM on LVM-thin and one CT.
func importFake(t *testing.T) (*httptest.Server, string, *[]string) {
	t.Helper()
	var seen []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		if r.Method != "GET" || r.Header.Get("Authorization") != "PVEAPIToken=carrel@pve!import="+testSourceSecret {
			http.Error(w, `{"data":null}`, http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api2/json/version":
			fmt.Fprint(w, `{"data":{"version":"8.4.1"}}`)
		case "/api2/json/storage":
			fmt.Fprint(w, `{"data":[{"storage":"local","type":"dir"},{"storage":"local-lvm","type":"lvmthin"},{"storage":"tank","type":"zfspool"}]}`)
		case "/api2/json/cluster/resources":
			fmt.Fprint(w, `{"data":[{"vmid":104,"type":"qemu","node":"anvil","status":"running","template":0},{"vmid":105,"type":"lxc","node":"anvil","status":"stopped"},{"vmid":9000,"type":"qemu","node":"anvil","status":"stopped","template":1}]}`)
		case "/api2/json/nodes/anvil/qemu/104/config":
			fmt.Fprint(w, `{"data":{"name":"sandbox","cores":4,"sockets":1,"memory":8192,"cpu":"host","scsi0":"local-lvm:vm-104-disk-0,size=32G","ide2":"local-lvm:vm-104-cloudinit,media=cdrom,size=4M","ide0":"local:iso/x.iso,media=cdrom","net0":"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0","ipconfig0":"ip=dhcp","cicustom":"user=local:snippets/u.yaml"}}`)
		case "/api2/json/nodes/anvil/lxc/105/config":
			fmt.Fprint(w, `{"data":{"hostname":"ct","cores":2,"memory":1024,"rootfs":"tank:subvol-105-disk-0,size=8G","net0":"name=eth0,bridge=vmbr0,ip=10.0.0.5/24"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return srv, strings.Join(parts, ":"), &seen
}

func TestMachineImportDryRun(t *testing.T) {
	p, _ := fixture(t)
	p.Config.SourceDir = t.TempDir()
	srv, fp, seen := importFake(t)
	admin, alice := person("root", true), person("alice", false)
	run := func(a, who D) D { return p.Execute(context.Background(), "machine_import", a, who) }
	if r := p.Execute(context.Background(), "source_add", sourceArgs(srv, fp), admin); r["ok"] != true {
		t.Fatalf("source_add: %v", r)
	}
	args := func(guest int) D { return D{"tenant": "alice", "source": "old-lab", "guest": guest, "dry_run": true} }
	snapshot := func() string {
		return fmt.Sprint(p.Store.Objects("machines", 1), p.Store.Objects("ports", 1), p.Store.Rows("SELECT n, quota FROM tenants"), p.Store.Objects("operations", 1))
	}
	before := snapshot()
	*seen = nil

	// A member is refused and the source is not called.
	if r := run(args(104), alice); r["ok"] == true || obj(r["error"])["code"] != "forbidden" {
		t.Fatalf("non-admin: %v", r)
	}
	if len(*seen) != 0 {
		t.Fatalf("a refused call reached the source: %v", *seen)
	}

	// A running VM on LVM-thin.
	r := run(args(104), admin)
	if r["ok"] != true || r["dry_run"] != true {
		t.Fatalf("dry run: %v", r)
	}
	plan := obj(r["plan"])
	target := obj(plan["target"])
	if integer(target["vmid"]) != 10100 || target["ip"] != "10.200.1.10" || plan["path"] != "directory_hop" {
		t.Errorf("plan = %v", plan)
	}
	if num(plan["disk_gib"]) != 32 || num(obj(plan["quota_delta"])["vcpu"]) != 4 || num(obj(plan["quota_delta"])["memory_mb"]) != 8192 || num(obj(r["delta"])["machines"]) != 1 {
		t.Errorf("sizes: %v / delta %v", plan, r["delta"])
	}
	if len(arr(plan["disks"])) != 2 {
		t.Errorf("disks (a CD-ROM is not one): %v", plan["disks"])
	}
	text := fmt.Sprint(plan["changes"], plan["warnings"])
	for _, want := range []string{"cloud-init disk", "dropped", "directory storage", "x86-64-v3", "cicustom", "dhcp", "firewall=1"} {
		if !strings.Contains(text, want) {
			t.Errorf("plan does not mention %q: %s", want, text)
		}
	}
	// Every call to the source was a read.
	for _, c := range *seen {
		if !strings.HasPrefix(c, "GET ") {
			t.Errorf("source call %s", c)
		}
	}

	// A stopped CT on ZFS goes direct.
	r = run(args(105), admin)
	if r["ok"] != true || obj(r["plan"])["path"] != "direct" || obj(obj(r["plan"])["guest"])["kind"] != "ct" {
		t.Fatalf("ct: %v", r)
	}

	// A template, an unknown guest, an unknown source.
	for _, bad := range []D{{"guest": 9000}, {"guest": 777}, {"source": "nowhere"}} {
		a := args(104)
		for k, v := range bad {
			a[k] = v
		}
		if r := run(a, admin); r["ok"] == true || obj(r["error"])["code"] != "not_found" {
			t.Errorf("%v: %v", bad, r)
		}
	}

	// confirm is not built; neither is a call without dry_run.
	conf := args(104)
	delete(conf, "dry_run")
	conf["confirm"] = true
	if r := run(conf, admin); r["ok"] == true || obj(r["error"])["code"] != "not_implemented" {
		t.Errorf("confirm: %v", r)
	}
	delete(conf, "confirm")
	if r := run(conf, admin); r["ok"] == true || obj(r["error"])["code"] != "invalid" {
		t.Errorf("neither: %v", r)
	}

	// Nothing was allocated or changed.
	if after := snapshot(); after != before {
		t.Errorf("state changed:\n%s\n%s", before, after)
	}
}
