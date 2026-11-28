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

// seenForms are the writes the fake source received; importFailTask names a
// task (a path fragment of its ID) that ends in failure.
var (
	seenForms      []string
	importFailTask = "none"
	// importPollErrors is how many task reads fail before one answers.
	importPollErrors int
	// importGuestStatus, when set, is what status/current reports, one entry
	// per read with the last one repeating. Unset, a guest runs as the
	// inventory says until a shutdown or stop task for it succeeds.
	importGuestStatus []string
	// importRefuse, when set, makes remote_migrate answer 500 with this
	// Proxmox message.
	importRefuse string
	// importTruncate makes remote_migrate answer 200 with a body cut short,
	// as when the connection drops after the headers.
	importTruncate bool
)

// importFake is a source with one running VM on LVM-thin and one CT.
func importFake(t *testing.T) (*httptest.Server, string, *[]string) {
	t.Helper()
	var seen []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "PVEAPIToken=carrel@pve!import="+testSourceSecret {
			http.Error(w, `{"data":null}`, http.StatusUnauthorized)
			return
		}
		if r.Method != "GET" {
			r.ParseForm()
			if importRefuse != "" && strings.HasSuffix(r.URL.Path, "/remote_migrate") {
				seenForms = append(seenForms, r.Method+" "+r.URL.Path+" "+r.PostForm.Encode())
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, `{"data":null,"message":%q}`, importRefuse+" target-endpoint: "+r.PostForm.Get("target-endpoint"))
				return
			}
			if importTruncate && strings.HasSuffix(r.URL.Path, "/remote_migrate") {
				seenForms = append(seenForms, r.Method+" "+r.URL.Path+" "+r.PostForm.Encode())
				fmt.Fprint(w, `{"data":"UPID:anvil:00`)
				return
			}
			seenForms = append(seenForms, r.Method+" "+r.URL.Path+" "+r.PostForm.Encode())
			fmt.Fprint(w, `{"data":"UPID:anvil:0001:0002:0003:`+strings.ReplaceAll(strings.Trim(r.URL.Path[len("/api2/json/nodes/anvil/"):], "/"), "/", "-")+`:root@pam:"}`)
			return
		}
		if strings.Contains(r.URL.Path, "/tasks/") {
			if importPollErrors > 0 {
				importPollErrors--
				http.Error(w, `{"data":null}`, http.StatusInternalServerError)
				return
			}
			status := "OK"
			if strings.Contains(r.URL.Path, importFailTask) {
				status = "command failed"
			}
			fmt.Fprintf(w, `{"data":{"status":"stopped","exitstatus":%q}}`, status)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/status/current") {
			status := "stopped"
			if len(importGuestStatus) > 0 {
				status = importGuestStatus[0]
				if len(importGuestStatus) > 1 {
					importGuestStatus = importGuestStatus[1:]
				}
			} else if strings.Contains(r.URL.Path, "/104/") || strings.Contains(r.URL.Path, "/106/") || strings.Contains(r.URL.Path, "/109/") {
				status = "running"
				guest := strings.TrimSuffix(r.URL.Path[len("/api2/json/nodes/anvil/"):], "status/current")
				for _, f := range seenForms {
					for _, op := range []string{"shutdown", "stop"} {
						if strings.Contains(f, guest+"status/"+op) && !strings.Contains("status-"+op, importFailTask) {
							status = "stopped"
						}
					}
				}
			}
			fmt.Fprintf(w, `{"data":{"status":%q}}`, status)
			return
		}
		switch r.URL.Path {
		case "/api2/json/version":
			fmt.Fprint(w, `{"data":{"version":"8.4.1"}}`)
		case "/api2/json/storage":
			fmt.Fprint(w, `{"data":[{"storage":"local","type":"dir"},{"storage":"local-lvm","type":"lvmthin"},{"storage":"tank","type":"zfspool"}]}`)
		case "/api2/json/cluster/resources":
			fmt.Fprint(w, `{"data":[{"vmid":104,"type":"qemu","node":"anvil","status":"running","template":0},{"vmid":105,"type":"lxc","node":"anvil","status":"stopped"},{"vmid":106,"type":"lxc","node":"anvil","status":"running","template":0},{"vmid":107,"type":"qemu","node":"anvil","status":"stopped","template":0},{"vmid":108,"type":"qemu","node":"anvil","status":"stopped","template":0},{"vmid":109,"type":"qemu","node":"anvil","status":"running","template":0},{"vmid":110,"type":"qemu","node":"anvil","status":"stopped","template":0,"hastate":"stopped"},{"vmid":111,"type":"qemu","node":"anvil","status":"stopped","template":0},{"vmid":112,"type":"qemu","node":"anvil","status":"stopped","template":0},{"vmid":113,"type":"qemu","node":"anvil","status":"stopped","template":0},{"vmid":114,"type":"qemu","node":"anvil","status":"stopped","template":0},{"vmid":115,"type":"qemu","node":"anvil","status":"stopped","template":0},{"vmid":9000,"type":"qemu","node":"anvil","status":"stopped","template":1}]}`)
		case "/api2/json/nodes/anvil/qemu/104/config":
			fmt.Fprint(w, `{"data":{"name":"sandbox","cores":4,"sockets":1,"memory":8192,"cpu":"host","scsi0":"local-lvm:vm-104-disk-0,size=32G","ide2":"local-lvm:vm-104-cloudinit,media=cdrom,size=4M","ide0":"none,media=cdrom","net0":"virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0","ipconfig0":"ip=dhcp","cicustom":"user=local:snippets/u.yaml"}}`)
		case "/api2/json/nodes/anvil/lxc/106/config":
			fmt.Fprint(w, `{"data":{"hostname":"Web_CT","cores":1,"memory":512,"rootfs":"local-lvm:vm-106-disk-0,size=4G","net0":"name=eth0,bridge=vmbr0,ip=10.0.0.6/24"}}`)
		case "/api2/json/nodes/anvil/qemu/107/config":
			fmt.Fprint(w, `{"data":{"name":"cold","cores":2,"sockets":1,"memory":2048,"scsi0":"local-lvm:vm-107-disk-0,size=10G","net0":"virtio=AA:BB:CC:DD:EE:00,bridge=vmbr0"}}`)
		case "/api2/json/nodes/anvil/qemu/108/config":
			fmt.Fprint(w, `{"data":{"name":"huge","cores":2,"sockets":1,"memory":2097152,"scsi0":"tank:vm-108-disk-0,size=10G","net0":"virtio=AA:BB:CC:DD:EE:08,bridge=vmbr0"}}`)
		case "/api2/json/nodes/anvil/qemu/109/config":
			fmt.Fprint(w, `{"data":{"name":"zfsvm","cores":1,"sockets":1,"memory":1024,"scsi0":"tank:vm-109-disk-0,size=8G","ide2":"local-lvm:vm-109-cloudinit,media=cdrom,size=4M","net0":"virtio=AA:BB:CC:DD:EE:09,bridge=vmbr0"}}`)
		case "/api2/json/nodes/anvil/qemu/110/config", "/api2/json/nodes/anvil/qemu/111/config", "/api2/json/nodes/anvil/qemu/112/config", "/api2/json/nodes/anvil/qemu/113/config", "/api2/json/nodes/anvil/qemu/114/config", "/api2/json/nodes/anvil/qemu/115/config":
			extra := map[string]string{"110": ``, "111": `,"protection":1`, "112": `,"scsi1":"tank:vm-112-disk-1,size=4G"`, "113": `,"unused0":"local-lvm:vm-113-disk-1"`, "114": `,"ide0":"local:iso/x.iso,media=cdrom"`, "115": `,"net1":"virtio=AA:BB:CC:DD:EE:11,bridge=vmbr1,firewall=0"`}[r.URL.Path[len("/api2/json/nodes/anvil/qemu/"):][:3]]
			fmt.Fprint(w, `{"data":{"name":"odd","cores":1,"memory":1024,"scsi0":"local-lvm:vm-1xx-disk-0,size=4G","net0":"virtio=AA:BB:CC:DD:EE:10,bridge=vmbr0"`+extra+`}}`)
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

	// Nothing was allocated or changed.
	if after := snapshot(); after != before {
		t.Errorf("state changed:\n%s\n%s", before, after)
	}
}
