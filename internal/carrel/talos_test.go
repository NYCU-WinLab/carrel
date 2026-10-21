package carrel

import (
	"context"
	"strings"
	"testing"
)

// An image imported with ports runs no SSH and no cloud-config (issue #94).
func TestAVMFromAnImageWithPortsHasNoSSH(t *testing.T) {
	p, _ := fixture(t)
	p.Config["ssh_jump"] = true
	e := p.execution(context.Background())
	tenant := p.Store.TenantN(1)
	vol := "rs822rp1:import/carrel-t001-talos-cdcdcdcdcdcd.qcow2"
	p.Store.Put("images", "img1", 1, decode(string(encoded(imageRecord{ID: "img1", TenantN: 1, Name: "talos", Kind: "qcow2", SHA256: strings.Repeat("cd", 32), Size: 300 << 20, VirtualSize: 1 << 30, State: "ready", Volume: vol, Ports: []int{50000, 6443}}))))
	config := "version: v1alpha1\nmachine:\n  token: secret\n"
	// The jump host tunnel needs a saved key.
	if f := attempt(func() { e.MachineSpec(tenant, D{"name": "cp1", "image": "tenant:talos"}, false) }); f == nil {
		t.Fatal("created without a saved key for the tunnel")
	}
	p.Store.Put("keys", "1-k", 1, D{"id": "k", "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAliceAliceAliceAliceAliceAliceAliceAlice"})
	// No keys given: the VM itself takes none.
	m := e.MachineSpec(tenant, D{"name": "cp1", "image": "tenant:talos", "user_data": config}, false)
	if !unmanaged(m) || m["public_ssh"] != false || integer(m["swap_mb"]) != 0 || len(arr(m["ssh_keys"])) != 0 || m["user_data"] != config || m["readiness_token"] != nil {
		t.Fatal(m)
	}
	if integer(m["cpu"]) != 2 || integer(m["memory_mb"]) != 2048 || integer(m["disk_gb"]) != 10 {
		t.Fatal("not sized for a control plane", m)
	}
	if d := machineDelta(m); d["public_ports"] != 0 {
		t.Fatal(d)
	}
	for _, bad := range []D{
		{"name": "x", "image": "tenant:talos", "runcmd": []any{[]any{"true"}}},
		{"name": "x", "image": "tenant:talos", "ssh_keys": []any{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAliceAliceAliceAliceAliceAliceAliceAlice"}},
		{"name": "x", "image": "tenant:talos", "public_ssh": true},
		{"name": "x", "image": "tenant:talos", "user_data": strings.Repeat("a", 65537)},
		{"name": "x", "user_data": "x"},
	} {
		if f := attempt(func() { e.MachineSpec(tenant, bad, false) }); f == nil {
			t.Fatal("accepted", bad)
		}
	}

	m = merge(m, D{"vmid": 10101, "tenant_n": 1, "ip": "10.200.1.11", "state": "ready", "power_state": "running", "node": "carrel01"})
	p.Store.Put("machines", 10101, 1, m)
	pub := e.PublicMachine(m, nil)
	if pub["user_data"] != nil || pub["ssh"] != nil || pub["ssh_jump"] != nil || pub["tunnel"] != "ssh -N -L 50000:10.200.1.11:50000 -L 6443:10.200.1.11:6443 jump@carrel.winlab.tw" {
		t.Fatal(pub)
	}
	// Ready only while the first port answers.
	up := false
	p.serviceProbe = func(_ context.Context, m D) bool { return up }
	e.ObserveSSH(pub)
	if pub["state"] != "initializing" || obj(pub["readiness"])["service_status"] != "unavailable" {
		t.Fatal(pub)
	}
	up = true
	pub = e.PublicMachine(m, nil)
	e.ObserveSSH(pub)
	if pub["state"] != "ready" || obj(pub["readiness"])["service_status"] != "verified" || obj(pub["readiness"])["service_port"] != 50000 {
		t.Fatal(pub)
	}
	if _, ok := obj(pub["readiness"])["ssh_status"]; ok || pub["ssh_ready"] != nil {
		t.Fatal("SSH readiness on a machine without SSH", pub)
	}
	if pub["install"] != nil {
		t.Fatal("ISO install details on a Talos VM", pub)
	}
	// Its ide2 is the cloud-init drive: no media.
	if f := attempt(func() { e.Media(m, D{"action": "eject"}, tenant) }); f == nil {
		t.Fatal("media accepted on a Talos VM")
	}
	// The jump host forwards the declared ports, not SSH.
	keys := jumpAuthorizedKeys(p.Store)
	if !strings.Contains(keys, `permitopen="10.200.1.11:50000",permitopen="10.200.1.11:6443"`) || strings.Contains(keys, "10.200.1.11:22") {
		t.Fatal(keys)
	}
}

func TestImagePortsAreValidated(t *testing.T) {
	if got := servicePorts([]any{50000.0, 6443.0}); len(got) != 2 || got[0] != 50000 {
		t.Fatal(got)
	}
	for _, bad := range []any{[]any{}, []any{22.0}, []any{0.0}, []any{65536.0}, []any{1.5}, []any{80.0, 80.0}, []any{1.0, 2.0, 3.0, 4.0, 5.0}, []any{"80"}} {
		if f := attempt(func() { servicePorts(bad) }); f == nil {
			t.Fatal("accepted", bad)
		}
	}
}

func TestCapabilitiesFollowTheSite(t *testing.T) {
	p, _ := fixture(t)
	e := p.execution(context.Background())
	if e.capabilities()["custom_image_import"] != false {
		t.Fatal("imports without a fetcher")
	}
	p.Config["fetch"] = true
	if e.capabilities()["custom_image_import"] != true || obj(Contract["capabilities"])["custom_image_import"] != false {
		t.Fatal("the site's fetcher is not reported, or the contract changed")
	}
}
