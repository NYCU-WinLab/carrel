package carrel

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestAnISOImportFetchesStoresAndCounts(t *testing.T) {
	p, b := fixture(t)
	p.Config["fetch"] = true
	sum := strings.Repeat("ab", 32)
	var mu sync.Mutex
	state := D{}
	b.call = func(r D, _ string) (any, error) {
		mu.Lock()
		defer mu.Unlock()
		switch r["op"] {
		case "fetch_start":
			state[str(r["job"])] = "running"
			if strings.Contains(str(r["url"]), "broken") {
				state[str(r["job"])] = "failed"
			}
			if strings.Contains(str(r["url"]), "sized") {
				state[str(r["job"])+"-virtual"] = float64(12 << 30)
			}
			return D{"state": "running"}, nil
		case "fetch_status":
			if state[str(r["job"])] == "failed" {
				return D{"state": "failed", "result": D{"code": "checksum_mismatch", "error": "the file does not match its SHA-256"}}, nil
			}
			if state[str(r["job"])+"-virtual"] != nil {
				return D{"state": "done", "received": 3000, "result": D{"virtual_size": state[str(r["job"])+"-virtual"]}}, nil
			}
			return D{"state": "done", "received": 3000}, nil
		case "fetch_store":
			return D{"state": "stored", "volume": "rs822rp1:iso/" + str(r["volume"]), "size": 3000}, nil
		case "fetch_clean", "image_delete":
			state["cleaned"] = str(r["op"])
			return D{"state": "done"}, nil
		}
		return D{}, nil
	}
	runQueue(p)
	ctx, alice := context.Background(), person("alice", false)
	r := p.Execute(ctx, "iso_import", D{"name": "netinst", "url": "https://example.com/netinst.iso", "sha256": sum}, alice)
	op := awaitStateWithinMs(t, p, str(obj(r["operation"])["id"]), "succeeded")
	image := obj(obj(op["result"])["image"])
	if image["state"] != "ready" || image["volume"] != "rs822rp1:iso/carrel-t001-netinst-abababababab.iso" || num(image["size_bytes"]) != 3000 {
		t.Fatal(op)
	}
	list := p.Execute(ctx, "image_list", D{}, alice)
	if len(dicts(list["images"])) != 1 || num(obj(list["images_gb"])["used_gib"]) <= 0 {
		t.Fatal(list)
	}
	// The same name again is refused; a failed download leaves nothing.
	if r := p.Execute(ctx, "iso_import", D{"name": "netinst", "url": "https://example.com/x.iso", "sha256": sum}, alice); obj(obj(r["operation"])["error"])["code"] != "conflict" {
		t.Fatal(r)
	}
	r = p.Execute(ctx, "iso_import", D{"name": "bad", "url": "https://example.com/broken.iso", "sha256": sum}, alice)
	op = awaitStateWithinMs(t, p, str(obj(r["operation"])["id"]), "failed")
	if obj(op["error"])["code"] != "checksum_mismatch" || state["cleaned"] != "fetch_clean" || len(p.Store.Objects("images", 1)) != 1 {
		t.Fatal(op)
	}
	// A disk image keeps the virtual size the fetcher reported.
	r = p.Execute(ctx, "image_import", D{"name": "sized", "url": "https://example.com/sized.qcow2", "sha256": sum}, alice)
	op = awaitStateWithinMs(t, p, str(obj(r["operation"])["id"]), "succeeded")
	if rec, ok := e2image(p, "sized"); !ok || rec.VirtualSize != 12<<30 || num(obj(obj(op["result"])["image"])["virtual_size_bytes"]) != 12<<30 {
		t.Fatal(op)
	}
	// A disk image finished without a virtual size cannot be sized: refused.
	r = p.Execute(ctx, "image_import", D{"name": "nosize", "url": "https://example.com/disk.qcow2", "sha256": sum}, alice)
	op = awaitStateWithinMs(t, p, str(obj(r["operation"])["id"]), "failed")
	if obj(op["error"])["code"] != "image_refused" || len(p.Store.Objects("images", 1)) != 2 {
		t.Fatal(op)
	}
	if r := p.Execute(ctx, "image_delete", D{"name": "netinst", "confirm": "nope"}, alice); r["ok"] != false {
		t.Fatal("deleted without confirmation")
	}
	if r := p.Execute(ctx, "image_delete", D{"name": "netinst", "confirm": "netinst"}, alice); r["ok"] != true || state["cleaned"] != "image_delete" || len(p.Store.Objects("images", 1)) != 1 {
		t.Fatal(r)
	}
	// Without room in images_gb nothing starts.
	p.Store.Exec(`UPDATE tenants SET quota=json_set(quota,'$.images_gb',0) WHERE n=1`)
	if r := p.Execute(ctx, "iso_import", D{"name": "more", "url": "https://example.com/x.iso", "sha256": sum}, alice); obj(obj(r["operation"])["error"])["code"] != "quota_exceeded" {
		t.Fatal(r)
	}
}

func awaitStateWithinMs(t *testing.T, p *Platform, id, state string) D {
	t.Helper()
	return awaitStateWithin(t, p, id, state, 20e9)
}

func TestAnImportCutByARestartDoesNotReportSuccess(t *testing.T) {
	p, b := fixture(t)
	p.Config["fetch"] = true
	ctx, cancel := context.WithCancel(context.Background())
	e := p.execution(ctx)
	e.Op = D{"id": "op1", "tool": "iso_import", "tenant_n": 1}
	tenant := p.Store.TenantN(1)
	b.call = func(r D, _ string) (any, error) {
		switch r["op"] {
		case "fetch_status":
			return D{"state": "done"}, nil
		case "fetch_store":
			cancel()
			return nil, context.Canceled
		}
		return D{"state": "running"}, nil
	}
	e.PlanImport("iso_import", D{"name": "netinst", "url": "https://example.com/x.iso", "sha256": strings.Repeat("ab", 32)}, tenant)
	if attempt(e.PerformImport) == nil {
		t.Fatal("a cut store passed")
	}
	if len(p.Store.Objects("images", 1)) != 1 {
		t.Fatal("a shutdown dropped the record")
	}
	if attempt(func() { e.FinishImport() }) == nil {
		t.Fatal("reported an image that is not stored")
	}
}

func TestAMachineInstalledFromAnISO(t *testing.T) {
	p, b := fixture(t)
	vol := "rs822rp1:iso/carrel-t001-netinst-abababababab.iso"
	p.Store.Put("images", "img1", 1, decode(string(encoded(imageRecord{ID: "img1", TenantN: 1, Name: "netinst", Kind: "iso", SHA256: strings.Repeat("ab", 32), Size: 3000, State: "ready", Volume: vol}))))
	var mu sync.Mutex
	var sent []D
	b.call = func(r D, _ string) (any, error) {
		mu.Lock()
		sent = append(sent, r)
		mu.Unlock()
		switch r["op"] {
		case "status":
			return D{"status": "running"}, nil
		case "inventory":
			return baseInventory(), nil
		}
		return D{"state": "done", "power_state": "running"}, nil
	}
	runQueue(p)
	ctx, alice := context.Background(), person("alice", false)
	r := p.Execute(ctx, "machine_create", D{"name": "win", "iso": "netinst", "firmware": "uefi", "tpm": true}, alice)
	op := awaitStateWithinMs(t, p, str(obj(r["operation"])["id"]), "succeeded")
	m := obj(obj(op["result"])["machine"])
	install := obj(m["install"])
	if m["state"] != "installing" || install["media"] != "inserted" || install["gateway"] != "10.200.1.1" || install["dns"] != "10.200.0.2" {
		t.Fatal(m)
	}
	var create D
	for _, s := range sent {
		if s["op"] == "create" {
			create = obj(s["machine"])
		}
	}
	if create["iso_volume"] != vol || create["firmware"] != "uefi" || create["tpm"] != true || len(arr(create["ssh_keys"])) != 0 {
		t.Fatal(create)
	}
	if r := p.Execute(ctx, "image_delete", D{"name": "netinst", "confirm": "netinst"}, alice); r["ok"] != false {
		t.Fatal("deleted an ISO that is attached", r)
	}
	r = p.Execute(ctx, "machine_media", D{"machine": "win", "action": "eject"}, alice)
	op = awaitStateWithinMs(t, p, str(obj(r["operation"])["id"]), "succeeded")
	if m := obj(obj(op["result"])["machine"]); m["state"] != "ready" || obj(m["install"])["media"] != "ejected" {
		t.Fatal(m)
	}
	if r := p.Execute(ctx, "image_delete", D{"name": "netinst", "confirm": "netinst"}, alice); r["ok"] != true {
		t.Fatal(r)
	}
	// Managed machines take no media; an ISO needs a VM.
	seedMachine(p, "web", 10150)
	if r := p.Execute(ctx, "machine_media", D{"machine": "web", "action": "eject"}, alice); obj(obj(r["operation"])["error"])["code"] != "invalid" {
		t.Fatal(r)
	}
	if r := p.Execute(ctx, "machine_create", D{"name": "box", "kind": "ct", "iso": "netinst"}, alice); r["ok"] != false && obj(obj(r["operation"])["error"])["code"] == nil {
		t.Fatal(r)
	}
}

func TestAVMBootsATenantCloudImage(t *testing.T) {
	p, _ := fixture(t)
	e := p.execution(context.Background())
	tenant := p.Store.TenantN(1)
	vol := "rs822rp1:import/carrel-t001-noble-cdcdcdcdcdcd.qcow2"
	p.Store.Put("images", "img2", 1, decode(string(encoded(imageRecord{ID: "img2", TenantN: 1, Name: "noble", Kind: "qcow2", SHA256: strings.Repeat("cd", 32), Size: 600 << 20, VirtualSize: 12 << 30, State: "ready", Volume: vol}))))
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAliceAliceAliceAliceAliceAliceAliceAlice"
	m := e.MachineSpec(tenant, D{"name": "vm1", "image": "tenant:noble", "ssh_keys": []any{key}}, false)
	if m["import_volume"] != vol || m["import_sha256"] != strings.Repeat("cd", 32) || integer(m["disk_gb"]) != 12 || m["image"] != "tenant:noble" {
		t.Fatal(m)
	}
	if f := attempt(func() {
		e.MachineSpec(tenant, D{"name": "vm2", "image": "tenant:noble", "disk_gb": 11, "ssh_keys": []any{key}}, false)
	}); f == nil {
		t.Fatal("a disk smaller than the image was accepted")
	}
	// An image without a virtual size (a fetcher that did not report it)
	// cannot size its disk.
	p.Store.Put("images", "img3", 1, decode(string(encoded(imageRecord{ID: "img3", TenantN: 1, Name: "nosize", Kind: "raw", SHA256: strings.Repeat("ef", 32), Size: 1 << 30, State: "ready", Volume: "rs822rp1:import/carrel-t001-nosize-efefefefefef.raw"}))))
	// A CT cannot boot a cloud image: said plainly.
	if f := attempt(func() {
		e.MachineSpec(tenant, D{"name": "ct1", "kind": "ct", "image": "tenant:noble", "ssh_keys": []any{key}}, false)
	}); f == nil || !strings.Contains(fmt.Sprint(f), "Only a VM boots a cloud image") {
		t.Fatal("CT accepted or unclear", f)
	}
	// The image cannot go while a creation uses it: queued, or importing.
	p.Store.Put("operations", "op1", 1, D{"id": "op1", "tenant_n": 1, "tool": "machine_create", "state": "queued", "args": D{"name": "q", "image": "tenant:noble"}})
	if r := p.Execute(context.Background(), "image_delete", D{"name": "noble", "confirm": "noble"}, person("alice", false)); r["ok"] != false {
		t.Fatal("deleted under a queued creation", r)
	}
	p.Store.Remove("operations", "op1")
	p.Store.Put("machines", 10109, 1, D{"vmid": 10109, "tenant_n": 1, "name": "q", "state": "provisioning", "import_volume": vol})
	if r := p.Execute(context.Background(), "image_delete", D{"name": "noble", "confirm": "noble"}, person("alice", false)); r["ok"] != false {
		t.Fatal("deleted under a creation", r)
	}
	p.Store.Remove("machines", 10109)
	for _, bad := range []string{"tenant:missing", "tenant:netinst", "tenant:nosize"} {
		if f := attempt(func() { e.MachineSpec(tenant, D{"name": "vm3", "image": bad, "ssh_keys": []any{key}}, false) }); f == nil {
			t.Fatal("accepted", bad)
		}
	}
}

func e2image(p *Platform, name string) (imageRecord, bool) {
	return p.execution(context.Background()).imageNamed(1, name)
}

// The disk a cloud image raises counts against the tenant's disk quota.
func TestACloudImageDiskCountsAgainstTheQuota(t *testing.T) {
	p, _ := fixture(t)
	vol := "rs822rp1:import/carrel-t001-big-cdcdcdcdcdcd.qcow2"
	p.Store.Put("images", "img9", 1, decode(string(encoded(imageRecord{ID: "img9", TenantN: 1, Name: "big", Kind: "qcow2", SHA256: strings.Repeat("cd", 32), Size: 1 << 30, VirtualSize: 500 << 30, State: "ready", Volume: vol}))))
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAliceAliceAliceAliceAliceAliceAliceAlice"
	r := p.Execute(context.Background(), "machine_create", D{"name": "big", "image": "tenant:big", "ssh_keys": []any{key}, "dry_run": true}, person("alice", false))
	if e := obj(r["error"]); e["code"] != "quota_exceeded" || e["dimension"] != "disk_gb" || num(e["used"]) != 500 {
		t.Fatal("a 500 GiB image fit a 100 GiB quota", r)
	}
}
