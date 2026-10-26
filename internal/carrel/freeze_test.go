package carrel

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// freezeSite is a site with a backup storage and one stopped machine whose
// adapter calls are listed in order.
func freezeSite(t *testing.T) (*Platform, *fakeBackend, *[]string) {
	t.Helper()
	p, b := fixture(t)
	p.Config["backup_storage"] = "pbs"
	seen := &[]string{}
	b.call = func(r D, target string) (any, error) {
		op := str(r["op"])
		if op == "action" {
			op += ":" + str(r["action"])
		}
		*seen = append(*seen, op)
		switch r["op"] {
		case "status":
			return D{"status": "stopped"}, nil
		case "freeze":
			return D{"volid": "pbs:backup/vm/10100/2026-10-26T00:00:00Z", "size": 1 << 30}, nil
		case "inventory":
			return baseInventory(), nil
		case "storage_usage":
			return []D{}, nil
		}
		return D{"state": "done"}, nil
	}
	seedMachine(p, "box", 10100)
	runQueue(p)
	return p, b, seen
}

func member(p *Platform, tool string, a D) D {
	return p.Execute(context.Background(), tool, a, person("alice", false))
}

// failure is the error of a refused operation.
func failure(r D) D {
	if op := obj(r["operation"]); op["error"] != nil {
		return obj(op["error"])
	}
	return obj(r["error"])
}

func frozenOps(seen []string, op string) int {
	n := 0
	for _, s := range seen {
		if s == op {
			n++
		}
	}
	return n
}

func TestFreezeRefusals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(p *Platform, b *fakeBackend)
		code  string
		text  string
	}{
		{"running", func(p *Platform, b *fakeBackend) {
			inner := b.call
			b.call = func(r D, target string) (any, error) {
				if r["op"] == "status" {
					return D{"status": "running"}, nil
				}
				return inner(r, target)
			}
		}, "conflict", "Shut the machine down"},
		{"snapshot", func(p *Platform, b *fakeBackend) {
			p.Store.Put("snapshots", "10100-s", 1, D{"id": "10100-s", "vmid": 10100, "name": "s", "disk_gb": 20})
		}, "conflict", "snapshots"},
		{"public ip", func(p *Platform, b *fakeBackend) {
			p.Store.Put("public_ips", "ip1", 1, D{"id": "ip1", "address": "140.113.1.1", "tenant_n": 1, "vmid": 10100})
		}, "conflict", "140.113.1.1"},
		{"special port", func(p *Platform, b *fakeBackend) {
			p.Store.Put("ports", "sp", 1, D{"id": "sp", "vmid": 10100, "special": true, "public_port": 25565, "proto": "tcp", "port": 25565, "ip": "10.200.1.10", "tenant_n": 1})
		}, "conflict", "25565/tcp"},
		{"special domain", func(p *Platform, b *fakeBackend) {
			p.Store.Put("domains", "d1", 1, D{"id": "d1", "vmid": 10100, "grant": "g1", "name": "app.winlab.tw", "tenant_n": 1})
		}, "conflict", "app.winlab.tw"},
		{"frozen quota", func(p *Platform, b *fakeBackend) {
			p.Store.Exec(`UPDATE tenants SET quota='{"frozen_gb":10}' WHERE n=1`)
		}, "quota_exceeded", "quota"},
		{"no backup storage", func(p *Platform, b *fakeBackend) { delete(p.Config, "backup_storage") }, "backend_unavailable", "not set up"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, b, seen := freezeSite(t)
			tc.setup(p, b)
			r := member(p, "machine_freeze", D{"machine": "box", "confirm": "box"})
			f := failure(r)
			if f["code"] != tc.code || !strings.Contains(strings.ToLower(str(f["message"])+string(encoded(f))), strings.ToLower(tc.text)) {
				t.Fatalf("want %s containing %q: %s", tc.code, tc.text, encoded(r))
			}
			if frozenOps(*seen, "freeze") != 0 || frozenOps(*seen, "action:delete") != 0 {
				t.Fatalf("a refused freeze reached the node: %v", *seen)
			}
			if p.Store.Get("machines", "10100") == nil || p.Store.Get("frozen", "10100") != nil {
				t.Fatal("a refused freeze changed the machine")
			}
		})
	}
}

func TestFailedOrUnverifiedBackupKeepsTheMachine(t *testing.T) {
	for name, reply := range map[string]func() (any, error){
		"failed":     func() (any, error) { return nil, errors.New("vzdump failed") },
		"unverified": func() (any, error) { return D{"volid": "", "size": 0}, nil },
	} {
		t.Run(name, func(t *testing.T) {
			p, b, seen := freezeSite(t)
			inner := b.call
			b.call = func(r D, target string) (any, error) {
				if r["op"] == "freeze" {
					*seen = append(*seen, "freeze")
					return reply()
				}
				return inner(r, target)
			}
			r := member(p, "machine_freeze", D{"machine": "box", "confirm": "box"})
			if failure(r)["code"] == nil {
				t.Fatalf("freeze succeeded: %s", encoded(r))
			}
			if frozenOps(*seen, "action:delete") != 0 || p.Store.Get("machines", "10100") == nil || p.Store.Get("frozen", "10100") != nil {
				t.Fatalf("the machine did not stay: %v", *seen)
			}
		})
	}
}

func TestFreezeAndThawRoundTrip(t *testing.T) {
	p, _, seen := freezeSite(t)
	before := obj(member(p, "quota_get", D{})["quota"])
	used := obj(before["used"])
	if num(used["vcpu"]) != 2 || num(used["machines"]) != 1 || num(used["disk_gb"]) != 20 || num(used["ips"]) != 1 || num(used["frozen_gb"]) != 0 {
		t.Fatal(encoded(used))
	}
	assertOK(t, member(p, "machine_freeze", D{"machine": "box", "confirm": "box"}))
	// The backup is verified before the machine goes.
	order := strings.Join(*seen, ",")
	if strings.Index(order, "freeze") > strings.Index(order, "action:delete") || frozenOps(*seen, "freeze") != 1 {
		t.Fatal(order)
	}
	used = obj(obj(member(p, "quota_get", D{})["quota"])["used"])
	for k, want := range map[string]float64{"vcpu": 0, "memory_mb": 0, "disk_gb": 0, "machines": 0, "ips": 1, "frozen_gb": 20} {
		if num(used[k]) != want {
			t.Fatalf("%s is %v after freeze: %s", k, used[k], encoded(used))
		}
	}
	listed := dicts(member(p, "machine_list", D{})["machines"])
	if len(listed) != 1 || listed[0]["name"] != "box" || listed[0]["state"] != "frozen" {
		t.Fatal(encoded(listed))
	}
	if f := failure(member(p, "machine_power", D{"machine": "box", "action": "start"})); f["code"] != "conflict" {
		t.Fatalf("a frozen machine was powered: %s", encoded(f))
	}
	if f := failure(member(p, "machine_create", D{"name": "box", "ssh_keys": []any{"ssh-ed25519 AAAA test"}})); f["code"] != "conflict" {
		t.Fatalf("the name of a frozen machine was reused: %s", encoded(f))
	}
	assertOK(t, member(p, "machine_thaw", D{"machine": "box"}))
	m := p.Store.Get("machines", "10100")
	if m == nil || m["name"] != "box" || m["ip"] != "10.200.1.10" || m["state"] != "stopped" || p.Store.Get("frozen", "10100") != nil {
		t.Fatal(encoded(m))
	}
	if frozenOps(*seen, "thaw") != 1 || frozenOps(*seen, "backup_remove") != 1 {
		t.Fatal(order)
	}
	after := obj(obj(member(p, "quota_get", D{})["quota"])["used"])
	for k, want := range map[string]float64{"vcpu": 2, "machines": 1, "disk_gb": 20, "ips": 1, "frozen_gb": 0} {
		if num(after[k]) != want {
			t.Fatalf("%s is %v after thaw: %s", k, after[k], encoded(after))
		}
	}
}

func TestThawChecksTheNormalQuota(t *testing.T) {
	p, _, seen := freezeSite(t)
	assertOK(t, member(p, "machine_freeze", D{"machine": "box", "confirm": "box"}))
	// Compute taken meanwhile leaves no room for the machine.
	p.Store.Exec(`UPDATE tenants SET quota='{"vcpu":1}' WHERE n=1`)
	r := member(p, "machine_thaw", D{"machine": "box"})
	f := failure(r)
	if f["code"] != "quota_exceeded" || f["dimension"] != "vcpu" || f["quota_after"] == nil {
		t.Fatal(encoded(r))
	}
	if frozenOps(*seen, "thaw") != 0 || p.Store.Get("frozen", "10100") == nil || p.Store.Get("machines", "10100") != nil {
		t.Fatal("a refused thaw changed the machine")
	}
}

func TestDeletingAFrozenMachineRemovesItsBackup(t *testing.T) {
	p, _, seen := freezeSite(t)
	assertOK(t, member(p, "machine_freeze", D{"machine": "box", "confirm": "box"}))
	if f := failure(member(p, "machine_delete", D{"machine": "box", "confirm": "wrong"})); f["code"] != "invalid" {
		t.Fatal(encoded(f))
	}
	assertOK(t, member(p, "machine_delete", D{"machine": "box", "confirm": "box"}))
	if frozenOps(*seen, "backup_remove") != 1 || p.Store.Get("frozen", "10100") != nil {
		t.Fatalf("%v", *seen)
	}
	used := obj(obj(member(p, "quota_get", D{})["quota"])["used"])
	if num(used["frozen_gb"]) != 0 || num(used["ips"]) != 0 {
		t.Fatal(encoded(used))
	}
}

func TestFrozenQuotaDefaultsToTheDiskQuota(t *testing.T) {
	if DefaultQuota["frozen_gb"] != DefaultQuota["disk_gb"] {
		t.Fatalf("frozen_gb %v, disk_gb %v", DefaultQuota["frozen_gb"], DefaultQuota["disk_gb"])
	}
}

func TestFreezeReleaseListComesFromTheConfig(t *testing.T) {
	p, _, _ := freezeSite(t)
	p.Store.Put("public_ips", "ip1", 1, D{"id": "ip1", "address": "140.113.1.1", "tenant_n": 1, "vmid": 10100})
	p.Config["freeze_release"] = []any{"nothing"}
	if f := failure(member(p, "machine_freeze", D{"machine": "box", "confirm": "box", "dry_run": true})); f["code"] != "invalid" {
		t.Fatalf("an unknown resource kind was accepted: %s", encoded(f))
	}
	// A public IP is not on this site's list, so the machine freezes.
	p.Config["freeze_release"] = []any{"special_ports"}
	assertOK(t, member(p, "machine_freeze", D{"machine": "box", "confirm": "box"}))
}
