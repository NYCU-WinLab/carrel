package carrel

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

func TestDefaultSelectionAcrossCreateAndDeployment(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args, want D
	}{
		{"minimal", D{}, D{"image": "debian-13-minimal", "cpu": 1, "memory_mb": 1024, "disk_gb": 10, "swap_mb": 1024}},
		{"development", D{"image": "debian-13"}, D{"image": "debian-13", "cpu": 2, "memory_mb": 2048, "disk_gb": 20, "swap_mb": 1024}},
		{"ubuntu", D{"image": "ubuntu-24.04"}, D{"image": "ubuntu-24.04", "cpu": 2, "memory_mb": 2048, "disk_gb": 20, "swap_mb": 1024}},
		{"ct", D{"kind": "ct"}, D{"image": "debian-13", "cpu": 1, "memory_mb": 1024, "disk_gb": 10, "swap_mb": 0}},
		{"overrides", D{"size": "small", "memory_mb": 3072, "swap_mb": 0}, D{"image": "debian-13-minimal", "cpu": 2, "memory_mb": 3072, "disk_gb": 20, "swap_mb": 0}},
	} {
		for _, tool := range []string{"machine_create", "deployment_plan", "deployment_apply"} {
			t.Run(tc.name+"/"+tool, func(t *testing.T) {
				p, _ := fixture(t)
				machine := merge(D{"name": "default-check"}, tc.args)
				args := merge(machine, D{"dry_run": true})
				if tool != "machine_create" {
					args = D{"machines": []any{machine}}
				}
				if tool == "deployment_apply" {
					args["dry_run"] = true
				}
				r := NewApp(p, nil).Call(context.Background(), tool, args, person("alice", false))
				assertOK(t, r)
				var got D
				if tool == "machine_create" {
					got = obj(r["machine"])
				} else {
					got = dicts(r["machines"])[0]
				}
				if !equal(pick(got, "image", "cpu", "memory_mb", "disk_gb", "swap_mb"), tc.want) {
					t.Fatalf("unexpected default: %s", encoded(r))
				}
				if len(p.Store.Objects("machines")) != 0 {
					t.Fatal("preview allocated a machine")
				}
			})
		}
	}
}

func TestEightMachinesFitButTotalsAndPortsStillApply(t *testing.T) {
	p, _ := fixture(t)
	ctx, who := context.Background(), person("alice", false)
	app := NewApp(p, nil)
	machines := []D{}
	for i := 0; i < 8; i++ {
		machines = append(machines, D{"name": fmt.Sprintf("tiny-%d", i)})
	}
	r := app.Call(ctx, "deployment_plan", D{"machines": arr(machines)}, who)
	assertOK(t, r)
	used := obj(obj(r["quota_after"])["used"])
	if !equal(pick(used, "vcpu", "memory_mb", "disk_gb", "machines", "ips", "public_ports"), D{"vcpu": 8, "memory_mb": 8192, "disk_gb": 80, "machines": 8, "ips": 8, "public_ports": 8}) {
		t.Fatalf("wrong aggregate: %s", encoded(r))
	}
	assertCode(t, app.Call(ctx, "deployment_plan", D{"machines": arr(append(machines, D{"name": "ninth"}))}, who), "quota_exceeded")
	machines[0]["cpu"] = 2
	assertCode(t, app.Call(ctx, "deployment_plan", D{"machines": arr(machines)}, who), "quota_exceeded")
	delete(machines[0], "cpu")
	e := p.execution(ctx)
	tenant := p.Store.TenantN(1)
	ports := map[int]bool{}
	for _, spec := range machines {
		m, grant := e.AllocateMachine(tenant, e.MachineSpec(tenant, merge(spec, D{"ssh_keys": []any{"ssh-ed25519 AAAA test"}}), true))
		port := integer(grant["public_port"])
		if ports[port] {
			t.Fatal("duplicate SSH port")
		}
		ports[port] = true
		m["state"] = "stopped"
		e.Put("machines", m["vmid"], 1, m)
	}
	if num(obj(e.Quota(tenant)["used"])["vcpu"]) != 8 {
		t.Fatal("stopped reservations lost")
	}
	for _, port := range []int{8000, 8001} {
		e.NetworkAction("port_open", D{"machine": "tiny-0", "port": port, "proto": "tcp"}, tenant)
	}
	assertCode(t, app.Call(ctx, "port_open", D{"machine": "tiny-0", "port": 8002, "proto": "tcp", "dry_run": true}, who), "quota_exceeded")
}

func TestCountQuotaMigrationPreservesOverridesAndRunsOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"default", "high", "low", "explicit", "temporary"} {
		tenant := s.Register("user:"+name, name)
		quota := merge(DefaultQuota, D{"machines": 4, "ips": 4})
		if name == "high" {
			quota["machines"], quota["ips"] = 16, 16
		}
		if name == "low" {
			quota["machines"], quota["ips"] = 2, 2
		}
		s.Exec("UPDATE tenants SET quota=? WHERE n=?", string(encoded(quota)), tenant["n"])
		if name == "explicit" {
			s.Log("admin", tenant["n"], "quota_set", D{"dimension": "machines", "amount": 4}, "ok")
		}
		if name == "temporary" {
			s.Put("requests", "grant", i+1, D{"kind": "quota", "dimension": "machines", "status": "approved", "amount": 4, "previous_limit": 2})
		}
	}
	s.Exec("DELETE FROM migrations")
	s.DB.Close()
	s, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]D{"default": {"machines": 8, "ips": 8}, "high": {"machines": 16, "ips": 16}, "low": {"machines": 2, "ips": 2}, "explicit": {"machines": 4, "ips": 8}, "temporary": {"machines": 4, "ips": 8}} {
		if !equal(pick(obj(s.Tenant("user:" + name)["quota"]), "machines", "ips"), want) {
			t.Fatalf("changed custom quota for %s", name)
		}
	}
	if len(s.Rows("SELECT id FROM audit WHERE tool='quota_defaults_migrate'")) != 3 {
		t.Fatal("missing migration audit")
	}
	s.Exec("UPDATE tenants SET quota=? WHERE subject='user:default'", string(encoded(merge(DefaultQuota, D{"machines": 4}))))
	s.DB.Close()
	s, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	if num(obj(s.Tenant("user:default")["quota"])["machines"]) != 4 {
		t.Fatal("migration repeated")
	}
	if num(obj(s.Register("user:new", "new")["quota"])["machines"]) != 8 {
		t.Fatal("new tenant has old default")
	}
}
