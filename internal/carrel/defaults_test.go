package carrel

import (
	"context"
	"fmt"
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
		for _, tool := range []string{"machine_create", "deployment_plan"} {
			t.Run(tc.name+"/"+tool, func(t *testing.T) {
				p, _ := fixture(t)
				machine := merge(D{"name": "default-check"}, tc.args)
				args := merge(machine, D{"dry_run": true})
				if tool != "machine_create" {
					args = D{"machines": []any{machine}}
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
