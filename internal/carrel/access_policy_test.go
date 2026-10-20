package carrel

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestExistingPolicyPreviewApplyAndRollback(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		t.Run(str(rollback), func(t *testing.T) {
			p, b := fixture(t)
			seedMachine(p, "app", 10100)
			original := seedMachine(p, "db", 10101)
			args := D{"access": []D{{"machine": "db", "network_access": "restricted"}}, "connections": []D{{"from": "app", "to": "db", "port": 5432}}}
			app, who, ctx := NewApp(p, nil), person("alice", false), context.Background()
			plan := app.Call(ctx, "deployment_plan", obj(copyValue(args)), who)
			assertOK(t, plan)
			if plan["ready_to_apply"] != false || len(arr(plan["requirements"])) != 1 || p.Store.Get("machines", "10101")["network_access"] != original["network_access"] {
				t.Fatal("preview did not preserve policy and require confirmation")
			}
			dicts(args["access"])[0]["confirm"] = "db"
			if rollback {
				calls := 0
				b.call = func(D, string) (any, error) {
					calls++
					if calls == 1 {
						return nil, errors.New("reconcile failed")
					}
					return D{}, nil
				}
			}
			runQueue(p)
			result := app.Call(ctx, "deployment_apply", obj(copyValue(args)), who)
			op := obj(result["operation"])
			m := p.Store.Get("machines", "10101")
			if !equal(machineIdentity(m), machineIdentity(original)) || len(p.Store.Objects("machines")) != 2 {
				t.Fatal("policy changed allocation")
			}
			if rollback {
				if op["state"] != "rolled_back" || textAt(m, "network_access", "tenant") != "tenant" || len(p.Store.Objects("peers")) != 0 {
					t.Fatalf("rollback did not restore original ingress: %s", encoded(result))
				}
			} else {
				if op["state"] != "succeeded" || m["network_access"] != "restricted" || len(p.Store.Objects("peers")) != 1 || len(arr(obj(op["result"])["updated_machines"])) != 2 {
					t.Fatalf("incomplete policy result: %s", encoded(result))
				}
				if b.count("create") != 0 || b.count("action") != 0 || b.count("inventory") != 0 {
					t.Fatal("network intent triggered compute work")
				}
			}
		})
	}
}

func TestPolicyRestrictsAMachineWithPrivateNICsButNotForeignMachines(t *testing.T) {
	p, _ := fixture(t)
	m := seedMachine(p, "db", 10100)
	m["nics"] = []D{{"index": 1, "network": "private"}}
	p.Store.Put("machines", 10100, 1, m)
	args := D{"access": []D{{"machine": "db", "network_access": "restricted", "confirm": "db"}}}
	app, ctx := NewApp(p, nil), context.Background()
	// Restricted filters the primary NIC only; the private NIC stays (issue #75).
	r := app.Call(ctx, "deployment_plan", obj(copyValue(args)), person("alice", false))
	assertOK(t, r)
	if impact := str(dicts(r["access"])[0]["impact"]); !strings.Contains(impact, "private NICs stay unfiltered") {
		t.Fatal(impact)
	}
	assertCode(t, app.Call(ctx, "deployment_plan", obj(copyValue(args)), person("bob", false)), "not_found")
}

func TestARestrictedMachineTakesAPrivateNIC(t *testing.T) {
	p, _ := fixture(t)
	m := seedMachine(p, "db", 10100)
	m["network_access"] = "restricted"
	e := p.execution(context.Background())
	nic := e.NICSpec(m, D{"id": "p00101", "mode": "raw_l2"}, 1)
	if nic["network"] != "p00101" {
		t.Fatal(nic)
	}
	if access := obj(e.PublicMachine(m, nil)["access"]); access["inbound"] != "restricted" || access["private_nics"] != "unfiltered_experiment_networks" {
		t.Fatal(access)
	}
}

func TestPolicyRollbackDoesNotOverwriteNewerIntent(t *testing.T) {
	for _, replaced := range []bool{false, true} {
		t.Run(str(replaced), func(t *testing.T) {
			p, b := fixture(t)
			m := seedMachine(p, "db", 10100)
			receipt := D{"vmid": 10100, "identity": machineIdentity(m), "before": "tenant", "after": "restricted"}
			m["network_access"], m["access_operation"] = "restricted", "newer"
			if replaced {
				m["allocation_id"] = "replacement"
				m["access_operation"] = "old"
			}
			p.Store.Put("machines", 10100, 1, m)
			e := p.execution(context.Background())
			e.Op = D{"id": "old", "deployment": D{"access": []D{receipt}}}
			if len(e.RestorePolicy()) != 0 || !equal(m, p.Store.Get("machines", "10100")) || b.count("reconcile") != 0 {
				t.Fatal("rollback overwrote newer policy/allocation")
			}
		})
	}
}

func TestOneDeploymentRestrictsAMachineAndAttachesAPrivateNIC(t *testing.T) {
	p, b := fixture(t)
	for i, name := range []string{"app", "db"} {
		m := seedMachine(p, name, 10100+i)
		m["state"], m["power_state"], m["ssh_ready"] = "stopped", "stopped", false
		p.Store.Put("machines", 10100+i, 1, m)
	}
	net := p.execution(context.Background()).NetworkSpec(p.Store.TenantN(1), D{"name": "lab"}, nil)
	p.Store.Put("networks", net["id"], 1, net)
	b.call = func(r D, _ string) (any, error) {
		if r["op"] == "status" {
			return D{"power_state": "stopped"}, nil
		}
		return D{}, nil
	}
	runQueue(p)
	r := p.Execute(context.Background(), "deployment_apply", D{
		"attachments": []D{{"machine": "db", "network": "lab"}},
		"access":      []D{{"machine": "db", "network_access": "restricted", "confirm": "db"}},
		"connections": []D{{"from": "app", "to": "db", "port": 5432, "protocol": "tcp"}},
	}, person("alice", false))
	if op := obj(r["operation"]); op["state"] != "succeeded" {
		t.Fatal(encoded(r))
	}
	db := p.Store.Get("machines", "10101")
	if db["network_access"] != "restricted" || len(arr(db["nics"])) != 1 || len(p.Store.Objects("peers", 1)) != 1 {
		t.Fatal(encoded(db))
	}
}
