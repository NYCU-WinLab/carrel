package carrel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
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
			return D{"volid": "pbs:backup/vm/10100/2026-10-26T00:00:00Z", "size": 1 << 30, "verification": "ok", "note": "carrel-freeze test"}, nil
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
		// A backup with no verification result is no better than a failed one.
		"unconfirmed": func() (any, error) {
			return D{"volid": "pbs:backup/vm/10100/2026-10-26T00:00:00Z", "size": 1 << 30, "note": "carrel-freeze x"}, nil
		},
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

// intercept answers an adapter request itself or leaves it to the site's fake.
func intercept(b *fakeBackend, answer func(r D) (any, error, bool)) {
	inner := b.call
	b.call = func(r D, target string) (any, error) {
		if v, err, ok := answer(r); ok {
			return v, err
		}
		return inner(r, target)
	}
}

func TestRetriedFreezeKeepsItsBackupIdentity(t *testing.T) {
	p, b, seen := freezeSite(t)
	ids, failed := []any{}, false
	intercept(b, func(r D) (any, error, bool) {
		if r["op"] != "freeze" {
			return nil, nil, false
		}
		ids = append(ids, r["freeze_id"])
		*seen = append(*seen, "freeze")
		if !failed {
			failed = true
			return nil, errors.New("ssh dropped after the backup"), true
		}
		return nil, nil, false
	})
	r := member(p, "machine_freeze", D{"machine": "box", "confirm": "box"})
	if failure(r)["code"] == nil || p.Store.Get("machines", "10100") == nil || frozenOps(*seen, "action:delete") != 0 {
		t.Fatalf("the first attempt did not leave the machine: %s", encoded(r))
	}
	assertOK(t, member(p, "operation_retry", D{"id": opOf(r)}))
	if len(ids) != 2 || ids[0] != ids[1] || ids[0] != opOf(r) || p.Store.Get("frozen", "10100") == nil {
		t.Fatalf("ids %v: a retry must ask for the same backup, which the node keeps only while the machine is unchanged", ids)
	}
}

func TestMachineThatRanDuringTheBackupIsKept(t *testing.T) {
	p, b, seen := freezeSite(t)
	started := false
	intercept(b, func(r D) (any, error, bool) {
		switch r["op"] {
		case "freeze":
			// Someone started the machine while vzdump was running.
			started = true
		case "status":
			if started {
				return D{"status": "running"}, nil, true
			}
		}
		return nil, nil, false
	})
	r := member(p, "machine_freeze", D{"machine": "box", "confirm": "box"})
	if failure(r)["code"] != "conflict" || p.Store.Get("machines", "10100") == nil || p.Store.Get("frozen", "10100") != nil {
		t.Fatalf("a machine that ran was frozen: %s", encoded(r))
	}
	if frozenOps(*seen, "action:delete") != 0 || frozenOps(*seen, "backup_remove") != 1 {
		t.Fatalf("the stale backup stayed or the machine went: %v", *seen)
	}
}

func TestFreezeAndThawLeaveTheWriterLockFree(t *testing.T) {
	p, b, _ := freezeSite(t)
	free := map[string]bool{}
	intercept(b, func(r D) (any, error, bool) {
		if op := str(r["op"]); op == "freeze" || op == "thaw" {
			locked := !p.writer.TryLock()
			if !locked {
				p.writer.Unlock()
			}
			free[op] = !locked
		}
		return nil, nil, false
	})
	assertOK(t, member(p, "machine_freeze", D{"machine": "box", "confirm": "box"}))
	assertOK(t, member(p, "machine_thaw", D{"machine": "box"}))
	if !free["freeze"] || !free["thaw"] {
		t.Fatalf("the writer lock was held during a backup or a restore: %v", free)
	}
}

func TestInterruptedThawIsFinishedOnTheSameNode(t *testing.T) {
	p, b, seen := freezeSite(t)
	assertOK(t, member(p, "machine_freeze", D{"machine": "box", "confirm": "box"}))
	nodes, failed := []any{}, false
	intercept(b, func(r D) (any, error, bool) {
		if r["op"] == "thaw" && r["discard"] == nil {
			nodes = append(nodes, obj(r["machine"])["node"])
			if !failed {
				failed = true
				return nil, errors.New("connection lost during the restore"), true
			}
		}
		return nil, nil, false
	})
	r := member(p, "machine_thaw", D{"machine": "box"})
	f := p.Store.Get("frozen", "10100")
	if failure(r)["code"] == nil || f == nil || f["thaw_node"] == nil || p.Store.Get("machines", "10100") != nil {
		t.Fatalf("an interrupted thaw must keep the frozen row and say where it restores: %s", encoded(r))
	}
	if frozenOps(*seen, "backup_remove") != 0 {
		t.Fatal("the backup went before the machine was recorded")
	}
	assertOK(t, member(p, "operation_retry", D{"id": opOf(r)}))
	if len(nodes) != 2 || nodes[0] != nodes[1] || p.Store.Get("machines", "10100") == nil || p.Store.Get("frozen", "10100") != nil {
		t.Fatalf("nodes %v", nodes)
	}
}

func TestBackupOfAThawedMachineGoesOnlyAfterItIsRecorded(t *testing.T) {
	p, b, seen := freezeSite(t)
	assertOK(t, member(p, "machine_freeze", D{"machine": "box", "confirm": "box"}))
	failed, recorded := false, []bool{}
	intercept(b, func(r D) (any, error, bool) {
		if r["op"] == "backup_remove" {
			recorded = append(recorded, p.Store.Get("machines", "10100") != nil && p.Store.Get("frozen", "10100") == nil)
			if !failed {
				failed = true
				return nil, errors.New("pbs unreachable"), true
			}
		}
		return nil, nil, false
	})
	r := member(p, "machine_thaw", D{"machine": "box"})
	if failure(r)["code"] == nil || p.Store.Get("machines", "10100") == nil {
		t.Fatalf("the restored machine must stay when only the cleanup failed: %s", encoded(r))
	}
	if listed := dicts(member(p, "machine_list", D{})["machines"]); len(listed) != 1 || listed[0]["state"] != "stopped" || listed[0]["thaw_backup"] != nil {
		t.Fatal(encoded(listed))
	}
	assertOK(t, member(p, "operation_retry", D{"id": opOf(r)}))
	if frozenOps(*seen, "thaw") != 1 || len(recorded) != 2 || !recorded[0] || !recorded[1] || p.Store.Get("machines", "10100")["thaw_backup"] != nil {
		t.Fatalf("recorded %v, %v", recorded, *seen)
	}
}

func TestDeletingAfterAPartialThawDiscardsWhatItRestored(t *testing.T) {
	p, b, seen := freezeSite(t)
	assertOK(t, member(p, "machine_freeze", D{"machine": "box", "confirm": "box"}))
	order := []string{}
	intercept(b, func(r D) (any, error, bool) {
		switch {
		case r["op"] == "thaw" && r["discard"] == nil:
			return nil, errors.New("killed during the restore"), true
		case r["op"] == "thaw":
			order = append(order, "discard")
		case r["op"] == "backup_remove":
			order = append(order, "backup_remove")
		}
		return nil, nil, false
	})
	if failure(member(p, "machine_thaw", D{"machine": "box"}))["code"] == nil {
		t.Fatal("the thaw did not fail")
	}
	assertOK(t, member(p, "machine_delete", D{"machine": "box", "confirm": "box"}))
	if strings.Join(order, ",") != "discard,backup_remove" || p.Store.Get("frozen", "10100") != nil {
		t.Fatalf("%v %v", order, *seen)
	}
}

func opOf(r D) string { return str(obj(r["operation"])["id"]) }

func TestPowerDuringAFreezeIsHeldUntilTheMachineIsGone(t *testing.T) {
	p, b, seen := freezeSite(t)
	var started string
	intercept(b, func(r D) (any, error, bool) {
		if r["op"] == "freeze" {
			// A member starts the machine while the backup is being made.
			started = opOf(member(p, "machine_power", D{"machine": "box", "action": "start", "wait_seconds": 0}))
			time.Sleep(300 * time.Millisecond)
		}
		return nil, nil, false
	})
	assertOK(t, member(p, "machine_freeze", D{"machine": "box", "confirm": "box"}))
	if frozenOps(*seen, "action:start") != 0 {
		t.Fatalf("the machine started while it was being frozen: %v", *seen)
	}
	awaitState(t, p, started, "failed")
	if frozenOps(*seen, "action:start") != 0 || p.Store.Get("frozen", "10100") == nil {
		t.Fatalf("%v", *seen)
	}
}

// A freeze that stops after its frozen row is written must finish on
// recovery or retry without touching the backup that row names.
func TestAFreezeStoppedAfterItsRowIsWrittenKeepsTheBackup(t *testing.T) {
	for _, how := range []string{"recover", "retry"} {
		t.Run(how, func(t *testing.T) {
			p, b, seen := freezeSite(t)
			failed := false
			intercept(b, func(r D) (any, error, bool) {
				if r["op"] == "action" && r["action"] == "delete" && !failed {
					failed = true
					return nil, errors.New("carrel stopped before the machine was deleted"), true
				}
				return nil, nil, false
			})
			r := member(p, "machine_freeze", D{"machine": "box", "confirm": "box"})
			id := opOf(r)
			if failure(r)["code"] == nil || p.Store.Get("frozen", "10100") == nil || p.Store.Get("machines", "10100")["state"] != "deleting" {
				t.Fatalf("setup: %s", encoded(r))
			}
			if how == "recover" {
				op := p.Store.Get("operations", id)
				op["state"], op["phase"] = "running", "waiting_for_guest"
				op["prepared_result"] = D{"machine": D{"name": "box", "state": "freezing"}}
				p.Operations.Save(op)
				p.Operations.Recover()
				awaitState(t, p, id, "succeeded")
			} else {
				assertOK(t, member(p, "operation_retry", D{"id": id}))
			}
			if frozenOps(*seen, "backup_remove") != 0 || p.Store.Get("frozen", "10100") == nil || p.Store.Get("machines", "10100") != nil {
				t.Fatalf("the backup or the row was lost: %v", *seen)
			}
		})
	}
}

func TestDeletingAThawedMachineWhoseBackupRemainedRemovesTheBackup(t *testing.T) {
	p, b, seen := freezeSite(t)
	assertOK(t, member(p, "machine_freeze", D{"machine": "box", "confirm": "box"}))
	failed := false
	intercept(b, func(r D) (any, error, bool) {
		if r["op"] == "backup_remove" && !failed {
			failed = true
			return nil, errors.New("pbs unreachable"), true
		}
		return nil, nil, false
	})
	if failure(member(p, "machine_thaw", D{"machine": "box"}))["code"] == nil {
		t.Fatal("the cleanup did not fail")
	}
	before := frozenOps(*seen, "backup_remove")
	assertOK(t, member(p, "machine_delete", D{"machine": "box", "confirm": "box"}))
	if frozenOps(*seen, "backup_remove") != before+1 || p.Store.Get("machines", "10100") != nil {
		t.Fatalf("the backup stayed: %v", *seen)
	}
}

// A delete of a machine whose thaw is restoring it waits for the thaw
// (CheckBusy), so the restore is never cut off under it (#192, item 1).
func TestDeleteWaitsForAThawInProgress(t *testing.T) {
	p, b, seen := freezeSite(t)
	assertOK(t, member(p, "machine_freeze", D{"machine": "box", "confirm": "box"}))
	var deleted D
	intercept(b, func(r D) (any, error, bool) {
		if r["op"] == "thaw" && r["discard"] == nil {
			deleted = member(p, "machine_delete", D{"machine": "box", "confirm": "box", "wait_seconds": 0})
			time.Sleep(300 * time.Millisecond)
		}
		return nil, nil, false
	})
	assertOK(t, member(p, "machine_thaw", D{"machine": "box"}))
	assertOK(t, deleted)
	if frozenOps(*seen, "thaw") != 1 {
		t.Fatalf("a discard ran under the thaw: %v", *seen)
	}
	awaitState(t, p, opOf(deleted), "succeeded")
	if p.Store.Get("machines", "10100") != nil || p.Store.Get("frozen", "10100") != nil {
		t.Fatal("the machine survived its delete")
	}
}

// A resize during a freeze waits for the freeze and then finds no live
// machine, so the frozen row keeps the size the backup holds (#192, item 2).
func TestResizeDuringAFreezeIsHeld(t *testing.T) {
	p, b, seen := freezeSite(t)
	var resized D
	intercept(b, func(r D) (any, error, bool) {
		if r["op"] == "freeze" {
			resized = member(p, "machine_resize", D{"machine": "box", "disk_gb": 40, "wait_seconds": 0})
			time.Sleep(300 * time.Millisecond)
		}
		return nil, nil, false
	})
	assertOK(t, member(p, "machine_freeze", D{"machine": "box", "confirm": "box"}))
	if frozenOps(*seen, "action:resize") != 0 {
		t.Fatalf("the machine was resized while frozen: %v", *seen)
	}
	awaitState(t, p, opOf(resized), "failed")
	if f := p.Store.Get("frozen", "10100"); f == nil || num(f["disk_gb"]) == 40 {
		t.Fatalf("frozen row: %s", encoded(f))
	}
}

func TestFreezeRespectsTheSiteWideCap(t *testing.T) {
	p, _, _ := freezeSite(t)
	p.Config["frozen_total_gb"] = 5
	r := member(p, "machine_freeze", D{"machine": "box", "confirm": "box"})
	if failure(r)["code"] != "quota_exceeded" {
		t.Fatalf("freeze over the cap: %s", encoded(r))
	}
	p.Config["frozen_total_gb"] = 100
	assertOK(t, member(p, "machine_freeze", D{"machine": "box", "confirm": "box"}))
}

// reconcile_run sweeps freeze backups that no record names, and names the
// ones that must stay (#192).
func TestReconcileRunSweepsOrphanedBackups(t *testing.T) {
	p, b, _ := freezeSite(t)
	assertOK(t, member(p, "machine_freeze", D{"machine": "box", "confirm": "box"}))
	var sweep D
	intercept(b, func(r D) (any, error, bool) {
		if r["op"] == "backup_sweep" {
			sweep = r
			return D{"orphans": []string{"pbs:backup/vm/10200/old"}, "removed": []string{"pbs:backup/vm/10200/old"}}, nil, true
		}
		return nil, nil, false
	})
	r := p.Execute(context.Background(), "reconcile_run", D{}, person("alice", true))
	assertOK(t, r)
	result := obj(awaitState(t, p, opOf(r), "succeeded")["result"])
	if sweep == nil || sweep["storage"] != "pbs" || !contains(arr(sweep["keep"]), "carrel-freeze test") || !contains(arr(sweep["keep_volids"]), "pbs:backup/vm/10100/2026-10-26T00:00:00Z") || len(arr(obj(result["backups_swept"])["removed"])) != 1 {
		t.Fatalf("sweep %s result %s", encoded(sweep), encoded(result))
	}
}

// A backup server that does not answer the sweep does not fail the
// reconcile that ran before it (#192 review).
func TestReconcileRunSurvivesASweepFailure(t *testing.T) {
	p, b, _ := freezeSite(t)
	intercept(b, func(r D) (any, error, bool) {
		if r["op"] == "backup_sweep" {
			return nil, errors.New("pbs unreachable"), true
		}
		return nil, nil, false
	})
	r := p.Execute(context.Background(), "reconcile_run", D{}, person("alice", true))
	assertOK(t, r)
	result := obj(awaitState(t, p, opOf(r), "succeeded")["result"])
	if result["result"] == nil || obj(result["backups_swept"])["error"] == nil {
		t.Fatalf("result %s", encoded(result))
	}
}
