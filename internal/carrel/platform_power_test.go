package carrel

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// powerFixture seeds unmanaged VMs whose power the fake node tracks, so a
// start returns them to ready without a guest report.
func powerFixture(t *testing.T, vmids ...int) (*Platform, map[int]string, *sync.Mutex) {
	t.Helper()
	p, b := fixture(t)
	power := map[int]string{}
	mu := &sync.Mutex{}
	for i, vmid := range vmids {
		m := seedMachine(p, fmt.Sprintf("m%d", i), vmid)
		m["guest_management"] = 0
		p.Store.Put("machines", vmid, 1, m)
		power[vmid] = "running"
	}
	b.call = func(r D, _ string) (any, error) {
		mu.Lock()
		defer mu.Unlock()
		vmid := integer(obj(r["machine"])["vmid"])
		switch r["op"] {
		case "inventory":
			return baseInventory(), nil
		case "status":
			if power[vmid] == "unknown" {
				return nil, fmt.Errorf("node does not answer")
			}
			if power[vmid] == "stuck" {
				return D{"status": "running"}, nil
			}
			return D{"status": power[vmid]}, nil
		case "action":
			if power[vmid] == "stuck" {
				return D{"status": "running"}, nil
			}
			power[vmid] = map[string]string{"shutdown": "stopped", "start": "running"}[str(r["action"])]
			return D{"status": power[vmid]}, nil
		case "platform_check":
			return D{"repaired": []any{}, "problems": []any{}}, nil
		}
		return D{"status": "running"}, nil
	}
	runQueue(p)
	return p, power, mu
}

func platformRun(t *testing.T, p *Platform, action string, who D) D {
	t.Helper()
	ctx := context.Background()
	dry := p.Execute(ctx, "platform_power", D{"action": action, "dry_run": true}, who)
	assertOK(t, dry)
	r := p.Execute(ctx, "platform_power", D{"action": action, "confirm": dry["confirm"]}, who)
	assertOK(t, r)
	op := obj(r["operation"])
	if op["state"] != "succeeded" {
		op = awaitStateWithin(t, p, str(op["id"]), "succeeded", 10*time.Second)
	}
	return obj(op["result"])
}

func restoreList(p *Platform) []int {
	out := []int{}
	for _, r := range dicts(obj(p.Store.SiteGet("platform", "power"))["restore"]) {
		out = append(out, integer(r["vmid"]))
	}
	return out
}

func TestPlatformPowerShutdownAndStartRestoreTheSameMachines(t *testing.T) {
	p, power, mu := powerFixture(t, 10100, 10101, 10102)
	admin := person("alice", true)
	if r := platformRun(t, p, "shutdown", admin); len(arr(r["done"])) != 3 || !boolean(r["complete"]) {
		t.Fatalf("shutdown: %s", encoded(r))
	}
	if !equal(restoreList(p), []int{10100, 10101, 10102}) {
		t.Fatalf("restore list: %v", restoreList(p))
	}
	// The owner starts one machine on their own: the platform start leaves it.
	assertOK(t, p.Execute(context.Background(), "machine_power", D{"machine": "m1", "action": "start"}, person("alice", false)))
	if !equal(restoreList(p), []int{10100, 10102}) {
		t.Fatalf("owner start kept the machine listed: %v", restoreList(p))
	}
	r := platformRun(t, p, "start", admin)
	if len(arr(r["done"])) != 2 || r["nodes"] == nil {
		t.Fatalf("start: %s", encoded(r))
	}
	mu.Lock()
	defer mu.Unlock()
	for vmid, state := range power {
		if state != "running" {
			t.Fatalf("%d is %s", vmid, state)
		}
		if m := p.Store.Get("machines", fmt.Sprint(vmid)); m["state"] != "ready" {
			t.Fatalf("%d ended %s", vmid, m["state"])
		}
	}
	if s := obj(p.Store.SiteGet("platform", "power")); s["state"] != "on" || len(dicts(s["restore"])) != 0 {
		t.Fatalf("record after start: %s", encoded(s))
	}
}

func TestPlatformShutdownAgainKeepsEarlierMachinesOnTheList(t *testing.T) {
	p, power, mu := powerFixture(t, 10100, 10101)
	admin := person("alice", true)
	mu.Lock()
	power[10101] = "stuck"
	mu.Unlock()
	if r := platformRun(t, p, "shutdown", admin); boolean(r["complete"]) || len(arr(r["failed"])) != 1 {
		t.Fatalf("first shutdown: %s", encoded(r))
	}
	mu.Lock()
	power[10101] = "running"
	mu.Unlock()
	platformRun(t, p, "shutdown", admin)
	if !equal(restoreList(p), []int{10100, 10101}) {
		t.Fatalf("second shutdown lost the first batch: %v", restoreList(p))
	}
}

func TestPlatformStartSkipsAReplacedMachine(t *testing.T) {
	p, _, _ := powerFixture(t, 10100)
	admin := person("alice", true)
	platformRun(t, p, "shutdown", admin)
	m := p.Store.Get("machines", "10100")
	m["allocation_id"] = "allocation-new"
	p.Store.Put("machines", 10100, 1, m)
	dry := p.Execute(context.Background(), "platform_power", D{"action": "start", "dry_run": true}, admin)
	if integer(dry["count"]) != 0 {
		t.Fatalf("a new machine on the old VMID was listed: %s", encoded(dry))
	}
}

func TestPlatformShutdownRefusesWhilePowerIsUnknown(t *testing.T) {
	p, power, mu := powerFixture(t, 10100, 10101)
	admin := person("alice", true)
	mu.Lock()
	power[10101] = "unknown"
	mu.Unlock()
	dry := p.Execute(context.Background(), "platform_power", D{"action": "shutdown", "dry_run": true}, admin)
	if dry["confirm"] != nil || len(arr(dry["unknown"])) != 1 {
		t.Fatalf("dry run issued a code: %s", encoded(dry))
	}
}

func TestPlatformConfirmCodeIsSingleUseAndPerAdmin(t *testing.T) {
	p, _, _ := powerFixture(t, 10100)
	ctx, admin := context.Background(), person("alice", true)
	dry := p.Execute(ctx, "platform_power", D{"action": "shutdown", "dry_run": true}, admin)
	other := p.Execute(ctx, "platform_power", D{"action": "shutdown", "confirm": dry["confirm"]}, person("bob", true))
	refused(t, p, other, "another admin spent the code")
	again := p.Execute(ctx, "platform_power", D{"action": "shutdown", "confirm": dry["confirm"]}, admin)
	refused(t, p, again, "a spent code worked")
	dry = p.Execute(ctx, "platform_power", D{"action": "shutdown", "dry_run": true}, admin)
	p.platformMu.Lock()
	p.platformCodes[str(dry["confirm"])]["expires"] = now() - 1
	p.platformMu.Unlock()
	late := p.Execute(ctx, "platform_power", D{"action": "shutdown", "confirm": dry["confirm"]}, admin)
	refused(t, p, late, "an expired code worked")
}

func TestPlatformStartWaitsForManagedGuests(t *testing.T) {
	p, _, _ := powerFixture(t, 10100)
	m := p.Store.Get("machines", "10100")
	m["guest_management"] = 1
	p.Store.Put("machines", 10100, 1, m)
	admin := person("alice", true)
	platformRun(t, p, "shutdown", admin)
	// No guest reports: the wait times out (guest_ready_timeout 3) and lists it.
	r := platformRun(t, p, "start", admin)
	if len(arr(r["not_ready"])) != 1 {
		t.Fatalf("start: %s", encoded(r))
	}
	if s := p.Store.Get("machines", "10100")["state"]; s == "initializing" {
		t.Fatalf("machine left %s", s)
	}
}

// refused passes when the call or its queued operation fails.
func refused(t *testing.T, p *Platform, r D, what string) {
	t.Helper()
	if !boolean(r["ok"]) {
		return
	}
	op := obj(r["operation"])
	if op["state"] != "failed" {
		t.Logf("waiting for %s to fail", what)
		awaitStateWithin(t, p, str(op["id"]), "failed", 5*time.Second)
	}

}

func TestPlatformStartFinishesAListedMachineThatAlreadyRuns(t *testing.T) {
	p, power, mu := powerFixture(t, 10100, 10101)
	admin := person("alice", true)
	platformRun(t, p, "shutdown", admin)
	// A start reached the node but its answer was lost: it runs, still listed.
	mu.Lock()
	power[10101] = "running"
	mu.Unlock()
	if r := platformRun(t, p, "start", admin); len(arr(r["done"])) != 2 {
		t.Fatalf("start: %s", encoded(r))
	}
	if len(restoreList(p)) != 0 {
		t.Fatalf("restore list kept: %v", restoreList(p))
	}
}

func TestPlatformStartOneSilentGuestDoesNotFailTheOthers(t *testing.T) {
	p, _, _ := powerFixture(t, 10100, 10101)
	for _, vmid := range []int{10100, 10101} {
		m := p.Store.Get("machines", fmt.Sprint(vmid))
		m["guest_management"] = 1
		p.Store.Put("machines", vmid, 1, m)
	}
	p.sshProbe = func(_ context.Context, m D) bool { return integer(m["vmid"]) == 10101 }
	admin := person("alice", true)
	platformRun(t, p, "shutdown", admin)
	// 10101 reports from its new boot once it starts; 10100 never does.
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(20 * time.Millisecond):
			}
			if p.Store.Get("machines", "10101")["state"] == "initializing" {
				p.Store.Put("guest_reports", 10101, 1, D{"vmid": 10101, "boot_id": "new", "reported_at": now(), "initialization_status": "complete", "application_status": "not_checked", "interfaces": []D{}})
				p.notifyReport(10101)
				return
			}
		}
	}()
	r := platformRun(t, p, "start", admin)
	if len(arr(r["not_ready"])) != 1 || integer(dicts(r["not_ready"])[0]["vmid"]) != 10100 {
		t.Fatalf("start: %s", encoded(r))
	}
	if s := p.Store.Get("machines", "10101")["state"]; s != "ready" {
		t.Fatalf("the guest that reported ended %s", s)
	}
}

// A paused VM is shut down with the rest, but a start leaves it stopped:
// its memory is gone, and its owner decides whether it runs (#195).
func TestPlatformStartLeavesAPausedMachineStopped(t *testing.T) {
	p, power, mu := powerFixture(t, 10100, 10101)
	mu.Lock()
	power[10101] = "paused"
	mu.Unlock()
	admin := person("alice", true)
	if r := platformRun(t, p, "shutdown", admin); len(arr(r["done"])) != 2 {
		t.Fatalf("shutdown: %s", encoded(r))
	}
	r := platformRun(t, p, "start", admin)
	if len(arr(r["done"])) != 1 || len(arr(r["skipped"])) != 1 || integer(dicts(r["skipped"])[0]["vmid"]) != 10101 {
		t.Fatalf("start: %s", encoded(r))
	}
	mu.Lock()
	defer mu.Unlock()
	if power[10100] != "running" || power[10101] != "stopped" {
		t.Fatalf("power after start: %v", power)
	}
	if len(restoreList(p)) != 0 {
		t.Fatalf("restore list kept: %v", restoreList(p))
	}
}

// A machine whose shutdown failed was not stopped by the platform: it is
// not listed, so a later start never boots it (#195).
func TestPlatformFailedShutdownIsNotListed(t *testing.T) {
	p, power, mu := powerFixture(t, 10100, 10101)
	mu.Lock()
	power[10101] = "stuck"
	mu.Unlock()
	admin := person("alice", true)
	r := platformRun(t, p, "shutdown", admin)
	if len(arr(r["failed"])) != 1 || boolean(r["complete"]) {
		t.Fatalf("shutdown: %s", encoded(r))
	}
	if !equal(restoreList(p), []int{10100}) {
		t.Fatalf("restore list: %v", restoreList(p))
	}
}

// The restore list expires: an entry older than platformRestoreTTL is not
// a shutdown's doing any more (#195).
func TestPlatformRestoreListExpires(t *testing.T) {
	p, power, mu := powerFixture(t, 10100, 10101)
	admin := person("alice", true)
	platformRun(t, p, "shutdown", admin)
	power2 := obj(p.Store.SiteGet("platform", "power"))
	for _, r := range dicts(power2["restore"]) {
		if integer(r["vmid"]) == 10101 {
			r["at"] = now() - platformRestoreTTL.Seconds() - 1
		}
	}
	p.Store.SitePut("platform", "power", power2)
	dry := p.Execute(context.Background(), "platform_power", D{"action": "start", "dry_run": true}, admin)
	assertOK(t, dry)
	if integer(dry["count"]) != 1 {
		t.Fatalf("dry run: %s", encoded(dry))
	}
	r := platformRun(t, p, "start", admin)
	mu.Lock()
	defer mu.Unlock()
	if len(arr(r["done"])) != 1 || power[10100] != "running" || power[10101] != "stopped" {
		t.Fatalf("start: %s, power %v", encoded(r), power)
	}
	if s := obj(p.Store.SiteGet("platform", "power")); s["state"] != "on" || len(dicts(s["restore"])) != 0 {
		t.Fatalf("record after start: %s", encoded(s))
	}
}
