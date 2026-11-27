package carrel

import (
	"context"
	"testing"
	"time"
)

func TestCapacityCountsSnapshotsAtWhatTheyHold(t *testing.T) {
	snapshots := []diskHold{{DiskGB: 80}, {DiskGB: 80}}
	summary := func(inventory D) (disk, policy, committed D) {
		c := summarize(inventory, nil, snapshots, time.Now())
		return obj(obj(c["physical"])["disk"]), obj(c["policy"]), obj(obj(c["allocatable"])["disk_gib"])
	}
	// baseInventory: a 1500 GiB pool with 10 GiB used and 20 GiB of volumes.
	held := baseInventory()
	held["snapshot_bytes"] = 3 * GiB
	disk, policy, committed := summary(held)
	if num(committed["committed"]) != 23 || num(disk["snapshot_gib"]) != 3 || num(disk["snapshot_declared_gib"]) != 160 {
		t.Fatal(disk, committed)
	}
	// The pool's used space already includes what snapshots hold.
	if policy["snapshot_accounting"] != "held" || num(policy["snapshot_headroom_gib"]) != 1500*0.8-10 {
		t.Fatal(policy)
	}

	// Measured as nothing is still a measurement.
	held["snapshot_bytes"] = 0
	if _, policy, committed := summary(held); num(committed["committed"]) != 20 || policy["snapshot_accounting"] != "held" {
		t.Fatal(policy, committed)
	}

	// A node that does not report it: every snapshot at its disk's full size.
	disk, policy, committed = summary(baseInventory())
	if num(committed["committed"]) != 180 || num(disk["snapshot_gib"]) != 160 {
		t.Fatal(disk, committed)
	}
	if policy["snapshot_accounting"] != "declared" || num(policy["snapshot_headroom_gib"]) != 1500*0.8-10-160 {
		t.Fatal(policy)
	}
}

func TestStorageWatermark(t *testing.T) {
	for used, want := range map[float64]string{0: "ok", 70: "ok", 71: "warning", 80: "warning", 81: "blocked", 85: "blocked", 86: "critical", 100: "critical"} {
		inventory := baseInventory()
		inventory["storage"] = D{"total": 100 * GiB, "used": used * GiB}
		policy := obj(summarize(inventory, nil, nil, time.Now())["policy"])
		if policy["storage_watermark"] != want || boolean(policy["storage_admission_blocked"]) != (used > 80) {
			t.Fatalf("%v GiB of 100: %v, blocked %v", used, policy["storage_watermark"], policy["storage_admission_blocked"])
		}
	}
}

// A snapshot is admitted against what the node holds now: other snapshots
// no longer reserve their full size, but one disk that could outgrow the
// headroom on its own is still refused.
func TestSnapshotAdmissionUsesHeldBytes(t *testing.T) {
	p, b := fixture(t)
	putSnapshotRecord(p, 1, 10100, "old", 900, "ready", nil)
	e := p.execution(context.Background())
	node := p.Nodes()[0]
	admit := func(gb float64) any {
		return attempt(func() { e.Admission(node, 0, 0, gb, nil, true) })
	}
	// Declared: 0.8 * 1500 - 10 - 900 leaves 290 GiB.
	if admit(290) != nil || admit(300) == nil {
		t.Fatal("declared accounting")
	}
	b.mu.Lock()
	b.inventory["snapshot_bytes"] = 5 * GiB
	b.mu.Unlock()
	// Held: 0.8 * 1500 - 10 leaves 1190 GiB.
	if admit(300) != nil || admit(1190) != nil || admit(1200) == nil {
		t.Fatal("held accounting")
	}
	// Above the ceiling nothing grows, a snapshot included.
	b.mu.Lock()
	b.inventory["storage"] = D{"total": 1500 * GiB, "used": 1300 * GiB}
	b.mu.Unlock()
	if admit(1) == nil {
		t.Fatal("snapshot admitted above the ceiling")
	}
}

func TestCombinedCapacityNamesTheFullestNode(t *testing.T) {
	node := func(used float64, held any) D {
		inventory := baseInventory()
		inventory["storage"] = D{"total": 100 * GiB, "used": used * GiB}
		if held != nil {
			inventory["snapshot_bytes"] = held
		}
		return summarize(inventory, nil, []diskHold{{DiskGB: 10}}, time.Now())
	}
	c := combine([]D{node(10, 1*GiB), node(90, 2*GiB), node(75, 3*GiB)})
	policy, disk := obj(c["policy"]), obj(obj(c["physical"])["disk"])
	if policy["storage_watermark"] != "critical" || policy["snapshot_accounting"] != "held" || boolean(policy["storage_admission_blocked"]) {
		t.Fatal(policy)
	}
	if num(disk["snapshot_gib"]) != 6 || num(disk["snapshot_declared_gib"]) != 30 {
		t.Fatal(disk)
	}
	// One node that does not measure makes the sum declared.
	if policy := obj(combine([]D{node(10, 1*GiB), node(10, nil)})["policy"]); policy["snapshot_accounting"] != "declared" || policy["storage_watermark"] != "ok" {
		t.Fatal(policy)
	}
}

// A snapshot still being taken holds nothing, but a second request on the
// node must see its disk taken out of the headroom.
func TestSnapshotAdmissionCountsSnapshotsBeingTaken(t *testing.T) {
	p, b := fixture(t)
	b.mu.Lock()
	b.inventory["snapshot_bytes"] = 0.0
	b.mu.Unlock()
	e := p.execution(context.Background())
	node := p.Nodes()[0]
	admit := func(gb float64) any {
		return attempt(func() { e.Admission(node, 0, 0, gb, nil, true) })
	}
	if admit(1000) != nil {
		t.Fatal("headroom before")
	}
	putSnapshotRecord(p, 1, 10100, "new", 600, "creating", nil)
	if admit(590) != nil || admit(600) == nil {
		t.Fatal("snapshot being taken not counted")
	}
	putSnapshotRecord(p, 1, 10100, "new", 600, "ready", nil)
	if admit(1000) != nil {
		t.Fatal("ready snapshot counted twice")
	}
}
