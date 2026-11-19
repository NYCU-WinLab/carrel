package carrel

import (
	"context"
	"testing"
	"time"
)

// snapshotQuotaFixture gives alice one 80 GiB machine with two snapshots.
func snapshotQuotaFixture(t *testing.T) (*Platform, *App, func(tool string, args D) D) {
	t.Helper()
	p, _ := fixture(t)
	p.Store.Put("machines", 10100, 1, D{"vmid": 10100, "tenant_n": 1, "name": "web", "kind": "vm", "node": "carrel01", "cpu": 1, "memory_mb": 1024, "disk_gb": 80, "state": "ready"})
	for _, name := range []string{"s1", "s2"} {
		p.Store.Put("snapshots", "10100-"+name, 1, D{"id": "10100-" + name, "vmid": 10100, "name": name, "disk_gb": 80, "state": "ready"})
	}
	app := NewApp(p, nil)
	who := person("alice", false)
	return p, app, func(tool string, args D) D { return app.Call(context.Background(), tool, args, who) }
}

func sampleSnapshots(p *Platform, held float64, age time.Duration, available bool) {
	p.Store.Put("storage_usage", 1, 1, D{"tenant_n": 1, "available": available, "accounting": "test", "retained_snapshot_bytes": held * GiB, "unique_total_bytes": (held + 5) * GiB, "sampled_at": float64(time.Now().Add(-age).Unix())})
}

func snapshotGBOf(t *testing.T, r D) (used float64, counts any) {
	t.Helper()
	assertOK(t, r)
	return num(obj(obj(r["quota_after"])["used"])["snapshot_gb"]), obj(r["snapshot_storage"])["snapshot_gb_counts"]
}

func TestSnapshotQuotaCountsWhatSnapshotsHold(t *testing.T) {
	p, _, call := snapshotQuotaFixture(t)
	third := D{"machine": "web", "name": "s3", "dry_run": true}

	// No sample: two snapshots of an 80 GiB disk count 160, a third would pass 200.
	if used, counts := snapshotGBOf(t, call("snapshot_list", D{"machine": "web"})); counts != "declared" {
		t.Fatal(used, counts)
	}
	if used := num(obj(obj(call("quota_get", D{})["quota"])["used"])["snapshot_gb"]); used != 160 {
		t.Fatal("declared", used)
	}
	r := call("snapshot_create", third)
	assertCode(t, r, "quota_exceeded")
	if failure := obj(r["error"]); failure["dimension"] != "snapshot_gb" || num(failure["used"]) != 240 {
		t.Fatal(encoded(failure))
	}

	// Measured: the same two snapshots hold 3 GiB, and a new one adds nothing yet.
	sampleSnapshots(p, 3, time.Minute, true)
	if used, counts := snapshotGBOf(t, call("snapshot_create", third)); used != 3 || counts != "held" {
		t.Fatal(used, counts)
	}
	// Deleting one frees an amount only the next sample knows.
	if used, _ := snapshotGBOf(t, call("snapshot_delete", D{"machine": "web", "name": "s1", "dry_run": true})); used != 3 {
		t.Fatal("delete preview", used)
	}
	// The machine holds every snapshot the tenant has: deleting it leaves none.
	if used := num(obj(obj(call("machine_delete", D{"machine": "web", "confirm": "web", "dry_run": true})["quota_after"])["used"])["snapshot_gb"]); used != 0 {
		t.Fatal("machine delete preview", used)
	}
	p.Store.Remove("snapshots", "10100-s2")
	if used, _ := snapshotGBOf(t, call("snapshot_delete", D{"machine": "web", "name": "s1", "dry_run": true})); used != 0 {
		t.Fatal("last snapshot delete preview", used)
	}
	p.Store.Put("snapshots", "10100-s2", 1, D{"id": "10100-s2", "vmid": 10100, "name": "s2", "disk_gb": 80, "state": "ready"})

	// A sample the nodes stopped renewing, or one a node could not take, is not trusted.
	// Nor is one dated ahead of this clock: it would never grow old.
	for _, stale := range []func(){func() { sampleSnapshots(p, 3, 16*time.Minute, true) }, func() { sampleSnapshots(p, 3, time.Minute, false) }, func() { sampleSnapshots(p, 3, -24*time.Hour, true) }} {
		stale()
		assertCode(t, call("snapshot_create", third), "quota_exceeded")
		if used, counts := snapshotGBOf(t, call("snapshot_delete", D{"machine": "web", "name": "s1", "dry_run": true})); used != 80 || counts != "declared" {
			t.Fatal(used, counts)
		}
	}
}

func TestSnapshotRefusedWhileHeldSpaceIsOverTheLimit(t *testing.T) {
	p, _, call := snapshotQuotaFixture(t)
	third := D{"machine": "web", "name": "s3", "dry_run": true}

	sampleSnapshots(p, 200, time.Minute, true)
	assertOK(t, call("snapshot_create", third))

	sampleSnapshots(p, 200.5, time.Minute, true)
	r := call("snapshot_create", third)
	assertCode(t, r, "quota_exceeded")
	failure := obj(r["error"])
	if failure["dimension"] != "snapshot_gb" || num(failure["used"]) != 200.5 || num(failure["limit"]) != 200 || len(arr(failure["violations"])) != 1 {
		t.Fatal(encoded(failure))
	}
	if over := arr(obj(call("quota_get", D{})["quota"])["over_limit"]); len(over) != 1 || over[0] != "snapshot_gb" {
		t.Fatal(over)
	}
	// Cleanup stays open, and a snapshot that exists is not asked again.
	assertOK(t, call("snapshot_delete", D{"machine": "web", "name": "s1", "dry_run": true}))
}

func TestSnapshotQuotaWithoutSnapshotsOrSample(t *testing.T) {
	p, _, call := snapshotQuotaFixture(t)
	for _, name := range []string{"s1", "s2"} {
		p.Store.Remove("snapshots", "10100-"+name)
	}
	// An old sample of a tenant that has no snapshots counts nothing.
	sampleSnapshots(p, 50, 40*24*time.Hour, true)
	if used := num(obj(obj(call("quota_get", D{})["quota"])["used"])["snapshot_gb"]); used != 0 {
		t.Fatal(used)
	}
	// Without a fresh sample even the first snapshot is checked at the size of its disk.
	m := p.Store.Get("machines", "10100")
	m["disk_gb"] = 250
	p.Store.Put("machines", 10100, 1, m)
	first := D{"machine": "web", "name": "s1", "dry_run": true}
	assertCode(t, call("snapshot_create", first), "quota_exceeded")
	sampleSnapshots(p, 0, time.Minute, true)
	assertOK(t, call("snapshot_create", first))
}

func TestSnapshotCreatedUnderMeasuredQuotaKeepsItsRecord(t *testing.T) {
	p, _, _ := snapshotQuotaFixture(t)
	sampleSnapshots(p, 3, time.Minute, true)
	r := p.execution(context.Background()).SnapshotAction("snapshot_create", D{"machine": "web", "name": "s3"}, p.Store.TenantN(1))
	used := obj(obj(r["quota_after"])["used"])
	if num(used["snapshot_gb"]) != 3 || num(used["snapshots"]) != 3 || obj(r["snapshot_storage"])["snapshot_gb_counts"] != "held" {
		t.Fatal(encoded(r))
	}
	if s := p.Store.Get("snapshots", "10100-s3"); s["state"] != "ready" || num(s["disk_gb"]) != 80 {
		t.Fatal(encoded(s))
	}
}

// Snapshots grow without a request. A tenant over snapshot_gb is refused new
// snapshots, not the requests that add nothing; any other dimension still is.
func TestOverSnapshotSpaceBlocksOnlySnapshots(t *testing.T) {
	p, _, _ := snapshotQuotaFixture(t)
	e := p.execution(context.Background())
	for _, over := range []func(){func() { sampleSnapshots(p, 201, time.Minute, true) }, func() {
		// No sample: three snapshots of an 80 GiB disk count 240.
		p.Store.Remove("storage_usage", "1")
		p.Store.Put("snapshots", "10100-s3", 1, D{"id": "10100-s3", "vmid": 10100, "name": "s3", "disk_gb": 80, "state": "ready"})
	}} {
		over()
		tenant := p.Store.TenantN(1)
		if problem := attempt(func() { e.Quota(tenant, D{}) }); problem != nil {
			t.Fatal(describe(problem))
		}
		if problem := attempt(func() { e.Quota(tenant, D{"domains": 1}) }); problem != nil {
			t.Fatal(describe(problem))
		}
		if q := e.Quota(tenant); len(arr(q["over_limit"])) != 1 {
			t.Fatal(encoded(q))
		}
	}
	// Over in a dimension that only a request can raise: a request that adds
	// nothing passes, growth is refused.
	tenant := p.Store.TenantN(1)
	obj(tenant["quota"])["machines"] = 0
	if problem := attempt(func() { e.Quota(tenant, D{}) }); problem != nil {
		t.Fatal(describe(problem))
	}
	if problem := attempt(func() { e.Quota(tenant, D{"machines": 1}) }); problem == nil {
		t.Fatal("growth passed while over machines")
	}
}

func TestStorageSampleIsDatedByTheControlPlane(t *testing.T) {
	p, _, _ := nodeFixture(t)
	p.Store.Put("machines", 10100, 1, D{"vmid": 10100, "tenant_n": 1, "name": "web", "node": "carrel01", "disk_gb": 80})
	p.Store.Put("snapshots", "10100-s1", 1, D{"id": "10100-s1", "vmid": 10100, "name": "s1", "disk_gb": 80, "state": "ready"})
	e := p.execution(context.Background())
	if _, measured := e.snapshotGB(1); measured {
		t.Fatal("measured without a sample")
	}
	e.RefreshStorage()
	if age := now() - num(p.Store.Get("storage_usage", "1")["sampled_at"]); age < 0 || age > 5 {
		t.Fatal("sample age", age)
	}
	if held, measured := e.snapshotGB(1); !measured || held != 0 {
		t.Fatal(held, measured)
	}
}
