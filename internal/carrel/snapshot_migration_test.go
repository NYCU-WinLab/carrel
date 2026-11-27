package carrel

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// legacySnapshot is a core snapshot row as the release before wrote it.
func legacySnapshot(vmid int, name string, change D) D {
	return merge(D{"id": fmt.Sprintf("%d-%s", vmid, name), "vmid": vmid, "name": name, "disk_gb": 20, "state": "ready",
		"operation_id": "op-" + name, "configuration": D{"cpu": 1, "disk_gb": 20, "memory_mb": 1024, "nics": []any{}}}, change)
}

// unmigrated is a site whose start has not moved the snapshots yet.
func unmigrated(t *testing.T) *Platform {
	t.Helper()
	p, _ := fixture(t)
	p.Store.SiteRemove("migration", snapshotMigration)
	return p
}

// The move carries each ready row into the plugin ledger and drops it from
// the core table, so a release before #663 counts it once. A row that
// release writes later is moved at the next start.
func TestSnapshotMigrationMovesReadyRows(t *testing.T) {
	p := unmigrated(t)
	old := legacySnapshot(10100, "before", nil)
	p.Store.Put("snapshots", old["id"], 1, old)
	r, err := MigrateSnapshots(p.Store)
	if err != nil || r["moved"] != 1 {
		t.Fatal(r, err)
	}
	rec := p.Store.Get(pluginObjectRows, pluginObjectID("snapshot", "snapshot", 10100, "before"))
	if rec["state"] != "ready" || num(obj(rec["charge"])["snapshot_gb"]) != 20 || num(obj(rec["charge"])["snapshots"]) != 1 ||
		len(arr(rec["holds"])) != 3 || rec["operation_id"] != "op-before" || obj(rec["configuration"])["cpu"] == nil {
		t.Fatal(string(encoded(rec)))
	}
	if p.Store.Get("snapshots", str(old["id"])) != nil {
		t.Fatal("the old row is still counted by the release before")
	}
	if r, err := MigrateSnapshots(p.Store); err != nil || r["moved"] != 0 {
		t.Fatal("second run", r, err)
	}
	// A rollback to the release before took a snapshot; the next start moves it.
	later := legacySnapshot(10100, "later", nil)
	p.Store.Put("snapshots", later["id"], 1, later)
	if r, err := MigrateSnapshots(p.Store); err != nil || r["moved"] != 1 || p.Store.Get(pluginObjectRows, pluginObjectID("snapshot", "snapshot", 10100, "later")) == nil {
		t.Fatal("after a rollback", r, err)
	}
	if m := p.Store.SiteGet("migration", snapshotMigration); num(m["moved"]) != 2 {
		t.Fatal(m)
	}
}

// Anything the move cannot carry stops it, and nothing is written.
func TestSnapshotMigrationRefusesWhatItCannotCarry(t *testing.T) {
	for name, c := range map[string]struct {
		setup func(p *Platform)
		want  string
	}{
		"creating": {func(p *Platform) {
			p.Store.Put("snapshots", "10100-s1", 1, legacySnapshot(10100, "s1", D{"state": "creating"}))
		}, "not ready"},
		"short name": {func(p *Platform) { p.Store.Put("snapshots", "10100-a", 1, legacySnapshot(10100, "a", nil)) }, "name the plugin refuses"},
		"no configuration": {func(p *Platform) {
			p.Store.Put("snapshots", "10100-s1", 1, without(legacySnapshot(10100, "s1", nil), "configuration"))
		}, "no configuration"},
		"exists": {func(p *Platform) {
			p.Store.Put("snapshots", "10100-s1", 1, legacySnapshot(10100, "s1", nil))
			putSnapshotRecord(p, 1, 10100, "s1", 20, "", nil)
		}, "exists already"},
		"active operation": {func(p *Platform) {
			p.Store.Put("snapshots", "10100-s1", 1, legacySnapshot(10100, "s1", nil))
			p.Store.Put("operations", "op1", 1, D{"id": "op1", "tool": "snapshot_delete", "state": "running"})
		}, "still running"},
	} {
		t.Run(name, func(t *testing.T) {
			p := unmigrated(t)
			c.setup(p)
			before, core := len(p.Store.Objects(pluginObjectRows)), len(p.Store.Objects("snapshots"))
			r, err := MigrateSnapshots(p.Store)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatal(r, err)
			}
			if len(p.Store.Objects(pluginObjectRows)) != before || len(p.Store.Objects("snapshots")) != core || p.Store.SiteGet("migration", snapshotMigration) != nil {
				t.Fatal("a refused move changed rows")
			}
		})
	}
}

// The tool and quota rows the move writes are the ones the plugin's report
// writes, so the first report changes nothing.
func TestSnapshotMigrationWritesWhatThePluginReports(t *testing.T) {
	p, b := fixture(t)
	rows := func() string {
		return string(encoded([]any{p.Store.SiteRows(pluginToolRows), p.Store.SiteRows(pluginQuotaRows)}))
	}
	before := rows()
	withSnapshotPlugin(t, p, b, nil)
	p.pluginRegistry()
	if after := rows(); !equal(decode(`{"v":`+before+`}`), decode(`{"v":`+after+`}`)) {
		t.Fatalf("migration wrote\n%s\nthe report wrote\n%s", before, after)
	}
}

// A core snapshot operation that failed before the switch is not retried
// as a plugin run: it names no plugin, and the core no longer runs it.
func TestACoreSnapshotOperationIsNotRetriedAfterTheSwitch(t *testing.T) {
	p, b := fixture(t)
	withSnapshotPlugin(t, p, b, nil)
	p.Store.Put("operations", "op1", 1, D{"id": "op1", "tenant_n": 1, "tool": "snapshot_create", "state": "failed",
		"args": D{"machine": "web", "name": "s1"}, "next_action": "operation_retry", "error": D{"code": "internal"}})
	r := p.Execute(context.Background(), "operation_retry", D{"id": "op1"}, person("alice", false))
	if f := failure(r); f["code"] != "conflict" || f["recovery"] != "revise_request" || !strings.Contains(str(f["message"]), "no longer runs") {
		t.Fatal(string(encoded(r)))
	}
	if op := p.Store.Get("operations", "op1"); op["state"] != "failed" || len(p.Store.Objects(pluginObjectRows)) != 0 {
		t.Fatal("the refused retry changed something")
	}
}
