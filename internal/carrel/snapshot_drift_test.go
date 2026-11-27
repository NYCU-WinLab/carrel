package carrel

import (
	"context"
	"testing"
)

func driftSite(t *testing.T, answer func(D) (any, error)) (*Platform, *fakeBackend) {
	t.Helper()
	p, b := fixture(t)
	seedMachine(p, "box", 10100)
	withSnapshotPlugin(t, p, b, nil)
	b.call = func(r D, target string) (any, error) {
		if r["op"] == "plugin" {
			return answer(r)
		}
		return D{"status": "running"}, nil
	}
	return p, b
}

func listed(names ...any) func(D) (any, error) {
	return func(D) (any, error) {
		return D{"state": "succeeded", "done": true, "result": D{"snapshots": names}}, nil
	}
}

func snapshotRecords(p *Platform) int {
	return len(p.Store.Objects(pluginObjectRows))
}

func TestSweepDropsARecordWhoseSnapshotIsGone(t *testing.T) {
	p, _ := driftSite(t, listed("kept"))
	putSnapshotRecord(p, 1, 10100, "kept", 5, "", nil)
	putSnapshotRecord(p, 1, 10100, "gone", 7, "", nil)
	e := p.execution(context.Background())
	before := num(obj(obj(e.Quota(e.S.TenantN(1))["used"]))["snapshots"])
	dropped := e.SweepMissingSnapshots()
	if len(dropped) != 1 || dropped[0]["name"] != "gone" || integer(dropped[0]["tenant_n"]) != 1 {
		t.Fatalf("dropped %v", dropped)
	}
	if snapshotRecords(p) != 1 {
		t.Fatalf("records left: %d", snapshotRecords(p))
	}
	if after := num(obj(obj(e.Quota(e.S.TenantN(1))["used"]))["snapshots"]); before != 2 || after != 1 {
		t.Fatalf("snapshots charged %v then %v", before, after)
	}
}

func TestSweepKeepsWhatItCannotProveGone(t *testing.T) {
	failing := func(D) (any, error) {
		return nil, Failure{D{"ok": false, "error": D{"code": "backend_unavailable", "backend_code": "plugin_unavailable"}}}
	}
	reply := func(v any, state string, done bool) func(D) (any, error) {
		return func(D) (any, error) { return D{"state": state, "done": done, "result": v}, nil }
	}
	cases := map[string]func(D) (any, error){
		"present":       listed("snap"),
		"plugin error":  failing,
		"plugin failed": reply(D{"snapshots": []any{}}, "failed", true),
		"not done":      reply(D{"snapshots": []any{}}, "running", false),
		"no result":     reply(nil, "succeeded", true),
		"no field":      reply(D{"other": []any{}}, "succeeded", true),
		"not a list":    reply(D{"snapshots": "none"}, "succeeded", true),
		"non string":    reply(D{"snapshots": []any{1}}, "succeeded", true),
		"bad json text": reply("{", "succeeded", true),
		"not an object": reply([]any{}, "succeeded", true),
	}
	for name, answer := range cases {
		t.Run(name, func(t *testing.T) {
			p, _ := driftSite(t, answer)
			putSnapshotRecord(p, 1, 10100, "snap", 5, "", nil)
			if d := p.execution(context.Background()).SweepMissingSnapshots(); len(d) != 0 || snapshotRecords(p) != 1 {
				t.Fatalf("dropped %v, records %d", d, snapshotRecords(p))
			}
		})
	}
}

func TestSweepReadsTheResultAsJSONText(t *testing.T) {
	p, _ := driftSite(t, func(D) (any, error) {
		return D{"state": "succeeded", "done": true, "result": `{"snapshots":["other"]}`}, nil
	})
	putSnapshotRecord(p, 1, 10100, "snap", 5, "", nil)
	if d := p.execution(context.Background()).SweepMissingSnapshots(); len(d) != 1 || snapshotRecords(p) != 0 {
		t.Fatalf("dropped %v", d)
	}
}

func TestSweepSkipsRecordsThatAreNotReady(t *testing.T) {
	p, b := driftSite(t, listed())
	for _, state := range []string{"creating", "deleting"} {
		putSnapshotRecord(p, 1, 10100, state, 5, state, nil)
	}
	if d := p.execution(context.Background()).SweepMissingSnapshots(); len(d) != 0 || snapshotRecords(p) != 2 {
		t.Fatalf("dropped %v", d)
	}
	if b.count("plugin") != 0 {
		t.Fatal("asked the plugin about a machine with no ready record")
	}
}

func TestSweepKeepsRecordsWhenNoNodeReportsThePlugin(t *testing.T) {
	p, _ := fixture(t)
	seedMachine(p, "box", 10100)
	putSnapshotRecord(p, 1, 10100, "snap", 5, "", nil)
	if d := p.execution(context.Background()).SweepMissingSnapshots(); len(d) != 0 || snapshotRecords(p) != 1 {
		t.Fatalf("dropped %v", d)
	}
}
