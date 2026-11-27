package freeze

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/NYCU-WinLab/carrel/internal/pluginpb"
)

const frozenNote = "carrel-freeze k1"

// thawNode is a fake PVE node for thaws: VMID 10100 is frozen, its backup is
// on the storage, and the guest is not on the node.
type thawNode struct {
	mu                sync.Mutex
	guest             *guestEntry
	restoreExit       string // exit status of the restore task, "OK" unless set
	restoreLeavesHalf bool   // a failed restore leaves the guest locked
	removeFails       bool   // the backup cannot be removed
	discardExit       string
	running           bool // the restore task has not ended
	refuseLocked      bool // PVE refuses to destroy a locked guest, as it does for a token
	calls             []string
	backups           map[string]*thawBackup
	tasks             []taskEntry
	restoreForm       url.Values
}

type guestEntry struct{ name, lock string }

type thawBackup struct {
	notes     string
	protected int
	ctime     int64
	verified  string
}

func newThawNode() *thawNode {
	return &thawNode{backups: map[string]*thawBackup{volid: {notes: frozenNote, protected: 1, ctime: time.Now().Unix(), verified: "ok"}}}
}

func (n *thawNode) called(prefix string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := 0
	for _, x := range n.calls {
		if strings.HasPrefix(x, prefix) {
			c++
		}
	}
	return c
}

func (n *thawNode) task(typ, exit string) string {
	if exit == "" {
		exit = "OK"
	}
	upid := fmt.Sprintf("UPID:pve:%08X:%08X:%08X:%s:10100:root@pam!carrel-freeze:", len(n.tasks)+1, 1, time.Now().Unix(), typ)
	n.tasks = append(n.tasks, taskEntry{upid, typ, exit, time.Now().Unix()})
	return upid
}

func (n *thawNode) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	reply := func(v any) { _ = json.NewEncoder(w).Encode(map[string]any{"data": v}) }
	path := strings.TrimPrefix(r.URL.Path, "/api2/json")
	_ = r.ParseForm()
	n.calls = append(n.calls, r.Method+" "+path)
	const content = "/nodes/pve/storage/pbs/content"
	switch {
	case r.Method == "GET" && path == "/nodes/pve/qemu":
		list := []map[string]any{}
		if n.guest != nil {
			list = append(list, map[string]any{"vmid": 10100})
		}
		reply(list)
	case r.Method == "GET" && path == "/nodes/pve/qemu/10100/config" && n.guest != nil:
		c := map[string]any{"name": n.guest.name}
		if n.guest.lock != "" {
			c["lock"] = n.guest.lock
		}
		reply(c)
	case r.Method == "POST" && path == "/nodes/pve/qemu":
		n.restoreForm = r.Form
		if r.Form.Get("vmid") != "10100" || r.Form.Get("archive") != volid || r.Form.Get("storage") != "tank" {
			http.Error(w, "bad request", 400)
			return
		}
		upid := n.task("qmrestore", n.restoreExit)
		switch {
		case n.restoreExit == "" || n.restoreExit == "OK":
			n.guest = &guestEntry{name: "box"}
		case n.restoreLeavesHalf:
			n.guest = &guestEntry{name: "box", lock: "create"}
		}
		reply(upid)
	case r.Method == "DELETE" && path == "/nodes/pve/qemu/10100":
		exit := n.discardExit
		if n.refuseLocked && n.guest != nil && n.guest.lock != "" {
			exit = "VM is locked (" + n.guest.lock + ")"
		}
		upid := n.task("qmdestroy", exit)
		if exit == "" || exit == "OK" {
			n.guest = nil
		}
		reply(upid)
	case r.Method == "DELETE" && strings.HasPrefix(path, "/nodes/pve/tasks/"):
		n.running = false
		reply(nil)
	case r.Method == "GET" && path == "/nodes/pve/tasks":
		out := []map[string]any{}
		for _, t := range n.tasks {
			out = append(out, map[string]any{"upid": t.upid, "type": t.typ, "id": "10100", "starttime": t.start})
		}
		reply(out)
	case r.Method == "GET" && strings.HasPrefix(path, "/nodes/pve/tasks/") && strings.HasSuffix(path, "/status"):
		for _, t := range n.tasks {
			if strings.HasSuffix(strings.TrimSuffix(path, "/status"), t.upid) {
				if n.running && t.typ == "qmrestore" {
					reply(map[string]any{"status": "running"})
					return
				}
				reply(map[string]any{"status": "stopped", "exitstatus": t.exit})
				return
			}
		}
		http.NotFound(w, r)
	case r.Method == "GET" && path == content:
		list := []map[string]any{}
		for id, b := range n.backups {
			if v := r.Form.Get("vmid"); v != "" && !strings.Contains(id, "/"+v+"/") {
				continue
			}
			list = append(list, map[string]any{"volid": id, "notes": b.notes + "\n", "size": 1 << 30, "protected": b.protected, "ctime": b.ctime,
				"verification": map[string]any{"state": b.verified}})
		}
		reply(list)
	case r.Method == "PUT" && strings.HasPrefix(path, content+"/"):
		b := n.backups[strings.TrimPrefix(path, content+"/")]
		if b == nil {
			http.NotFound(w, r)
			return
		}
		b.protected = map[string]int{"1": 1}[r.Form.Get("protected")]
		reply(nil)
	case r.Method == "DELETE" && strings.HasPrefix(path, content+"/"):
		id := strings.TrimPrefix(path, content+"/")
		if n.removeFails || n.backups[id] == nil {
			http.Error(w, "storage error", 500)
			return
		}
		delete(n.backups, id)
		reply(nil)
	default:
		http.NotFound(w, r)
	}
}

func thawSite(t *testing.T) (*server, *thawNode) {
	t.Helper()
	n := newThawNode()
	return fixtureWith(t, "pbs", n.ServeHTTP), n
}

func thawReq(key string) *pluginpb.StartRequest {
	return &pluginpb.StartRequest{IdempotencyKey: key, Operation: "machine_thaw", Reservation: "res-2",
		Params: `{"machine":"10100"}`,
		Machine: `{"vmid":10100,"kind":"vm","name":"box","power_state":"stopped","backup_volid":"` + volid +
			`","backup_storage":"pbs","backup_note":"` + frozenNote + `"}`}
}

func deleteReq(key, params string) *pluginpb.StartRequest {
	return &pluginpb.StartRequest{IdempotencyKey: key, Operation: "frozen_delete", Params: params}
}

func resultOf(t *testing.T, op *pluginpb.Operation) map[string]any {
	t.Helper()
	var res map[string]any
	if err := json.Unmarshal([]byte(op.Result), &res); err != nil {
		t.Fatalf("result %q: %v", op.Result, err)
	}
	return res
}

func TestThawRestoresTheMachineThenRemovesTheBackup(t *testing.T) {
	s, n := thawSite(t)
	op := finish(t, s, start(t, s, thawReq("t1")).IdempotencyKey)
	if op.State != "succeeded" {
		t.Fatalf("op %+v", op)
	}
	res := resultOf(t, op)
	if res["backup_removed"] != true || res["thaw_backup"] != nil {
		t.Fatalf("result %v", res)
	}
	if n.guest == nil || len(n.backups) != 0 {
		t.Fatalf("guest %+v backups %+v", n.guest, n.backups)
	}
	// The backup goes only after the machine is restored.
	n.mu.Lock()
	defer n.mu.Unlock()
	restore, del := -1, -1
	for i, c := range n.calls {
		if c == "POST /nodes/pve/qemu" {
			restore = i
		}
		if strings.HasPrefix(c, "DELETE /nodes/pve/storage") {
			del = i
		}
	}
	if restore < 0 || del < restore || n.restoreForm.Get("archive") != volid || n.restoreForm.Get("storage") != "tank" {
		t.Fatalf("calls %v", n.calls)
	}
}

func TestAFailedRestoreKeepsTheBackup(t *testing.T) {
	s, n := thawSite(t)
	n.restoreExit = "ERROR: no space left"
	op := finish(t, s, start(t, s, thawReq("t1")).IdempotencyKey)
	if op.State != "failed" || !strings.Contains(op.Error, "backup "+volid+" is kept") || n.backups[volid] == nil || n.called("DELETE /nodes/pve/storage") != 0 {
		t.Fatalf("op %+v backups %+v", op, n.backups)
	}
}

func TestAFailedRestoreRemovesItsHalf(t *testing.T) {
	s, n := thawSite(t)
	n.restoreExit, n.restoreLeavesHalf = "ERROR: broken", true
	op := finish(t, s, start(t, s, thawReq("t1")).IdempotencyKey)
	if op.State != "failed" || n.guest != nil || n.backups[volid] == nil || n.called("DELETE /nodes/pve/qemu/10100") != 1 {
		t.Fatalf("op %+v guest %+v", op, n.guest)
	}
}

func TestABackupThatCannotBeRemovedIsReported(t *testing.T) {
	s, n := thawSite(t)
	n.removeFails = true
	op := finish(t, s, start(t, s, thawReq("t1")).IdempotencyKey)
	res := resultOf(t, op)
	kept, _ := res["thaw_backup"].(map[string]any)
	if op.State != "succeeded" || res["backup_removed"] != false || kept["volid"] != volid || kept["note"] != frozenNote || n.guest == nil || n.backups[volid] == nil {
		t.Fatalf("op %+v", op)
	}
}

func TestAThawAskedAgainAfterItFinishedChangesNothing(t *testing.T) {
	s, n := thawSite(t)
	finish(t, s, start(t, s, thawReq("t1")).IdempotencyKey)
	calls := len(n.calls)
	again := start(t, s, thawReq("t1"))
	if !again.Done || again.State != "succeeded" || n.called("POST /nodes/pve/qemu") != 1 || len(n.calls) != calls {
		t.Fatalf("again %+v calls %v", again, n.calls)
	}
	// A new key for a machine that is back and whose backup is gone.
	other := start(t, s, thawReq("t2"))
	if !other.Done || other.State != "succeeded" || n.called("POST /nodes/pve/qemu") != 1 {
		t.Fatalf("other %+v", other)
	}
}

func TestARetryAfterTheRestoreFinishedRemovesTheBackup(t *testing.T) {
	s, n := thawSite(t)
	n.guest = &guestEntry{name: "box"}
	op := finish(t, s, start(t, s, thawReq("t1")).IdempotencyKey)
	if op.State != "succeeded" || n.called("POST /nodes/pve/qemu") != 0 || len(n.backups) != 0 {
		t.Fatalf("op %+v calls %v", op, n.calls)
	}
}

func TestACutOffRestoreIsRemovedBeforeTheNextOne(t *testing.T) {
	s, n := thawSite(t)
	n.guest = &guestEntry{name: "box", lock: "create"}
	op := finish(t, s, start(t, s, thawReq("t1")).IdempotencyKey)
	if op.State != "succeeded" || n.called("DELETE /nodes/pve/qemu/10100") != 1 || n.called("POST /nodes/pve/qemu") != 1 || n.guest == nil || n.guest.lock != "" {
		t.Fatalf("op %+v calls %v", op, n.calls)
	}
}

// A token cannot destroy a locked half: the thaw fails, keeps the backup and
// says how a person unlocks it.
func TestALockedHalfThatCannotBeRemovedKeepsTheBackup(t *testing.T) {
	s, n := thawSite(t)
	n.guest, n.refuseLocked = &guestEntry{name: "box", lock: "create"}, true
	op := finish(t, s, start(t, s, thawReq("t1")).IdempotencyKey)
	if op.State != "failed" || !strings.Contains(op.Error, "`qm unlock 10100`") || !strings.Contains(op.Error, "backup "+volid+" is kept") ||
		n.guest == nil || n.backups[volid] == nil || n.called("POST /nodes/pve/qemu") != 0 {
		t.Fatalf("op %+v calls %v", op, n.calls)
	}
}

// A container goes back to the guest storage too: without storage PVE puts
// its mount points on "local".
func TestAContainerRestoreNamesTheGuestStorage(t *testing.T) {
	var form url.Values
	s := fixtureWith(t, "pbs", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.Form
		_ = json.NewEncoder(w).Encode(map[string]any{"data": "UPID:pve:1:1:1:vzrestore:10100:root@pam!carrel-freeze:"})
	})
	ct := "pbs:backup/ct/10100/2026-11-27T00:00:00Z"
	if _, err := s.pve.start(context.Background(), &run{Phase: "restore", Kind: "ct", VMID: 10100, Volid: ct, Target: s.guestStorage}); err != nil {
		t.Fatal(err)
	}
	if form.Get("storage") != "tank" || form.Get("ostemplate") != ct || form.Get("restore") != "1" {
		t.Fatalf("form %v", form)
	}
}

func TestThawRefusals(t *testing.T) {
	s, n := thawSite(t)
	other := func(f func(r *pluginpb.StartRequest)) *pluginpb.StartRequest {
		r := thawReq("t1")
		f(r)
		return r
	}
	cases := map[string]struct {
		req  *pluginpb.StartRequest
		code codes.Code
	}{
		"no reservation":  {other(func(r *pluginpb.StartRequest) { r.Reservation = "" }), codes.InvalidArgument},
		"bad key":         {other(func(r *pluginpb.StartRequest) { r.IdempotencyKey = "a b" }), codes.InvalidArgument},
		"another machine": {other(func(r *pluginpb.StartRequest) { r.Params = `{"machine":"10101"}` }), codes.InvalidArgument},
		"no name":         {other(func(r *pluginpb.StartRequest) { r.Machine = strings.Replace(r.Machine, `"name":"box",`, "", 1) }), codes.InvalidArgument},
		"another storage": {other(func(r *pluginpb.StartRequest) { r.Machine = strings.Replace(r.Machine, `"pbs"`, `"other"`, 1) }), codes.InvalidArgument},
		"volume not on pbs": {other(func(r *pluginpb.StartRequest) {
			r.Machine = strings.ReplaceAll(r.Machine, volid, "other:backup/vm/10100/x")
		}), codes.InvalidArgument},
		"volume of another": {other(func(r *pluginpb.StartRequest) {
			r.Machine = strings.ReplaceAll(r.Machine, volid, "pbs:backup/vm/10101/x")
		}), codes.InvalidArgument},
		"unknown operation": {other(func(r *pluginpb.StartRequest) { r.Operation = "machine_nope" }), codes.InvalidArgument},
	}
	for name, c := range cases {
		if _, err := s.StartOperation(context.Background(), c.req); status.Code(err) != c.code {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n.called("POST") != 0 {
		t.Fatalf("a refusal sent %v", n.calls)
	}
	// The VMID holds a guest that is not this machine.
	n.guest = &guestEntry{name: "someone-else"}
	if _, err := s.StartOperation(context.Background(), thawReq("t1")); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("foreign guest: %v", err)
	}
	// An unverified backup is not restored.
	n.guest = nil
	n.backups[volid].verified = "failed"
	if _, err := s.StartOperation(context.Background(), thawReq("t1")); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("unverified: %v", err)
	}
	// Nor is a backup of the cluster's own.
	n.backups[volid].verified, n.backups[volid].notes = "ok", "nightly"
	if _, err := s.StartOperation(context.Background(), thawReq("t1")); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("not a freeze backup: %v", err)
	}
	if n.called("POST") != 0 {
		t.Fatalf("a refusal sent %v", n.calls)
	}
}

func TestAThawDryRunChangesNothing(t *testing.T) {
	s, n := thawSite(t)
	req := thawReq("")
	req.DryRun, req.Reservation = true, ""
	if op := start(t, s, req); !op.Done || op.State != "succeeded" {
		t.Fatalf("dry run %+v", op)
	}
	if n.called("POST") != 0 || n.called("DELETE") != 0 || n.called("PUT") != 0 {
		t.Fatalf("calls %v", n.calls)
	}
}

func TestCancelStopsARestoreAndKeepsTheBackup(t *testing.T) {
	s, n := thawSite(t)
	n.restoreExit, n.restoreLeavesHalf, n.running = "ERROR: stopped", true, true
	op := start(t, s, thawReq("t1"))
	if op.Done {
		t.Fatalf("op %+v", op)
	}
	if _, err := s.Cancel(context.Background(), &pluginpb.CancelRequest{IdempotencyKey: "t1"}); err != nil {
		t.Fatal(err)
	}
	if end := finish(t, s, "t1"); end.State != "cancelled" || n.running || n.backups[volid] == nil || n.guest != nil {
		t.Fatalf("op %+v", end)
	}
}

func TestDeleteFrozenRemovesTheBackup(t *testing.T) {
	s, n := thawSite(t)
	op := finish(t, s, start(t, s, deleteReq("d1", `{"volid":"`+volid+`","note":"`+frozenNote+`"}`)).IdempotencyKey)
	if op.State != "succeeded" || len(n.backups) != 0 {
		t.Fatalf("op %+v", op)
	}
	// Asked again, the backup is gone and so is the answer's worry.
	if again := start(t, s, deleteReq("d2", `{"volid":"`+volid+`"}`)); !again.Done && finish(t, s, "d2").State != "succeeded" {
		t.Fatalf("again %+v", again)
	}
}

func TestDeleteFrozenReportsABackupThatStays(t *testing.T) {
	s, n := thawSite(t)
	n.removeFails = true
	op := finish(t, s, start(t, s, deleteReq("d1", `{"volid":"`+volid+`"}`)).IdempotencyKey)
	if op.State != "failed" || !strings.Contains(op.Error, "could not be removed") || n.backups[volid] == nil {
		t.Fatalf("op %+v", op)
	}
}

func TestDeleteFrozenNeverRemovesAnotherBackup(t *testing.T) {
	s, n := thawSite(t)
	n.backups[volid].notes = "nightly"
	if _, err := s.StartOperation(context.Background(), deleteReq("d1", `{"volid":"`+volid+`"}`)); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err %v", err)
	}
	// Nor the note of another freeze.
	n.backups[volid].notes = "carrel-freeze other"
	if _, err := s.StartOperation(context.Background(), deleteReq("d2", `{"volid":"`+volid+`","note":"`+frozenNote+`"}`)); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err %v", err)
	}
	if _, err := s.StartOperation(context.Background(), deleteReq("d3", `{"volid":"other:backup/vm/10100/x"}`)); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err %v", err)
	}
	if n.called("DELETE") != 0 {
		t.Fatalf("calls %v", n.calls)
	}
}

func TestDeleteFrozenRemovesACutOffRestoreFirst(t *testing.T) {
	s, n := thawSite(t)
	n.guest = &guestEntry{name: "box", lock: "create"}
	op := finish(t, s, start(t, s, deleteReq("d1", `{"volid":"`+volid+`","vmid":10100,"kind":"vm","name":"box"}`)).IdempotencyKey)
	if op.State != "succeeded" || n.guest != nil || len(n.backups) != 0 {
		t.Fatalf("op %+v guest %+v", op, n.guest)
	}
	// A machine that came back whole is not a cut-off restore: it stays.
	n.guest = &guestEntry{name: "box"}
	n.backups[volid] = &thawBackup{notes: frozenNote, verified: "ok"}
	if _, err := s.StartOperation(context.Background(), deleteReq("d2", `{"volid":"`+volid+`","vmid":10100,"kind":"vm","name":"box"}`)); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("whole machine: %v", err)
	}
	if n.guest == nil || n.backups[volid] == nil {
		t.Fatal("removed")
	}
}

func TestSweepListsOnlyBackupsNoRecordOwns(t *testing.T) {
	s, n := thawSite(t)
	old := time.Now().Add(-30 * 24 * time.Hour).Unix()
	n.backups = map[string]*thawBackup{
		"pbs:backup/vm/1/a": {notes: "carrel-freeze owned", ctime: old, verified: "ok"},
		"pbs:backup/vm/2/a": {notes: "carrel-freeze by-volume", ctime: old, verified: "ok"},
		"pbs:backup/vm/3/a": {notes: "carrel-freeze orphan", ctime: old, verified: "ok", protected: 1},
		"pbs:backup/vm/4/a": {notes: "carrel-freeze young", ctime: time.Now().Unix(), verified: "ok"},
		"pbs:backup/vm/5/a": {notes: "nightly job", ctime: old, verified: "ok"},
		"pbs:backup/vm/6/a": {notes: "carrel-freeze no-age", verified: "ok"},
	}
	req := &pluginpb.StartRequest{Operation: "backup_sweep", DryRun: true,
		Params: `{"keep":["carrel-freeze owned"],"keep_volids":["pbs:backup/vm/2/a"],"older_than":604800}`}
	op := start(t, s, req)
	res := resultOf(t, op)
	orphans, _ := res["orphans"].([]any)
	got := []string{}
	for _, o := range orphans {
		got = append(got, o.(string))
	}
	if !op.Done || len(got) != 3 || n.called("DELETE") != 0 || len(n.backups) != 6 {
		t.Fatalf("op %+v calls %v", op, n.calls)
	}
	// Listing only: no older_than, nothing removed.
	req.DryRun, req.Params = false, `{"keep":["carrel-freeze owned"],"keep_volids":["pbs:backup/vm/2/a"]}`
	if op := start(t, s, req); len(resultOf(t, op)["removed"].([]any)) != 0 || n.called("DELETE") != 0 {
		t.Fatalf("op %+v", op)
	}
	// With older_than only the old orphan with a known age goes.
	req.Params = `{"keep":["carrel-freeze owned"],"keep_volids":["pbs:backup/vm/2/a"],"older_than":604800}`
	op = start(t, s, req)
	if removed := resultOf(t, op)["removed"].([]any); len(removed) != 1 || removed[0] != "pbs:backup/vm/3/a" || len(n.backups) != 5 {
		t.Fatalf("op %+v backups %v", op, n.backups)
	}
}
