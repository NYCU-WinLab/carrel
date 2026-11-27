package freeze

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/NYCU-WinLab/carrel/internal/pluginpb"
)

const volid = "pbs:backup/vm/10100/2026-11-27T00:00:00Z"

// node is a fake PVE node with one machine, VMID 10100, and a backup storage.
type node struct {
	mu sync.Mutex
	// the machine
	exists bool
	power  string
	snaps  int
	digest string
	onboot int
	// what the node does
	dumpExit, destroyExit string // exit status of the task, "OK" unless set
	verification          string // "ok" unless set
	loseDumpAnswer        bool   // do the work, answer 504
	// what happened
	calls   []string
	destroy url.Values // the query of the last guest removal
	backups map[string]*backupEntry
	tasks   []taskEntry
}

type backupEntry struct {
	notes     string
	protected int
}

type taskEntry struct {
	upid, typ, exit string
	start           int64
}

func newNode() *node {
	return &node{exists: true, power: "stopped", digest: "d0", backups: map[string]*backupEntry{}}
}

// startedBy logs a start of the machine by someone other than the plugin,
// and its stop: the machine is stopped again, and has run.
func (n *node) startedBy(user string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	upid := fmt.Sprintf("UPID:pve:%08X:%08X:%08X:qmstart:10100:%s:", len(n.tasks)+1, 1, time.Now().Unix(), user)
	n.tasks = append(n.tasks, taskEntry{upid, "qmstart", "OK", time.Now().Unix() + 1})
}

func (n *node) called(prefix string) int {
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

func (n *node) task(typ, exit string) string {
	if exit == "" {
		exit = "OK"
	}
	upid := fmt.Sprintf("UPID:pve:%08X:%08X:%08X:%s:10100:root@pam!carrel-freeze:", len(n.tasks)+1, 1, time.Now().Unix(), typ)
	n.tasks = append(n.tasks, taskEntry{upid, typ, exit, time.Now().Unix()})
	return upid
}

func (n *node) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	reply := func(v any) { _ = json.NewEncoder(w).Encode(map[string]any{"data": v}) }
	path := strings.TrimPrefix(r.URL.Path, "/api2/json")
	_ = r.ParseForm()
	n.calls = append(n.calls, r.Method+" "+path)
	switch {
	case r.Method == "GET" && path == "/nodes/pve/qemu":
		list := []map[string]any{}
		if n.exists {
			list = append(list, map[string]any{"vmid": 10100})
		}
		reply(list)
	case r.Method == "GET" && path == "/nodes/pve/qemu/10100/status/current":
		reply(map[string]any{"status": n.power})
	case r.Method == "GET" && path == "/nodes/pve/qemu/10100/config":
		reply(map[string]any{"digest": n.digest, "onboot": n.onboot})
	case r.Method == "PUT" && path == "/nodes/pve/qemu/10100/config":
		if r.Form.Get("onboot") != "0" {
			http.Error(w, "bad request", 400)
			return
		}
		n.onboot, n.digest = 0, n.digest+"+"
		reply(nil)
	case r.Method == "GET" && path == "/nodes/pve/qemu/10100/snapshot":
		list := []map[string]any{{"name": "current"}}
		for i := 0; i < n.snaps; i++ {
			list = append(list, map[string]any{"name": fmt.Sprint("s", i)})
		}
		reply(list)
	case r.Method == "POST" && path == "/nodes/pve/vzdump":
		if r.Form.Get("mode") != "stop" || r.Form.Get("storage") != "pbs" || r.Form.Get("vmid") != "10100" {
			http.Error(w, "bad request", 400)
			return
		}
		upid := n.task("vzdump", n.dumpExit)
		if n.dumpExit == "" || n.dumpExit == "OK" {
			n.backups[volid] = &backupEntry{notes: r.Form.Get("notes-template")}
		}
		if n.loseDumpAnswer {
			http.Error(w, "gateway timeout", 504)
			return
		}
		reply(upid)
	case r.Method == "GET" && path == "/nodes/pve/tasks":
		out := []map[string]any{}
		for _, t := range n.tasks {
			out = append(out, map[string]any{"upid": t.upid, "type": t.typ, "id": "10100", "starttime": t.start})
		}
		reply(out)
	case r.Method == "GET" && strings.HasSuffix(path, "/status") && strings.HasPrefix(path, "/nodes/pve/tasks/"):
		for _, t := range n.tasks {
			if strings.HasSuffix(strings.TrimSuffix(path, "/status"), t.upid) {
				reply(map[string]any{"status": "stopped", "exitstatus": t.exit})
				return
			}
		}
		http.NotFound(w, r)
	case r.Method == "GET" && path == "/nodes/pve/storage/pbs/content":
		list := []map[string]any{}
		for id, b := range n.backups {
			v := n.verification
			if v == "" {
				v = "ok"
			}
			list = append(list, map[string]any{"volid": id, "notes": b.notes + "\n", "size": 1 << 30, "protected": b.protected,
				"verification": map[string]any{"state": v}})
		}
		reply(list)
	case r.Method == "PUT" && strings.HasPrefix(path, "/nodes/pve/storage/pbs/content/"):
		b := n.backups[strings.TrimPrefix(path, "/nodes/pve/storage/pbs/content/")]
		if b == nil {
			http.NotFound(w, r)
			return
		}
		b.protected = map[string]int{"1": 1}[r.Form.Get("protected")]
		reply(nil)
	case r.Method == "DELETE" && strings.HasPrefix(path, "/nodes/pve/storage/pbs/content/"):
		id := strings.TrimPrefix(path, "/nodes/pve/storage/pbs/content/")
		if b := n.backups[id]; b == nil || b.protected != 0 {
			http.Error(w, "protected", 400)
			return
		}
		delete(n.backups, id)
		reply(nil)
	case r.Method == "DELETE" && path == "/nodes/pve/qemu/10100":
		n.destroy = r.URL.Query()
		upid := n.task("qmdestroy", n.destroyExit)
		if n.destroyExit == "" || n.destroyExit == "OK" {
			n.exists = false
		}
		reply(upid)
	default:
		http.NotFound(w, r)
	}
}

func freezeReq(key string) *pluginpb.StartRequest {
	return &pluginpb.StartRequest{IdempotencyKey: key, Operation: "machine_freeze", Reservation: "res-1",
		Params:  `{"machine":"10100","confirm":"box"}`,
		Machine: `{"vmid":10100,"kind":"vm","power_state":"stopped"}`}
}

func site(t *testing.T) (*server, *node) {
	t.Helper()
	n := newNode()
	return fixtureWith(t, "pbs", n.ServeHTTP), n
}

func start(t *testing.T, s *server, req *pluginpb.StartRequest) *pluginpb.Operation {
	t.Helper()
	op, err := s.StartOperation(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func get(t *testing.T, s *server, key string) *pluginpb.Operation {
	t.Helper()
	op, err := s.GetOperation(context.Background(), &pluginpb.GetRequest{IdempotencyKey: key})
	if err != nil {
		t.Fatal(err)
	}
	return op
}

// finish asks after the run until it ends.
func finish(t *testing.T, s *server, key string) *pluginpb.Operation {
	t.Helper()
	for i := 0; i < 10; i++ {
		if op := get(t, s, key); op.Done {
			return op
		}
	}
	t.Fatal("the run did not end")
	return nil
}

func TestFreezeBacksUpVerifiesAndRemovesTheMachine(t *testing.T) {
	s, n := site(t)
	op := finish(t, s, start(t, s, freezeReq("k1")).IdempotencyKey)
	if op.State != "succeeded" || !op.Done {
		t.Fatalf("op: %+v", op)
	}
	var res struct {
		Gone   bool `json:"gone"`
		Backup struct {
			Volid, Verification string
			Size                int64
		} `json:"backup"`
	}
	if err := json.Unmarshal([]byte(op.Result), &res); err != nil || !res.Gone || res.Backup.Volid != volid || res.Backup.Verification != "ok" || res.Backup.Size <= 0 {
		t.Fatalf("result %s: %v", op.Result, err)
	}
	if n.exists || n.backups[volid] == nil || n.backups[volid].protected != 1 || n.backups[volid].notes != "carrel-freeze k1" {
		t.Fatalf("node: exists=%v backups=%+v", n.exists, n.backups)
	}
	// Only the disks of the config, which the backup holds, are removed.
	if n.destroy.Get("purge") != "1" || n.destroy.Has("destroy-unreferenced-disks") || len(n.destroy) != 1 {
		t.Fatalf("destroy query %v", n.destroy)
	}
}

func TestFreezeClearsOnbootBeforeTheBackup(t *testing.T) {
	s, n := site(t)
	n.onboot = 1
	op := finish(t, s, start(t, s, freezeReq("k1")).IdempotencyKey)
	if op.State != "succeeded" || n.onboot != 0 || n.called("PUT /nodes/pve/qemu/10100/config") != 1 {
		t.Fatalf("op %+v onboot %d calls %v", op, n.onboot, n.calls)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	put, dump := slices.Index(n.calls, "PUT /nodes/pve/qemu/10100/config"), slices.Index(n.calls, "POST /nodes/pve/vzdump")
	if put < 0 || dump < put {
		t.Fatalf("onboot was not cleared before the backup: %v", n.calls)
	}
}

func TestAMachineStartedAndStoppedDuringTheWaitStays(t *testing.T) {
	s, n := site(t)
	n.verification = "none"
	start(t, s, freezeReq("k1"))
	// The node rebooted, or someone started it and shut it down again.
	n.startedBy("root@pam")
	n.mu.Lock()
	n.verification = "ok"
	n.mu.Unlock()
	op := get(t, s, "k1")
	if op.State != "failed" || !strings.Contains(op.Error, "changed") || !n.exists || len(n.backups) != 0 || n.called("DELETE /nodes/pve/qemu") != 0 {
		t.Fatalf("op %+v node %v %+v", op, n.exists, n.backups)
	}
}

func TestAMachineWhoseConfigChangedDuringTheWaitStays(t *testing.T) {
	s, n := site(t)
	n.verification = "none"
	start(t, s, freezeReq("k1"))
	n.mu.Lock()
	n.verification, n.digest = "ok", "d1"
	n.mu.Unlock()
	op := get(t, s, "k1")
	if op.State != "failed" || !strings.Contains(op.Error, "changed") || !n.exists || len(n.backups) != 0 || n.called("DELETE /nodes/pve/qemu") != 0 {
		t.Fatalf("op %+v node %v %+v", op, n.exists, n.backups)
	}
}

func TestARunWithNoProofDoesNotRemoveTheMachine(t *testing.T) {
	s, n := site(t)
	n.verification = "none"
	start(t, s, freezeReq("k1"))
	// A run stored before the proof existed.
	r, err := s.runs.load("k1")
	if err != nil || r == nil {
		t.Fatalf("run %+v: %v", r, err)
	}
	r.Digest = ""
	if err := s.runs.save(r); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	n.verification = "ok"
	n.mu.Unlock()
	if op := get(t, s, "k1"); op.State != "failed" || !n.exists || n.called("DELETE /nodes/pve/qemu") != 0 {
		t.Fatalf("op %+v calls %v", op, n.calls)
	}
}

func TestTheSameKeyIsTheSameOperation(t *testing.T) {
	s, n := site(t)
	first := start(t, s, freezeReq("k1"))
	second := start(t, s, freezeReq("k1"))
	if first.Task == "" || second.Task != first.Task {
		t.Fatalf("tasks %q and %q", first.Task, second.Task)
	}
	finish(t, s, "k1")
	again := start(t, s, freezeReq("k1"))
	if !again.Done || again.State != "succeeded" || n.called("POST /nodes/pve/vzdump") != 1 || n.called("DELETE /nodes/pve/qemu/10100") != 1 {
		t.Fatalf("again %+v, calls %v", again, n.calls)
	}
	other := freezeReq("k1")
	other.Operation = "machine_thaw"
	if _, err := s.StartOperation(context.Background(), other); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("another operation under the key: %v", err)
	}
}

func TestARestartedPluginFindsTheStoredTask(t *testing.T) {
	s, n := site(t)
	first := start(t, s, freezeReq("k1"))
	restarted := newServer() // the same state directory and environment
	if st, err := restarted.runs.load("k1"); err != nil || st == nil || st.UPID != first.Task {
		t.Fatalf("stored run %+v: %v", st, err)
	}
	if op := finish(t, restarted, "k1"); op.State != "succeeded" || n.called("POST /nodes/pve/vzdump") != 1 {
		t.Fatalf("op %+v, calls %v", op, n.calls)
	}
}

func TestALostAnswerFindsTheTaskAgain(t *testing.T) {
	s, n := site(t)
	n.loseDumpAnswer = true
	first := start(t, s, freezeReq("k1"))
	if first.Done {
		t.Fatalf("op: %+v", first)
	}
	if op := finish(t, s, "k1"); op.State != "succeeded" || n.called("POST /nodes/pve/vzdump") != 1 {
		t.Fatalf("op %+v, calls %v", op, n.calls)
	}
}

func TestAFailedBackupLeavesTheMachine(t *testing.T) {
	s, n := site(t)
	n.dumpExit = "ERROR: vzdump failed"
	op := finish(t, s, start(t, s, freezeReq("k1")).IdempotencyKey)
	if op.State != "failed" || !strings.Contains(op.Error, "backup task failed") {
		t.Fatalf("op: %+v", op)
	}
	if !n.exists || n.called("DELETE /nodes/pve/qemu") != 0 || len(n.backups) != 0 {
		t.Fatalf("the machine did not stay: %v", n.calls)
	}
}

func TestABackupThatFailsVerificationIsRemovedAndTheMachineStays(t *testing.T) {
	s, n := site(t)
	n.verification = "failed"
	op := finish(t, s, start(t, s, freezeReq("k1")).IdempotencyKey)
	if op.State != "failed" || !strings.Contains(op.Error, "verification") {
		t.Fatalf("op: %+v", op)
	}
	if !n.exists || n.called("DELETE /nodes/pve/qemu") != 0 || len(n.backups) != 0 {
		t.Fatalf("node: %v %+v", n.calls, n.backups)
	}
}

func TestABackupNotVerifiedInTimeIsRemoved(t *testing.T) {
	s, n := site(t)
	n.verification = "none"
	start(t, s, freezeReq("k1"))
	if op := get(t, s, "k1"); op.Done || op.Message != "verify" {
		t.Fatalf("op: %+v", op)
	}
	s.now = func() time.Time { return time.Now().Add(s.verifyWait + time.Second) }
	op := get(t, s, "k1")
	if op.State != "failed" || !strings.Contains(op.Error, "not verified in time") || !n.exists || len(n.backups) != 0 {
		t.Fatalf("op %+v node %v %+v", op, n.exists, n.backups)
	}
}

func TestAMachineStartedDuringTheBackupKeepsItsPower(t *testing.T) {
	s, n := site(t)
	n.verification = "none"
	start(t, s, freezeReq("k1"))
	n.mu.Lock()
	n.verification, n.power = "ok", "running"
	n.mu.Unlock()
	op := get(t, s, "k1")
	if op.State != "failed" || !n.exists || len(n.backups) != 0 || n.called("DELETE /nodes/pve/qemu") != 0 {
		t.Fatalf("op %+v node %v %+v", op, n.exists, n.backups)
	}
}

func TestCancelLeavesTheMachineAsItWas(t *testing.T) {
	s, n := site(t)
	n.verification = "none"
	start(t, s, freezeReq("k1"))
	op, err := s.Cancel(context.Background(), &pluginpb.CancelRequest{IdempotencyKey: "k1"})
	if err != nil || op.State != "cancelled" || !op.Done {
		t.Fatalf("cancel: %+v %v", op, err)
	}
	if !n.exists || len(n.backups) != 0 || n.called("DELETE /nodes/pve/qemu") != 0 {
		t.Fatalf("node: %v %+v", n.calls, n.backups)
	}
}

func TestAFailedRemovalKeepsTheBackup(t *testing.T) {
	s, n := site(t)
	n.destroyExit = "ERROR: busy"
	op := finish(t, s, start(t, s, freezeReq("k1")).IdempotencyKey)
	if op.State != "failed" || !strings.Contains(op.Error, "kept") || n.backups[volid] == nil {
		t.Fatalf("op %+v backups %+v", op, n.backups)
	}
}

func TestFreezeRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(n *node)
		edit  func(r *pluginpb.StartRequest)
		code  codes.Code
	}{
		"running":        {setup: func(n *node) { n.power = "running" }, code: codes.FailedPrecondition},
		"snapshots":      {setup: func(n *node) { n.snaps = 1 }, code: codes.FailedPrecondition},
		"no reservation": {edit: func(r *pluginpb.StartRequest) { r.Reservation = "" }, code: codes.InvalidArgument},
		"other machine":  {edit: func(r *pluginpb.StartRequest) { r.Params = `{"machine":"10101"}` }, code: codes.InvalidArgument},
		"bad key":        {edit: func(r *pluginpb.StartRequest) { r.IdempotencyKey = "a b" }, code: codes.InvalidArgument},
	} {
		t.Run(name, func(t *testing.T) {
			s, n := site(t)
			if tc.setup != nil {
				tc.setup(n)
			}
			req := freezeReq("k1")
			if tc.edit != nil {
				tc.edit(req)
			}
			if _, err := s.StartOperation(context.Background(), req); status.Code(err) != tc.code {
				t.Fatalf("err %v", err)
			}
			if n.called("POST") != 0 || n.called("DELETE") != 0 {
				t.Fatalf("a refused freeze reached the node: %v", n.calls)
			}
			if st, _ := s.runs.load(req.IdempotencyKey); st != nil {
				t.Fatalf("a refusal left a run: %+v", st)
			}
		})
	}
}

func TestADryRunChangesNothing(t *testing.T) {
	s, n := site(t)
	req := freezeReq("")
	req.DryRun, req.Reservation = true, ""
	if op := start(t, s, req); !op.Done || op.State != "succeeded" {
		t.Fatalf("op: %+v", op)
	}
	if slices.ContainsFunc(n.calls, func(c string) bool { return !strings.HasPrefix(c, "GET ") }) {
		t.Fatalf("calls: %v", n.calls)
	}
}

func TestTheVerifyWaitComesFromTheEnvironment(t *testing.T) {
	t.Setenv("CARREL_FREEZE_VERIFY_WAIT", "60")
	s, _ := site(t)
	if s.verifyWait != time.Minute || s.problem != "" {
		t.Fatalf("wait %v problem %q", s.verifyWait, s.problem)
	}
	t.Setenv("CARREL_FREEZE_VERIFY_WAIT", "soon")
	if s, _ := site(t); s.problem == "" {
		t.Fatal("a bad wait was taken")
	}
	t.Setenv("CARREL_FREEZE_VERIFY_WAIT", "")
	if s, _ := site(t); s.verifyWait != 1800*time.Second {
		t.Fatalf("default %v", s.verifyWait)
	}
}
