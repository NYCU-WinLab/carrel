package snapshot

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/NYCU-WinLab/carrel/internal/pluginpb"
)

// fakePVE is one node's API: guests with snapshots, and the tasks started.
type fakePVE struct {
	mu    sync.Mutex
	snaps map[int]map[string]bool
	power map[int]string
	tasks map[string]*fakeTask
	// sent counts the requests that started a task.
	sent int
	// lose: the next start is done but its answer is cut off.
	lose bool
	// refuse: the next start is answered with this error, doing nothing.
	refuse string
	// hold: tasks stay running until released.
	hold bool
	// exit is the exit status of the next task; "" is OK.
	exit string
	// auth is the token every request must carry.
	auth string
}

type fakeTask struct {
	upid, typ, id string
	start         int64
	running       bool
	exit          string
	apply         func()
}

func (f *fakePVE) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != f.auth {
		http.Error(w, "authentication failure", http.StatusUnauthorized)
		return
	}
	reply := func(v any) { _ = json.NewEncoder(w).Encode(map[string]any{"data": v}) }
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api2/json/"), "/")
	if r.URL.Path == "/api2/json/version" {
		reply(map[string]any{"version": "9.2"})
		return
	}
	if len(parts) >= 3 && parts[0] == "nodes" && parts[2] == "tasks" {
		if len(parts) == 3 {
			out := []map[string]any{}
			for _, t := range f.tasks {
				// PVE lists only ended tasks unless asked for all.
				if t.running && r.URL.Query().Get("source") != "all" {
					continue
				}
				if t.id == r.URL.Query().Get("vmid") && t.typ == r.URL.Query().Get("typefilter") {
					out = append(out, map[string]any{"upid": t.upid, "type": t.typ, "id": t.id, "starttime": t.start})
				}
			}
			reply(out)
			return
		}
		t := f.tasks[parts[3]]
		if t == nil {
			http.Error(w, "no such task", http.StatusNotFound)
			return
		}
		if t.running && !f.hold {
			t.running = false
			t.apply()
		}
		state := map[bool]string{true: "running", false: "stopped"}[t.running]
		reply(map[string]any{"status": state, "exitstatus": t.exit})
		return
	}
	var vmid int
	fmt.Sscan(parts[3], &vmid)
	kind := map[string]string{"qemu": "vm", "lxc": "ct"}[parts[2]]
	snaps := f.snaps[vmid]
	if snaps == nil {
		http.Error(w, "no such guest", http.StatusInternalServerError)
		return
	}
	rest := parts[4:]
	switch {
	case r.Method == http.MethodGet && rest[0] == "status":
		reply(map[string]any{"status": f.power[vmid]})
	case r.Method == http.MethodGet && rest[0] == "snapshot":
		out := []map[string]any{{"name": "current"}}
		for n := range snaps {
			out = append(out, map[string]any{"name": n})
		}
		reply(out)
	default:
		_ = r.ParseForm()
		op, name := "", ""
		switch {
		case r.Method == http.MethodPost && len(rest) == 1:
			op, name = "create", r.PostForm.Get("snapname")
		case r.Method == http.MethodDelete && len(rest) == 2:
			op, name = "delete", rest[1]
		case r.Method == http.MethodPost && len(rest) == 3 && rest[2] == "rollback":
			op, name = "rollback", rest[1]
		}
		if f.refuse != "" {
			http.Error(w, f.refuse, http.StatusInternalServerError)
			f.refuse = ""
			return
		}
		f.sent++
		upid := fmt.Sprintf("UPID:pve:%08d:%s:%d:root@pam!carrel-snapshot:", f.sent, taskTypes[kind][op], vmid)
		exit := f.exit
		if exit == "" {
			exit = "OK"
		}
		f.exit = ""
		apply := func() {
			if exit != "OK" {
				return
			}
			switch op {
			case "create":
				snaps[name] = true
			case "delete":
				delete(snaps, name)
			}
		}
		f.tasks[upid] = &fakeTask{upid: upid, typ: taskTypes[kind][op], id: fmt.Sprint(vmid), start: time.Now().Unix(), running: true, exit: exit, apply: apply}
		if f.lose {
			f.lose = false
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		reply(upid)
	}
}

func fixture(t *testing.T) (*server, *fakePVE) {
	t.Helper()
	f := &fakePVE{snaps: map[int]map[string]bool{10100: {}, 10200: {}}, power: map[int]string{10100: "stopped", 10200: "stopped"},
		tasks: map[string]*fakeTask{}, auth: "PVEAPIToken=root@pam!carrel-snapshot=secret"}
	ts := httptest.NewTLSServer(http.HandlerFunc(f.handler))
	t.Cleanup(ts.Close)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STATE_DIRECTORY", state)
	t.Setenv("CARREL_PVE_URL", ts.URL)
	t.Setenv("CARREL_PVE_TOKEN", f.auth)
	t.Setenv("CARREL_PVE_NODE", "pve")
	t.Setenv("CARREL_PVE_CA", ca)
	s := newServer()
	if s.problem != "" {
		t.Fatal(s.problem)
	}
	return s, f
}

func start(s *server, key, op string, params string, power string) (*pluginpb.Operation, error) {
	return s.StartOperation(context.Background(), &pluginpb.StartRequest{IdempotencyKey: key, Operation: op, Params: params,
		Reservation: "snapshot/snapshot/10100/s1", Machine: `{"vmid":10100,"kind":"vm","power_state":"` + power + `"}`})
}

func get(t *testing.T, s *server, key string) *pluginpb.Operation {
	t.Helper()
	op, err := s.GetOperation(context.Background(), &pluginpb.GetRequest{IdempotencyKey: key})
	if err != nil {
		t.Fatal(err)
	}
	return op
}

const take = `{"machine":"10100","name":"s1"}`

// A create, a rollback and a delete each run one PVE task, followed by its
// UPID; a second start under the same key starts nothing more.
func TestTheOperationsRunPVETasks(t *testing.T) {
	s, f := fixture(t)
	op, err := start(s, "k1", "create", take, "running")
	if err != nil || op.Task == "" {
		t.Fatalf("create: %v %v", op, err)
	}
	if op = get(t, s, "k1"); op.State != "succeeded" || !f.snaps[10100]["s1"] {
		t.Fatalf("create: %v", op)
	}
	if op, _ = start(s, "k1", "create", take, "running"); op.State != "succeeded" || f.sent != 1 {
		t.Fatalf("replay: %v, sent %d", op, f.sent)
	}
	if _, err := start(s, "k2", "rollback", `{"machine":"10100","name":"s1","confirm":"s1"}`, "running"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a rollback of a running machine: %v", err)
	}
	if op, err = start(s, "k3", "rollback", `{"machine":"10100","name":"s1","confirm":"s1"}`, "stopped"); err != nil || get(t, s, "k3").State != "succeeded" {
		t.Fatalf("rollback: %v %v", op, err)
	}
	if op, err = start(s, "k4", "delete", take, "stopped"); err != nil || get(t, s, "k4").State != "succeeded" || f.snaps[10100]["s1"] {
		t.Fatalf("delete: %v %v", op, err)
	}
	if f.sent != 3 {
		t.Fatalf("sent %d", f.sent)
	}
}

// What PVE shows decides: a snapshot that is there is not taken again, and
// one that is not there cannot be deleted, which carrel takes as proof.
func TestPVEStateDecides(t *testing.T) {
	s, f := fixture(t)
	f.snaps[10100]["s1"] = true
	if _, err := start(s, "k1", "create", take, "running"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("an existing name: %v", err)
	}
	delete(f.snaps[10100], "s1")
	op, err := start(s, "k2", "delete", take, "running")
	if err != nil || op.State != "failed" || op.ErrorCode != "not_found" || f.sent != 0 {
		t.Fatalf("a missing snapshot: %v %v", op, err)
	}
	// PVE refuses the request and starts nothing: the start is refused.
	f.refuse = "VM is locked (backup)"
	if _, err := start(s, "k3", "create", take, "running"); status.Code(err) != codes.FailedPrecondition || f.snaps[10100]["s1"] {
		t.Fatalf("a refused request: %v", err)
	}
	// A task that fails leaves the run failed, with PVE's reason.
	f.exit = "snapshot feature is not available"
	op, err = start(s, "k4", "create", take, "running")
	if err != nil {
		t.Fatal(err)
	}
	if op = get(t, s, "k4"); op.State != "failed" || !strings.Contains(op.Error, "not available") {
		t.Fatalf("a failed task: %v", op)
	}
}

// A start whose answer is lost leaves no UPID: the plugin finds the task by
// its type and time, also after a restart, and never sends it twice.
func TestALostAnswerIsFoundAgainAfterARestart(t *testing.T) {
	s, f := fixture(t)
	f.lose, f.hold = true, true
	op, err := start(s, "k1", "create", take, "running")
	if err != nil || op.State != "running" || op.Task == "" {
		t.Fatalf("lost: %v %v", op, err)
	}
	// The plugin died before it saved the UPID.
	r, _ := s.runs.load("k1")
	r.UPID = ""
	if err := s.runs.save(r); err != nil {
		t.Fatal(err)
	}
	restarted := newServer()
	if op = get(t, restarted, "k1"); op.State != "running" || op.Task == "" {
		t.Fatalf("after the restart: %v", op)
	}
	f.mu.Lock()
	f.hold = false
	f.mu.Unlock()
	if op = get(t, restarted, "k1"); op.State != "succeeded" || f.sent != 1 {
		t.Fatalf("done: %v, sent %d", op, f.sent)
	}
}

// A request that never reached PVE is sent again once it is overdue.
func TestARequestThatNeverArrivedIsSentAgain(t *testing.T) {
	s, f := fixture(t)
	r := &run{Key: "k1", Operation: "create", Kind: "vm", VMID: 10100, Name: "s1", SentAt: time.Now().Add(-time.Minute).Unix()}
	if err := s.runs.save(r); err != nil {
		t.Fatal(err)
	}
	if op := get(t, s, "k1"); f.sent != 1 || op.State == "failed" {
		t.Fatalf("resent: %v, sent %d", op, f.sent)
	}
	if op := get(t, s, "k1"); op.State != "succeeded" {
		t.Fatalf("done: %v", op)
	}
}

// Every start is checked before anything is sent.
func TestAStartIsCheckedFirst(t *testing.T) {
	s, f := fixture(t)
	for name, req := range map[string]*pluginpb.StartRequest{
		"no reservation":  {IdempotencyKey: "a", Operation: "create", Params: take, Machine: `{"vmid":10100,"kind":"vm"}`},
		"another machine": {IdempotencyKey: "b", Operation: "create", Params: take, Reservation: "r", Machine: `{"vmid":10200,"kind":"vm"}`},
		"bad name":        {IdempotencyKey: "c", Operation: "create", Params: `{"machine":"10100","name":"A1"}`, Reservation: "r", Machine: `{"vmid":10100,"kind":"vm"}`},
		"one character":   {IdempotencyKey: "h", Operation: "create", Params: `{"machine":"10100","name":"a"}`, Reservation: "r", Machine: `{"vmid":10100,"kind":"vm"}`},
		"bad confirm": {IdempotencyKey: "d", Operation: "rollback", Params: `{"machine":"10100","name":"s1","confirm":"s2"}`, Reservation: "r",
			Machine: `{"vmid":10100,"kind":"vm","power_state":"stopped"}`},
		"no power state": {IdempotencyKey: "e", Operation: "rollback", Params: `{"machine":"10100","name":"s1","confirm":"s1"}`, Reservation: "r",
			Machine: `{"vmid":10100,"kind":"vm"}`},
		"bad kind": {IdempotencyKey: "f", Operation: "create", Params: take, Reservation: "r", Machine: `{"vmid":10100,"kind":"pod"}`},
	} {
		if _, err := s.StartOperation(context.Background(), req); status.Code(err) != codes.InvalidArgument && status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A dry run checks and sends nothing.
	op, err := s.StartOperation(context.Background(), &pluginpb.StartRequest{IdempotencyKey: "g", Operation: "create", Params: take, DryRun: true,
		Machine: `{"vmid":10100,"kind":"vm"}`})
	if err != nil || op.State != "succeeded" || f.sent != 0 {
		t.Fatalf("dry run: %v %v", op, err)
	}
	if _, err := s.GetOperation(context.Background(), &pluginpb.GetRequest{IdempotencyKey: "g"}); status.Code(err) != codes.NotFound {
		t.Fatalf("a dry run was kept: %v", err)
	}
}

// Without its token the plugin says why, and starts nothing.
func TestAPluginWithoutItsTokenSaysWhy(t *testing.T) {
	t.Setenv("STATE_DIRECTORY", t.TempDir())
	t.Setenv("CARREL_PVE_TOKEN", "")
	s := newServer()
	p, _ := s.Probe(context.Background(), &pluginpb.ProbeRequest{})
	if p.Supported || !strings.Contains(p.Reason, "CARREL_PVE_TOKEN") {
		t.Fatalf("probe: %v", p)
	}
	if _, err := start(s, "k", "create", take, "running"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start: %v", err)
	}
}

// A task still running when its lost answer is overdue is found, not sent
// again.
func TestARunningTaskIsNotSentAgain(t *testing.T) {
	s, f := fixture(t)
	resendAfter = 0
	t.Cleanup(func() { resendAfter = 30 * time.Second })
	f.lose, f.hold = true, true
	if _, err := start(s, "k1", "create", take, "running"); err != nil {
		t.Fatal(err)
	}
	r, _ := s.runs.load("k1")
	r.UPID = ""
	if err := s.runs.save(r); err != nil {
		t.Fatal(err)
	}
	if op := get(t, newServer(), "k1"); op.State != "running" || op.Task == "" || f.sent != 1 {
		t.Fatalf("overdue: %v, sent %d", op, f.sent)
	}
}

// An earlier task on the same guest is not taken for the run's: a delete
// whose answer was lost and whose task failed is failed, though the delete
// before it succeeded.
func TestAnEarlierTaskIsNotTheRuns(t *testing.T) {
	s, f := fixture(t)
	f.snaps[10100]["s1"], f.snaps[10100]["s2"] = true, true
	if _, err := start(s, "k1", "delete", take, "running"); err != nil || get(t, s, "k1").State != "succeeded" {
		t.Fatalf("first delete: %v", err)
	}
	f.lose, f.exit = true, "snapshot is locked"
	if _, err := start(s, "k2", "delete", `{"machine":"10100","name":"s2"}`, "running"); err != nil {
		t.Fatal(err)
	}
	r, _ := s.runs.load("k2")
	r.UPID = ""
	if err := s.runs.save(r); err != nil {
		t.Fatal(err)
	}
	if op := get(t, newServer(), "k2"); op.State != "failed" || !f.snaps[10100]["s2"] {
		t.Fatalf("second delete: %v", op)
	}
}
