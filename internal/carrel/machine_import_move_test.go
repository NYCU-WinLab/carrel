package carrel

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// importSite sets a platform up with a source and a target, and returns a
// way to run machine_import confirm and wait for the job.
func importSite(t *testing.T) (*Platform, *fakeBackend, func(guest int) D) {
	t.Helper()
	p, b := fixture(t)
	p.Config.SourceDir = t.TempDir()
	p.Config.ImportTargetEndpoint = "target.test:8006"
	p.Config.ImportTargetNode = "carrel01"
	p.Config.ImportTargetTokenID = "carrel@pve!import"
	p.Config.ImportTargetFingerprint = strings.Repeat("AB:", 31) + "AB"
	p.Config = p.Config.WithDefaults()
	if err := os.WriteFile(filepath.Join(p.Config.SourceDir, "_target.secret"), []byte("99999999-2222-3333-4444-555555555555"), 0600); err != nil {
		t.Fatal(err)
	}
	importPoll = time.Millisecond
	p.wg.Add(1)
	go p.Operations.Loop()
	importFailTask, seenForms, importPollErrors, importGuestStatus = "none", nil, 0, nil
	srv, fp, _ := importFake(t)
	admin := person("root", true)
	if r := p.Execute(context.Background(), "source_add", sourceArgs(srv, fp), admin); r["ok"] != true {
		t.Fatalf("source_add: %v", r)
	}
	run := func(guest int) D {
		r := p.Execute(context.Background(), "machine_import", D{"tenant": "alice", "source": "old-lab", "guest": guest, "confirm": true}, admin)
		if r["ok"] != true {
			return r
		}
		t1 := p.Store.TenantN(1)
		op := p.Operations.Wait(context.Background(), t1, str(obj(r["operation"])["id"]), 20)
		for i := 0; i < 400 && !boolean(op["done"]); i++ {
			time.Sleep(10 * time.Millisecond)
			op = publicOperation(p.Store.Get("operations", str(op["id"])))
		}
		return op
	}
	return p, b, run
}

func joined() string { return strings.Join(seenForms, "\n") }

func TestMachineImportConfirmRunningVM(t *testing.T) {
	p, b, run := importSite(t)
	op := run(104)
	if op["state"] != "succeeded" {
		t.Fatalf("operation: %v", op)
	}
	log := joined()
	// The VM shuts down, then the cloud-init disk goes, then it moves offline:
	// its disks are on LVM, so they land on the hop storage, then move to tank.
	for _, want := range []string{"POST /api2/json/nodes/anvil/qemu/104/status/shutdown", "PUT /api2/json/nodes/anvil/qemu/104/config delete=ide2", "POST /api2/json/nodes/anvil/qemu/104/remote_migrate", "target-storage=local", "target-vmid=10100", "target-bridge=t001"} {
		if !strings.Contains(log, want) {
			t.Errorf("missing %q in\n%s", want, log)
		}
	}
	if strings.Index(log, "status/shutdown") > strings.Index(log, "delete=ide2") {
		t.Errorf("the cloud-init disk must go after the shutdown, or the delete stays pending:\n%s", log)
	}
	if strings.Contains(log, "online=1") {
		t.Errorf("a VM must not move online onto the tenant bridge:\n%s", log)
	}
	if obj(op["result"])["stopped_with"] != "qm shutdown" {
		t.Errorf("result: %v", op["result"])
	}
	if strings.Contains(log, "vmbr0") {
		t.Errorf("the guest must not join the node underlay:\n%s", log)
	}
	if strings.Contains(log, "delete=1") || strings.Contains(log, "DELETE ") {
		t.Errorf("the source must not be deleted:\n%s", log)
	}
	if strings.Contains(op["result"].(D)["machine"].(D)["state"].(string), "importing") {
		t.Errorf("result: %v", op["result"])
	}
	m := p.Store.Get("machines", "10100")
	if m == nil || m["state"] != "imported_unverified" || m["node"] != "carrel01" || m["imported"] != true {
		t.Fatalf("machine: %v", m)
	}
	if num((&Execution{P: p, S: p.Store, Ctx: context.Background()}).Usage(p.Store.TenantN(1))["vcpu"]) != 4 {
		t.Errorf("quota not charged")
	}
	finished := 0
	for _, c := range b.calls {
		if c["op"] == "import_finish" {
			finished++
			if c["hop_storage"] != "local" || c["kind"] != "vm" {
				t.Errorf("import_finish: %v", c)
			}
		}
	}
	if finished != 1 {
		t.Errorf("a running VM from LVM moves its volumes off the hop once, got %d", finished)
	}
	if strings.Contains(string(encoded(op)), "99999999-2222") || strings.Contains(string(encoded(p.Store.Get("operations", str(op["id"])))), "99999999-2222") {
		t.Errorf("a secret reached the operation")
	}
}

func TestMachineImportConfirmCTUsesHopAndStop(t *testing.T) {
	p, b, run := importSite(t)
	importFailTask = "status-shutdown"
	// The CT is stopped on the fake source, so make it a running one.
	op := run(106)
	if op["state"] != "succeeded" {
		t.Fatalf("operation: %v", op)
	}
	log := joined()
	for _, want := range []string{"status/shutdown", "status/stop", "target-storage=local"} {
		if !strings.Contains(log, want) && !strings.Contains(strings.Join(seenForms, " "), want) {
			t.Errorf("missing %q in\n%s", want, log)
		}
	}
	if obj(op["result"])["stopped_with"] != "pct stop" {
		t.Errorf("result: %v", op["result"])
	}
	moved := false
	for _, c := range b.calls {
		if c["op"] == "import_finish" && c["hop_storage"] == "local" && integer(c["vmid"]) == 10100 && c["kind"] == "ct" {
			moved = true
		}
	}
	if !moved {
		t.Errorf("no volume move on the target: %v", b.calls)
	}
	_ = p
}

func TestMachineImportConfirmStoppedVMHop(t *testing.T) {
	_, b, run := importSite(t)
	if op := run(107); op["state"] != "succeeded" {
		t.Fatalf("operation: %v", op)
	}
	if !strings.Contains(joined(), "target-storage=local") || strings.Contains(joined(), "online=1") {
		t.Errorf("stopped VM:\n%s", joined())
	}
	moved := false
	for _, c := range b.calls {
		moved = moved || c["op"] == "import_finish" && c["kind"] == "vm"
	}
	if !moved {
		t.Errorf("no volume move: %v", b.calls)
	}
}

func importUsage(p *Platform) D {
	return (&Execution{P: p, S: p.Store, Ctx: context.Background()}).Usage(p.Store.TenantN(1))
}

func TestMachineImportConfirmVMShutdownTimeoutNeverForcesStop(t *testing.T) {
	p, _, run := importSite(t)
	// The VM does not shut down in time: it keeps running on the source.
	importFailTask = "status-shutdown"
	op := run(104)
	if op["state"] != "failed" || obj(op["error"])["backend_code"] != "source_shutdown_timeout" {
		t.Fatalf("operation: %v", op)
	}
	log := joined()
	if strings.Contains(log, "status/stop") {
		t.Errorf("a VM must never be stopped by force:\n%s", log)
	}
	if strings.Contains(log, "remote_migrate") || strings.Contains(log, "delete=ide2") {
		t.Errorf("nothing may change after a failed shutdown:\n%s", log)
	}
	// The shutdown request may still power the VM off: an admin checks it.
	if m := p.Store.Get("machines", "10100"); m == nil || m["state"] != "import_failed" {
		t.Errorf("record: %v", m)
	}
}

func TestMachineImportConfirmVMThatStopsLateContinues(t *testing.T) {
	_, _, run := importSite(t)
	// The shutdown task times out, but the guest powered off meanwhile: its
	// state is read again and the import goes on.
	importFailTask = "status-shutdown"
	importGuestStatus = []string{"running", "stopped"}
	op := run(104)
	if op["state"] != "succeeded" || obj(op["result"])["stopped_with"] != "qm shutdown" {
		t.Fatalf("operation: %v", op)
	}
	if strings.Contains(joined(), "status/stop") {
		t.Errorf("a VM must never be stopped by force:\n%s", joined())
	}
}

func TestMachineImportConfirmAlreadyStoppedGuestIsNotShutDown(t *testing.T) {
	_, _, run := importSite(t)
	// A resumed job, or the owner shut the guest down after the plan.
	importGuestStatus = []string{"stopped"}
	op := run(106)
	if op["state"] != "succeeded" || obj(op["result"])["stopped_with"] != "already stopped" {
		t.Fatalf("operation: %v", op)
	}
	if strings.Contains(joined(), "status/") {
		t.Errorf("no power call was needed:\n%s", joined())
	}
}

func TestMachineImportZFSVMWithLVMCloudInitMovesDirect(t *testing.T) {
	_, _, run := importSite(t)
	// The cloud-init disk is dropped, so only the ZFS disk decides the path.
	op := run(109)
	if op["state"] != "succeeded" {
		t.Fatalf("operation: %v", op)
	}
	if !strings.Contains(joined(), "target-storage=tank") {
		t.Errorf("a ZFS VM must move straight to tank:\n%s", joined())
	}
}

func TestMachineImportConfirmFailedStopKeepsRecord(t *testing.T) {
	p, _, run := importSite(t)
	// Neither pct shutdown nor pct stop finishes. Nothing was sent to
	// migrate, but the source was asked to change, so an admin checks it.
	importFailTask = "status-"
	op := run(106)
	if op["state"] != "failed" {
		t.Fatalf("operation: %v", op)
	}
	if strings.Contains(joined(), "remote_migrate") {
		t.Fatalf("migrated after a failed stop:\n%s", joined())
	}
	if m := p.Store.Get("machines", "10100"); m == nil || m["state"] != "import_failed" {
		t.Errorf("record: %v", m)
	}
	if u := importUsage(p); num(u["machines"]) != 1 {
		t.Errorf("quota released: %v", u)
	}
	if strings.Contains(joined(), "DELETE") {
		t.Errorf("the source was touched destructively")
	}
}

func TestMachineImportConfirmFailureAfterMigrateKeepsRecord(t *testing.T) {
	p, _, run := importSite(t)
	// The migration task fails: the guest may be half on the target, so the
	// VMID and the quota stay held for an admin.
	importFailTask = "remote_migrate"
	op := run(104)
	if op["state"] != "failed" {
		t.Fatalf("operation: %v", op)
	}
	m := p.Store.Get("machines", "10100")
	if m == nil || m["state"] != "import_failed" {
		t.Fatalf("record: %v", m)
	}
	if u := importUsage(p); num(u["vcpu"]) != 4 || num(u["machines"]) != 1 {
		t.Errorf("quota released: %v", u)
	}
	if strings.Contains(joined(), "DELETE") {
		t.Errorf("the source was touched destructively")
	}
	// The same guest is not imported again while that record stands.
	if op := run(104); op["state"] != "failed" || obj(op["error"])["code"] != "conflict" {
		t.Errorf("second import: %v", op)
	}
}

func TestMachineImportConfirmFailedVolumeMoveKeepsRecord(t *testing.T) {
	p, b, run := importSite(t)
	// A failure on the target after the move keeps the record as well.
	b.call = func(r D, _ string) (any, error) {
		if r["op"] == "import_finish" {
			return nil, Failure{D{"ok": false, "error": D{"code": "backend_unavailable", "message": "x"}}}
		}
		if r["op"] == "inventory" {
			return baseInventory(), nil
		}
		return D{"status": "running"}, nil
	}
	importFailTask = "none"
	op := run(107)
	if op["state"] != "failed" {
		t.Fatalf("hop failure: %v", op)
	}
	if m := p.Store.Get("machines", "10100"); m == nil || m["state"] != "import_failed" || obj(m["import"])["failed_at"] != "move_volumes" {
		t.Errorf("record after a failed volume move: %v", m)
	}
}

func TestMachineImportPollErrorIsRetried(t *testing.T) {
	p, _, run := importSite(t)
	// The source answers 500 to a few task reads during the copy.
	importPollErrors = 3
	if op := run(104); op["state"] != "succeeded" {
		t.Fatalf("operation: %v", op)
	}
	if importPollErrors != 0 {
		t.Errorf("the failing reads were not made")
	}
	if m := p.Store.Get("machines", "10100"); m == nil || m["state"] != "imported_unverified" {
		t.Errorf("machine: %v", m)
	}
}

func TestMachineImportResumesSavedTask(t *testing.T) {
	p, _, run := importSite(t)
	importFailTask = "remote_migrate"
	op := run(104)
	raw := p.Store.Get("operations", str(op["id"]))
	job := obj(raw["import"])
	if !strings.HasPrefix(str(job["upid"]), "UPID:") || job["migrate_sent"] != true {
		t.Fatalf("task ID not saved: %v", job)
	}
	// A restarted job polls the saved task and sends nothing new.
	importFailTask, seenForms = "none", nil
	job["migrated"] = nil
	e := p.execution(context.Background())
	e.Op = raw
	if f := attempt(e.PerformMachineImport); f != nil {
		t.Fatalf("resume: %v", f)
	}
	if len(seenForms) != 0 {
		t.Errorf("a resumed job wrote to the source: %v", seenForms)
	}
}

func TestMachineImportPinsTargetNode(t *testing.T) {
	p, _, _ := nodeFixture(t)
	p.Config.SourceDir = t.TempDir()
	srv, fp, _ := importFake(t)
	admin := person("root", true)
	if r := p.Execute(context.Background(), "source_add", sourceArgs(srv, fp), admin); r["ok"] != true {
		t.Fatalf("source_add: %v", r)
	}
	plan := func(guest int) D {
		return p.Execute(context.Background(), "machine_import", D{"tenant": "alice", "source": "old-lab", "guest": guest, "dry_run": true}, admin)
	}
	// Place alone picks carrel02; the endpoint serves carrel01.
	if r := plan(107); obj(obj(obj(r["plan"])["target"]))["node"] != "carrel02" {
		t.Fatalf("unpinned plan: %v", r)
	}
	p.Config.ImportTargetNode = "carrel01"
	if r := plan(107); obj(obj(obj(r["plan"])["target"]))["node"] != "carrel01" {
		t.Errorf("pinned plan: %v", r)
	}
	// No room on the pinned node is a conflict, not another node.
	if r := plan(108); obj(r["error"])["code"] != "conflict" {
		t.Errorf("full node: %v", r)
	}
	p.Store.SitePut("node", "carrel01", D{"drained": true})
	if r := plan(107); obj(r["error"])["code"] != "conflict" {
		t.Errorf("drained node: %v", r)
	}
	p.Config.ImportTargetNode = "carrel09"
	if r := plan(107); obj(r["error"])["code"] != "invalid" {
		t.Errorf("unknown node: %v", r)
	}
}

func TestMachineImportConfirmRefusals(t *testing.T) {
	p, _, run := importSite(t)
	if r := p.Execute(context.Background(), "machine_import", D{"tenant": "alice", "source": "old-lab", "guest": 104, "confirm": true}, person("alice", false)); r["ok"] == true {
		t.Errorf("non-admin: %v", r)
	}
	p.Config.ImportTargetNode = ""
	if op := run(104); op["state"] != "failed" || len(seenForms) != 0 {
		t.Errorf("no target settings: %v / %v", op, seenForms)
	}
}

func TestMachineImportRefusesGuestsItCannotMoveSafely(t *testing.T) {
	_, _, run := importSite(t)
	for vmid, why := range map[int]string{110: "HA", 111: "protection", 112: "ZFS and on other", 113: "detached disk", 114: "ISO"} {
		seenForms = nil
		op := run(vmid)
		if op["state"] != "failed" || !strings.Contains(str(obj(op["error"])["message"]), why) {
			t.Errorf("guest %d: %v", vmid, op["error"])
		}
		if len(seenForms) != 0 {
			t.Errorf("guest %d: the source was touched:\n%s", vmid, joined())
		}
	}
}

func TestMachineImportGuestStartedAgainIsNotChanged(t *testing.T) {
	p, _, run := importSite(t)
	// The stopped VM was started on the source after the plan.
	importGuestStatus = []string{"running"}
	op := run(107)
	if op["state"] != "failed" || obj(op["error"])["backend_code"] != "source_running" {
		t.Fatalf("operation: %v", op)
	}
	if len(seenForms) != 0 {
		t.Errorf("a running guest was changed:\n%s", joined())
	}
	// Nothing was sent to the source: the record and quota are freed.
	if m := p.Store.Get("machines", "10100"); m != nil {
		t.Errorf("record kept: %v", m)
	}
	if u := importUsage(p); num(u["machines"]) != 0 {
		t.Errorf("quota still reserved: %v", u)
	}
}

func TestMachineImportResumeWaitsForSavedShutdown(t *testing.T) {
	p, _, run := importSite(t)
	importFailTask = "status-shutdown"
	op := run(104)
	raw := p.Store.Get("operations", str(op["id"]))
	job := obj(raw["import"])
	if !strings.HasPrefix(str(job["shutdown_upid"]), "UPID:") || str(job["stopped_with"]) != "" {
		t.Fatalf("shutdown task not saved: %v", job)
	}
	// A restarted job polls the saved shutdown and sends no second one.
	importFailTask, seenForms, importGuestStatus = "none", nil, []string{"stopped"}
	e := p.execution(context.Background())
	e.Op = raw
	if f := attempt(e.PerformMachineImport); f != nil {
		t.Fatalf("resume: %v", f)
	}
	if strings.Contains(joined(), "status/shutdown") {
		t.Errorf("a second shutdown was sent:\n%s", joined())
	}
	if obj(raw["import"])["stopped_with"] != "qm shutdown" {
		t.Errorf("job: %v", raw["import"])
	}
}

func TestMachineImportedGuestCanBeReadAndDeleted(t *testing.T) {
	p, _, run := importSite(t)
	if op := run(104); op["state"] != "succeeded" {
		t.Fatalf("operation: %v", op)
	}
	m := p.Store.Get("machines", "10100")
	if m == nil || m["state"] != "imported_unverified" {
		t.Fatalf("machine: %v", m)
	}
	alice := person("alice", false)
	app := NewApp(p, nil)
	if r := app.Call(context.Background(), "machine_get", D{"machine": str(m["name"])}, alice); r["ok"] != true {
		t.Errorf("machine_get: %v", r)
	}
	if r := app.Call(context.Background(), "machine_delete", D{"machine": str(m["name"]), "confirm": str(m["name"])}, alice); r["ok"] != true {
		t.Errorf("machine_delete: %v", r)
	}
}
