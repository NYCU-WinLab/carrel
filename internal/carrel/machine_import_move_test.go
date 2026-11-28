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
	p.Config.ImportTargetTokenID = "carrel@pve!import"
	p.Config.ImportTargetFingerprint = strings.Repeat("AB:", 31) + "AB"
	p.Config = p.Config.WithDefaults()
	if err := os.WriteFile(filepath.Join(p.Config.SourceDir, "_target.secret"), []byte("99999999-2222-3333-4444-555555555555"), 0600); err != nil {
		t.Fatal(err)
	}
	importPoll = time.Millisecond
	p.wg.Add(1)
	go p.Operations.Loop()
	importFailTask, seenForms = "none", nil
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
	// The cloud-init disk goes, the VM moves online straight to tank.
	for _, want := range []string{"PUT /api2/json/nodes/anvil/qemu/104/config delete=ide2", "POST /api2/json/nodes/anvil/qemu/104/remote_migrate", "online=1", "target-storage=tank", "target-vmid=10100", "target-bridge=vmbr0"} {
		if !strings.Contains(log, want) {
			t.Errorf("missing %q in\n%s", want, log)
		}
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
	for _, c := range b.calls {
		if c["op"] == "import_finish" {
			t.Errorf("an online VM needs no volume move: %v", c)
		}
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

func TestMachineImportConfirmFailureRollsBack(t *testing.T) {
	p, b, run := importSite(t)
	importFailTask = "remote_migrate"
	op := run(104)
	if op["state"] != "failed" {
		t.Fatalf("operation: %v", op)
	}
	if m := p.Store.Get("machines", "10100"); m != nil {
		t.Errorf("record kept: %v", m)
	}
	if num((&Execution{P: p, S: p.Store, Ctx: context.Background()}).Usage(p.Store.TenantN(1))["vcpu"]) != 0 || num((&Execution{P: p, S: p.Store, Ctx: context.Background()}).Usage(p.Store.TenantN(1))["machines"]) != 0 {
		t.Errorf("quota still reserved: %v", (&Execution{P: p, S: p.Store, Ctx: context.Background()}).Usage(p.Store.TenantN(1)))
	}
	if strings.Contains(joined(), "DELETE") {
		t.Errorf("the source was touched destructively")
	}

	// A failure on the target after the move rolls back as well.
	b.call = func(r D, _ string) (any, error) {
		if r["op"] == "import_finish" {
			return nil, Failure{D{"ok": false, "error": D{"code": "backend_unavailable", "message": "x"}}}
		}
		return nil, nil
	}
	importFailTask = "none"
	if op := run(107); op["state"] != "failed" {
		t.Fatalf("hop failure: %v", op)
	}
	if p.Store.Get("machines", "10100") != nil {
		t.Errorf("record kept after a failed volume move")
	}
}

func TestMachineImportConfirmRefusals(t *testing.T) {
	p, _, run := importSite(t)
	if r := p.Execute(context.Background(), "machine_import", D{"tenant": "alice", "source": "old-lab", "guest": 104, "confirm": true}, person("alice", false)); r["ok"] == true {
		t.Errorf("non-admin: %v", r)
	}
	p.Config.ImportTargetEndpoint = ""
	if op := run(104); op["state"] != "failed" || len(seenForms) != 0 {
		t.Errorf("no target settings: %v / %v", op, seenForms)
	}
}
