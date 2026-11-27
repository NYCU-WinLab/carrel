// Package snapshot is the snapshot plugin: it takes, deletes and rolls back disk snapshots of carrel
// machines on one Proxmox VE node, through the PVE HTTP API (#663). carrel
// keeps the record of each snapshot, charges the tenant and stops the guest
// around a rollback; the plugin starts the PVE task and follows it.
//
// It serves the plugin contract on the socket systemd passes as fd 3, and
// keeps each run in $STATE_DIRECTORY under its idempotency key, with the
// task's UPID: a plugin that restarts finds the task again (#563 found that
// a CLI task dies with its caller). The environment names the API, the
// token, the node and the cluster CA:
//
//	CARREL_PVE_URL    https://localhost:8006 unless set
//	CARREL_PVE_TOKEN  PVEAPIToken=<user>!<token>=<secret>
//	CARREL_PVE_NODE   the PVE node name, which can differ from the host name
//	CARREL_PVE_CA     /etc/carrel/plugins/snapshot-ca.pem unless set
package snapshot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/NYCU-WinLab/carrel/internal/pluginpb"
)

// Version is set at build time.
var Version = "0.0.0-dev"

// resendAfter is how long a start request whose answer was lost may take to
// show as a task, before it is sent again.
var resendAfter = 30 * time.Second

// snapshotName is carrel's name rule, at least 2 characters: PVE refuses a
// one-character snapshot name (pve-configid).
var snapshotName = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

type server struct {
	pluginpb.UnimplementedPluginServer
	pve *pve
	// problem says why the plugin cannot run here, or "".
	problem string
	runs    store
	// mu serializes the calls: each is a few short API requests.
	mu  sync.Mutex
	now func() time.Time
}

const machineSchema = `"machine":{"type":"string"}`
const nameSchema = `"name":{"type":"string","pattern":"^[a-z][a-z0-9-]{1,31}$"}`

// Describe is what the plugin declares.
func Describe() *pluginpb.DescribeResponse {
	object := func(op *pluginpb.OperationType, effect string) *pluginpb.OperationType {
		op.ObjectKind, op.ObjectEffect, op.Member, op.Toolset = "snapshot", effect, true, "machines"
		if effect != "list" {
			op.ObjectParam = "name"
		}
		return op
	}
	return &pluginpb.DescribeResponse{Name: "snapshot", Version: Version, Contract: 1,
		Quota: []*pluginpb.QuotaDimension{
			{Name: "snapshots", DefaultLimit: 4},
			{Name: "snapshot_gb", DefaultLimit: 200, Unit: "GiB", Measured: true},
		},
		Objects: []*pluginpb.ObjectKind{{Name: "snapshot", Disk: true, Holds: []string{"freeze", "migrate", "backfill"},
			Charges: []*pluginpb.Charge{{Dimension: "snapshots", Amount: 1}, {Dimension: "snapshot_gb", Amount: 1, Per: "disk_gb"}}}},
		Operations: []*pluginpb.OperationType{
			object(&pluginpb.OperationType{Name: "create", DryRun: true, Idempotent: true,
				Description:  "Take a disk snapshot of a machine. It counts against the tenant's snapshots and snapshot_gb quota.",
				ParamsSchema: `{"type":"object","properties":{` + machineSchema + `,` + nameSchema + `},"required":["machine","name"],"additionalProperties":false}`}, "create"),
			object(&pluginpb.OperationType{Name: "delete", DryRun: true, Destructive: true, Idempotent: true,
				Description:  "Delete a disk snapshot of a machine.",
				ParamsSchema: `{"type":"object","properties":{` + machineSchema + `,` + nameSchema + `},"required":["machine","name"],"additionalProperties":false}`}, "delete"),
			object(&pluginpb.OperationType{Name: "rollback", DryRun: true, Destructive: true, Stopped: true, Rewinds: true, Confirm: true,
				Description: "Roll a machine's disk back to a snapshot. A running machine is shut down and started again; confirm repeats the snapshot name.",
				ParamsSchema: `{"type":"object","properties":{` + machineSchema + `,` + nameSchema + `,"confirm":{"type":"string","pattern":"^[a-z][a-z0-9-]{1,31}$"}},` +
					`"required":["machine","name","confirm"],"additionalProperties":false}`}, "use"),
			object(&pluginpb.OperationType{Name: "list", ReadOnly: true,
				Description:  "List a machine's disk snapshots.",
				ParamsSchema: `{"type":"object","properties":{` + machineSchema + `},"required":["machine"],"additionalProperties":false}`}, "list"),
		}}
}

func (s *server) Describe(context.Context, *pluginpb.DescribeRequest) (*pluginpb.DescribeResponse, error) {
	return Describe(), nil
}

func (s *server) Probe(ctx context.Context, _ *pluginpb.ProbeRequest) (*pluginpb.ProbeResponse, error) {
	if s.problem != "" {
		return &pluginpb.ProbeResponse{Reason: s.problem}, nil
	}
	if err := s.pve.version(ctx); err != nil {
		return &pluginpb.ProbeResponse{Reason: "the PVE API does not answer: " + err.Error()}, nil
	}
	return &pluginpb.ProbeResponse{Supported: true}, nil
}

// request is a start, checked.
type request struct {
	op, kind, name, power string
	vmid                  int
}

func refuse(code codes.Code, format string, a ...any) error { return status.Errorf(code, format, a...) }

func parse(req *pluginpb.StartRequest) (request, error) {
	var params struct {
		Machine string `json:"machine"`
		Name    string `json:"name"`
		Confirm string `json:"confirm"`
	}
	var machine struct {
		VMID       int    `json:"vmid"`
		Kind       string `json:"kind"`
		PowerState string `json:"power_state"`
	}
	r := request{op: req.Operation}
	if !map[string]bool{"create": true, "delete": true, "rollback": true, "list": true}[r.op] {
		return r, refuse(codes.InvalidArgument, "no operation %q", r.op)
	}
	if json.Unmarshal([]byte(req.Params), &params) != nil || json.Unmarshal([]byte(req.Machine), &machine) != nil {
		return r, refuse(codes.InvalidArgument, "params and machine must be JSON objects")
	}
	// carrel sends the machine's facts; the params name it by VMID.
	if machine.VMID <= 0 || params.Machine != strconv.Itoa(machine.VMID) {
		return r, refuse(codes.InvalidArgument, "the machine's facts do not name the machine of the params")
	}
	if _, ok := taskTypes[machine.Kind]; !ok {
		return r, refuse(codes.InvalidArgument, "machine kind %q is not vm or ct", machine.Kind)
	}
	r.kind, r.vmid, r.name, r.power = machine.Kind, machine.VMID, params.Name, machine.PowerState
	if r.op == "list" {
		return r, nil
	}
	if !snapshotName.MatchString(r.name) {
		return r, refuse(codes.InvalidArgument, "name must match %s", snapshotName)
	}
	if r.op == "rollback" && params.Confirm != r.name {
		return r, refuse(codes.InvalidArgument, "confirm must equal snapshot name")
	}
	// carrel reserves the record first; an agent built before the field
	// drops it, and the count would be wrong.
	if !req.DryRun && req.Reservation == "" {
		return r, refuse(codes.InvalidArgument, "an operation on a snapshot needs carrel's reservation")
	}
	// An older agent sends no power state: the guest may be running.
	if r.op == "rollback" && !req.DryRun && r.power != "stopped" {
		return r, refuse(codes.FailedPrecondition, "a rollback runs on a stopped machine")
	}
	return r, nil
}

func done(key, state string) *pluginpb.Operation {
	return &pluginpb.Operation{IdempotencyKey: key, State: state, Done: true, Result: "{}"}
}

func (s *server) StartOperation(ctx context.Context, req *pluginpb.StartRequest) (*pluginpb.Operation, error) {
	if s.problem != "" {
		return nil, refuse(codes.FailedPrecondition, "%s", s.problem)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := parse(req)
	if err != nil {
		return nil, err
	}
	if req.DryRun {
		return done(req.IdempotencyKey, "succeeded"), nil
	}
	if r.op == "list" {
		// A read: it proves the API answers for the guest.
		if _, err := s.pve.snapshots(ctx, r.kind, r.vmid); err != nil {
			return nil, refuse(codes.Unavailable, "list the snapshots: %v", err)
		}
		return done(req.IdempotencyKey, "succeeded"), nil
	}
	if old, err := s.runs.load(req.IdempotencyKey); err != nil {
		return nil, refuse(codes.Unavailable, "read the run: %v", err)
	} else if old != nil {
		if old.Operation != r.op || old.Kind != r.kind || old.VMID != r.vmid || old.Name != r.name {
			return nil, refuse(codes.InvalidArgument, "the idempotency key names another operation")
		}
		return s.answer(ctx, old), nil
	}
	// Checked before anything is sent: a refusal proves nothing ran.
	snaps, err := s.pve.snapshots(ctx, r.kind, r.vmid)
	if err != nil {
		return nil, refuse(codes.Unavailable, "list the snapshots: %v", err)
	}
	run := &run{Key: req.IdempotencyKey, Operation: r.op, Kind: r.kind, VMID: r.vmid, Name: r.name}
	switch {
	case r.op == "create" && snaps[r.name]:
		return nil, refuse(codes.FailedPrecondition, "the machine already has a snapshot named %s", r.name)
	case r.op != "create" && !snaps[r.name]:
		// PVE says it is not there: proof for carrel to drop its record.
		run.Done, run.State, run.ErrorCode, run.Error = true, "failed", "not_found", "Snapshot not found"
		if err := s.runs.save(run); err != nil {
			return nil, refuse(codes.Unavailable, "save the run: %v", err)
		}
		return s.answer(ctx, run), nil
	case r.op == "rollback":
		if power, err := s.pve.status(ctx, r.kind, r.vmid); err != nil {
			return nil, refuse(codes.Unavailable, "read the machine's power: %v", err)
		} else if power != "stopped" {
			return nil, refuse(codes.FailedPrecondition, "the machine is %s; a rollback runs on a stopped machine", power)
		}
	}
	refused, err := s.send(ctx, run)
	if err != nil {
		return nil, refuse(codes.Unavailable, "%v", err)
	}
	if refused {
		// PVE refused the first request and started no task: nothing ran.
		return nil, refuse(codes.FailedPrecondition, "%s", run.Error)
	}
	return s.answer(ctx, run), nil
}

// send saves the run, then starts its task and saves the UPID. A request
// whose answer is lost leaves no UPID: answer finds the task or sends again.
// refused: PVE answered the request with an error and the guest shows it
// did nothing. An error: the run could not be saved, and nothing was sent.
func (s *server) send(ctx context.Context, r *run) (refused bool, err error) {
	r.SentAt = s.now().Unix()
	if err := s.runs.save(r); err != nil {
		return false, fmt.Errorf("save the run: %w", err)
	}
	upid, err := s.pve.start(ctx, r.Operation, r.Kind, r.VMID, r.Name)
	var api *apiError
	switch {
	case errors.As(err, &api):
		s.settle(ctx, r, api.Error())
		refused = r.Done && r.State == "failed"
	case err != nil:
		slog.Warn("snapshot_start_unanswered", "key", r.Key, "error", err)
	default:
		r.UPID = upid
	}
	if err := s.runs.save(r); err != nil {
		slog.Warn("snapshot_run_not_saved", "key", r.Key, "error", err)
	}
	return refused, nil
}

// settle ends a run whose task failed or was refused, by what the guest
// shows now: a snapshot that is there was taken, one that is gone was
// deleted, whatever the task said.
func (s *server) settle(ctx context.Context, r *run, reason string) {
	snaps, err := s.pve.snapshots(ctx, r.Kind, r.VMID)
	if err != nil {
		// Unknown: asked again on the next call.
		return
	}
	r.Done = true
	switch {
	case r.Operation == "create" && snaps[r.Name], r.Operation == "delete" && !snaps[r.Name]:
		r.State, r.Error = "succeeded", ""
	default:
		r.State, r.Error = "failed", reason
	}
}

// answer is the run as an operation, after it learns what it can of the task.
func (s *server) answer(ctx context.Context, r *run) *pluginpb.Operation {
	if !r.Done {
		s.follow(ctx, r)
	}
	op := &pluginpb.Operation{IdempotencyKey: r.Key, State: "running", Task: r.UPID}
	if r.Done {
		op.State, op.Done, op.Error, op.ErrorCode, op.Result = r.State, true, r.Error, r.ErrorCode, "{}"
	}
	return op
}

// follow learns how far the run's task got.
func (s *server) follow(ctx context.Context, r *run) {
	before := *r
	defer func() {
		if *r != before {
			if err := s.runs.save(r); err != nil {
				slog.Warn("snapshot_run_not_saved", "key", r.Key, "error", err)
			}
		}
	}()
	if r.UPID == "" {
		// The start was sent, or was about to be, and its answer lost.
		upid, err := s.pve.findTask(ctx, r.Operation, r.Kind, r.VMID, r.SentAt-2)
		if err != nil {
			return
		}
		if upid == "" {
			if s.now().Sub(time.Unix(r.SentAt, 0)) >= resendAfter {
				// A refusal now says nothing of the first request: settle
				// has judged it by what the guest shows.
				_, _ = s.send(ctx, r)
			}
			return
		}
		r.UPID = upid
	}
	ended, exit, err := s.pve.taskStatus(ctx, r.UPID)
	if err != nil || !ended {
		return
	}
	if exit == "OK" {
		r.Done, r.State = true, "succeeded"
		return
	}
	s.settle(ctx, r, "the PVE task failed: "+exit)
}

func (s *server) GetOperation(ctx context.Context, req *pluginpb.GetRequest) (*pluginpb.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.runs.load(req.IdempotencyKey)
	if err != nil {
		return nil, refuse(codes.Unavailable, "read the run: %v", err)
	}
	if r == nil {
		return nil, refuse(codes.NotFound, "no run under this idempotency key")
	}
	if s.problem != "" {
		return &pluginpb.Operation{IdempotencyKey: r.Key, State: "running", Task: r.UPID, Message: s.problem}, nil
	}
	return s.answer(ctx, r), nil
}

// Cancel does not stop a PVE task: a snapshot task is short, and one cut
// off leaves the guest locked. It answers how the run stands.
func (s *server) Cancel(ctx context.Context, req *pluginpb.CancelRequest) (*pluginpb.Operation, error) {
	return s.GetOperation(ctx, &pluginpb.GetRequest{IdempotencyKey: req.IdempotencyKey})
}

// NewServer reads the environment. A plugin that cannot run here still
// answers Describe, and says why in Probe.
func NewServer() pluginpb.PluginServer { return newServer() }

func newServer() *server {
	s := &server{runs: store{dir: os.Getenv("STATE_DIRECTORY")}, now: time.Now}
	base := os.Getenv("CARREL_PVE_URL")
	if base == "" {
		base = "https://localhost:8006"
	}
	ca := os.Getenv("CARREL_PVE_CA")
	if ca == "" {
		ca = "/etc/carrel/plugins/snapshot-ca.pem"
	}
	token, node := os.Getenv("CARREL_PVE_TOKEN"), os.Getenv("CARREL_PVE_NODE")
	switch {
	case s.runs.dir == "":
		s.problem = "no STATE_DIRECTORY"
	case token == "" || node == "":
		s.problem = "CARREL_PVE_TOKEN and CARREL_PVE_NODE must be set in /etc/carrel/plugins/snapshot.env"
	default:
		p, err := newPVE(base, token, node, ca)
		if err != nil {
			s.problem = err.Error()
		}
		s.pve = p
	}
	return s
}

// Problem says why the server cannot run here, or "".
func Problem(p pluginpb.PluginServer) string {
	if s, ok := p.(*server); ok {
		return s.problem
	}
	return ""
}
