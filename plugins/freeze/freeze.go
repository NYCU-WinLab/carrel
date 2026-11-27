// Package freeze is the freeze plugin: it parks a stopped carrel machine as a
// backup on the site's backup storage and brings it back (#664). The
// plugin declares the operations and the object kind, probes the site and
// runs machine_freeze (#717); machine_thaw does not run yet.
//
// It serves the plugin contract on the socket systemd passes as fd 3, and
// keeps its runs in $STATE_DIRECTORY. The environment names the API, the
// token, the node, the cluster CA and the storage to freeze to:
//
//	CARREL_PVE_URL        https://localhost:8006 unless set
//	CARREL_PVE_TOKEN      PVEAPIToken=<user>!<token>=<secret>
//	CARREL_PVE_NODE       the PVE node name, which can differ from the host name
//	CARREL_PVE_CA         /etc/carrel/plugins/freeze-ca.pem unless set
//	CARREL_BACKUP_STORAGE the backup storage; with none the site cannot freeze
//	CARREL_FREEZE_VERIFY_WAIT seconds to wait for a backup's verification, 1800 unless set
package freeze

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/NYCU-WinLab/carrel/internal/pluginpb"
)

// Version is set at build time.
var Version = "0.0.0-dev"

// noStorage is the reason carrel gives for a site without backup storage.
const noStorage = "The site has no backup storage (backup_storage) to freeze machines to"

type server struct {
	pluginpb.UnimplementedPluginServer
	pve *pve
	// storage is the backup storage, from CARREL_BACKUP_STORAGE.
	storage string
	// problem says why the plugin cannot run here, or "".
	problem string
	// verifyWait is how long to wait for the backup server to verify a backup.
	verifyWait time.Duration
	runs       store
	mu         sync.Mutex
	now        func() time.Time
}

const machineSchema = `"machine":{"type":"string","minLength":1,"maxLength":32}`

// Describe is what the plugin declares. The descriptions and schemas are
// those of machine_freeze and machine_thaw in internal/carrel/contract.json.
func Describe() *pluginpb.DescribeResponse {
	return &pluginpb.DescribeResponse{Name: "freeze", Version: Version, Contract: 1,
		Quota: []*pluginpb.QuotaDimension{{Name: "frozen_gb", DefaultLimit: 200, Unit: "GiB"}},
		Objects: []*pluginpb.ObjectKind{{Name: "frozen", Gone: true,
			Charges: []*pluginpb.Charge{{Dimension: "frozen_gb", Amount: 1, Per: "disk_gb"}}}},
		Operations: []*pluginpb.OperationType{
			{Name: "machine_freeze", Member: true, Toolset: "machines", DryRun: true, Idempotent: true,
				ObjectKind: "frozen", ObjectEffect: "create", ObjectParam: "machine", Stopped: true, Confirm: true,
				Description: "Park a stopped machine: carrel backs it up to the Proxmox Backup Server, verifies the backup and only then removes it from the cluster. " +
					"While frozen it releases vcpu, memory_mb, disk_gb and machines and charges its disk size to frozen_gb; its name, internal address, domains, ports and peers stay. " +
					"Refused unless the machine is shut down, has no disk snapshots, and has released any public IP, fixed public port or special domain it holds. " +
					"A failed or unverified backup leaves the machine untouched. The backup is the only copy: freezing is not an off-site backup. " +
					"confirm must equal the machine name. Bring it back with machine_thaw.",
				ParamsSchema: `{"type":"object","properties":{` + machineSchema + `,"confirm":{"type":"string","pattern":"^[a-z][a-z0-9-]{0,31}$"}},` +
					`"required":["machine","confirm"],"additionalProperties":false}`},
			{Name: "machine_thaw", Member: true, Toolset: "machines", DryRun: true,
				ObjectKind: "frozen", ObjectEffect: "delete", ObjectParam: "machine",
				Description: "Restore a frozen machine from its backup as a new machine with the same name and internal address. " +
					"Checks the normal quota like machine_create and fails with quota_exceeded when it is short; the machine comes back stopped, start it with machine_power. " +
					"Its backup is deleted and its frozen_gb released.",
				ParamsSchema: `{"type":"object","properties":{` + machineSchema + `},"required":["machine"],"additionalProperties":false}`},
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
	// A token that signs in but lacks a privilege fails only when a member
	// uses it: the probe says so first.
	missing, err := s.pve.missing(ctx, s.storage)
	if err != nil {
		return &pluginpb.ProbeResponse{Reason: "the token's permissions cannot be read: " + err.Error()}, nil
	}
	if len(missing) > 0 {
		return &pluginpb.ProbeResponse{Reason: "the token lacks " + strings.Join(missing, ", ")}, nil
	}
	return &pluginpb.ProbeResponse{Supported: true}, nil
}

// taskWindow is how far before a request, in seconds, the tasks it may be
// told apart from are looked for: PVE dates a task by its start second.
const taskWindow = 5

// resendAfter is how long a start request whose answer was lost may take to
// show as a task, before it is sent again.
var resendAfter = 30 * time.Second

// defaultVerifyWait is how long the plugin waits for the backup server to
// verify a new backup, unless CARREL_FREEZE_VERIFY_WAIT says otherwise.
const defaultVerifyWait = 1800 * time.Second

var keyPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

func refuse(code codes.Code, format string, a ...any) error { return status.Errorf(code, format, a...) }

func done(key, state string) *pluginpb.Operation {
	return &pluginpb.Operation{IdempotencyKey: key, State: state, Done: true, Result: "{}"}
}

// parse checks a start of machine_freeze and returns the machine's VMID and kind.
func parse(req *pluginpb.StartRequest) (vmid int, kind string, err error) {
	var params struct {
		Machine string `json:"machine"`
	}
	var machine struct {
		VMID int    `json:"vmid"`
		Kind string `json:"kind"`
	}
	if req.Operation != "machine_freeze" {
		return 0, "", refuse(codes.InvalidArgument, "no operation %q", req.Operation)
	}
	if json.Unmarshal([]byte(req.Params), &params) != nil || json.Unmarshal([]byte(req.Machine), &machine) != nil {
		return 0, "", refuse(codes.InvalidArgument, "params and machine must be JSON objects")
	}
	// carrel sends the machine's facts; the params name it by VMID.
	if machine.VMID <= 0 || params.Machine != strconv.Itoa(machine.VMID) {
		return 0, "", refuse(codes.InvalidArgument, "the machine's facts do not name the machine of the params")
	}
	if kinds[machine.Kind] == "" {
		return 0, "", refuse(codes.InvalidArgument, "machine kind %q is not vm or ct", machine.Kind)
	}
	if !req.DryRun {
		if req.Reservation == "" {
			return 0, "", refuse(codes.InvalidArgument, "a freeze needs carrel's reservation")
		}
		if !keyPattern.MatchString(req.IdempotencyKey) {
			return 0, "", refuse(codes.InvalidArgument, "a freeze needs an idempotency key of letters, digits and _.:-")
		}
	}
	return machine.VMID, machine.Kind, nil
}

func (s *server) StartOperation(ctx context.Context, req *pluginpb.StartRequest) (*pluginpb.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runs.dir == "" {
		return nil, refuse(codes.Unavailable, "%s", s.problem)
	}
	// A key it knows is answered before any check: carrel takes a refusal
	// of a key it sent before as proof that no run of it goes on.
	if !req.DryRun && req.IdempotencyKey != "" {
		if old, err := s.runs.load(req.IdempotencyKey); err != nil {
			return nil, refuse(codes.Unavailable, "read the run: %v", err)
		} else if old != nil {
			if old.Operation != req.Operation {
				return nil, refuse(codes.InvalidArgument, "the idempotency key names another operation")
			}
			if s.problem != "" {
				return nil, refuse(codes.Unavailable, "%s", s.problem)
			}
			return s.answer(ctx, old), nil
		}
	}
	if s.problem != "" {
		return nil, refuse(codes.FailedPrecondition, "%s", s.problem)
	}
	vmid, kind, err := parse(req)
	if err != nil {
		return nil, err
	}
	// Checked before anything is sent: a refusal proves nothing ran.
	power, err := s.pve.status(ctx, kind, vmid)
	if err != nil {
		return nil, refuse(codes.Unavailable, "read the machine's power: %v", err)
	}
	if power != "stopped" {
		return nil, refuse(codes.FailedPrecondition, "the machine is %s; shut it down before freezing it", power)
	}
	snaps, err := s.pve.snapshots(ctx, kind, vmid)
	if err != nil {
		return nil, refuse(codes.Unavailable, "list the snapshots: %v", err)
	}
	if snaps > 0 {
		return nil, refuse(codes.FailedPrecondition, "the machine has disk snapshots; a machine with snapshots does not freeze")
	}
	if req.DryRun {
		return done(req.IdempotencyKey, "succeeded"), nil
	}
	r := &run{Key: req.IdempotencyKey, Operation: req.Operation, Kind: kind, VMID: vmid,
		Phase: "backup", Storage: s.storage, Note: "carrel-freeze " + req.IdempotencyKey}
	if err := s.prove(ctx, r); err != nil {
		return nil, refuse(codes.Unavailable, "%v", err)
	}
	if err := s.launch(ctx, r); err != nil {
		var api *apiError
		if !errors.As(err, &api) {
			return nil, refuse(codes.Unavailable, "%v", err)
		}
		// PVE refused the request and started no task: nothing ran.
		s.fail(r, "PVE refused the backup: "+api.Error())
		if err := s.runs.save(r); err != nil {
			return nil, refuse(codes.Unavailable, "save the run: %v", err)
		}
	}
	return s.answer(ctx, r), nil
}

// launch saves the run, then starts the task of its phase and saves the
// UPID. A request whose answer is lost leaves no UPID: follow finds the task
// or sends again. An *apiError says PVE refused the request.
func (s *server) launch(ctx context.Context, r *run) error {
	now := s.now().Unix()
	// The tasks already there are told apart from the one this sends.
	before, err := s.pve.tasks(ctx, taskType(r), r.VMID, now-taskWindow)
	if err != nil {
		return fmt.Errorf("list the guest's tasks: %w", err)
	}
	r.SentAt, r.Before, r.UPID, r.Ambiguous = now, before, "", false
	if err := s.runs.save(r); err != nil {
		return fmt.Errorf("save the run: %w", err)
	}
	id, err := s.pve.start(ctx, r)
	var api *apiError
	switch {
	case errors.As(err, &api):
		return err
	case err != nil:
		slog.Warn("freeze_start_unanswered", "key", r.Key, "error", err)
	default:
		r.UPID = id
	}
	if err := s.runs.save(r); err != nil {
		slog.Warn("freeze_run_not_saved", "key", r.Key, "error", err)
	}
	return nil
}

// prove clears the machine's onboot, so a node reboot does not start it
// during the wait, then records its config digest and its newest start
// before the backup is sent: a start or a config change after this point
// differs from them (the node agent's freeze stamp).
func (s *server) prove(ctx context.Context, r *run) error {
	_, onboot, err := s.pve.config(ctx, r.Kind, r.VMID)
	if err != nil {
		return fmt.Errorf("read the machine's config: %w", err)
	}
	if onboot {
		if err := s.pve.noOnboot(ctx, r.Kind, r.VMID); err != nil {
			return fmt.Errorf("clear the machine's onboot: %w", err)
		}
	}
	digest, _, err := s.pve.config(ctx, r.Kind, r.VMID)
	if err != nil {
		return fmt.Errorf("read the machine's config: %w", err)
	}
	started, err := s.pve.lastStart(ctx, r.Kind, r.VMID)
	if err != nil {
		return fmt.Errorf("list the machine's starts: %w", err)
	}
	if digest == "" {
		return errors.New("PVE gave the machine's config no digest")
	}
	r.Digest, r.Started = digest, started
	return nil
}

// unchanged says whether the machine is provably as the backup holds it:
// stopped, with the config digest and the newest start of the proof. An
// error says nothing either way.
func (s *server) unchanged(ctx context.Context, r *run) (bool, error) {
	power, err := s.pve.status(ctx, r.Kind, r.VMID)
	if err != nil {
		return false, err
	}
	digest, _, err := s.pve.config(ctx, r.Kind, r.VMID)
	if err != nil {
		return false, err
	}
	started, err := s.pve.lastStart(ctx, r.Kind, r.VMID)
	if err != nil {
		return false, err
	}
	return power == "stopped" && r.Digest != "" && digest == r.Digest && started == r.Started, nil
}

// changed is the message of a run whose machine changed after the backup.
const changed = "the machine changed while it was backed up; the backup was removed"

func (s *server) fail(r *run, message string) {
	r.Done, r.State, r.Error = true, "failed", message
}

// answer is the run as an operation, after it learns what it can of the task.
func (s *server) answer(ctx context.Context, r *run) *pluginpb.Operation {
	if !r.Done {
		s.follow(ctx, r)
	}
	op := &pluginpb.Operation{IdempotencyKey: r.Key, State: "running", Task: r.UPID, Message: r.Phase}
	if !r.Done && r.UPID == "" && r.Ambiguous {
		op.Message = "more than one PVE task could be this run's; a person must look at the guest's tasks"
	}
	if r.Done {
		op.State, op.Done, op.Error, op.ErrorCode, op.Message, op.Result = r.State, true, r.Error, r.ErrorCode, "", "{}"
		if r.State == "succeeded" {
			// The machine is gone from the cluster; the backup is its only copy.
			res, _ := json.Marshal(map[string]any{"gone": true, "backup": map[string]any{"volid": r.Volid, "size": r.Size, "note": r.Note, "verification": "ok"}})
			op.Result = string(res)
		}
	}
	return op
}

// follow moves the run as far as PVE shows it can go.
func (s *server) follow(ctx context.Context, r *run) {
	before, _ := json.Marshal(r)
	defer func() {
		if after, _ := json.Marshal(r); string(after) != string(before) {
			if err := s.runs.save(r); err != nil {
				slog.Warn("freeze_run_not_saved", "key", r.Key, "error", err)
			}
		}
	}()
	for !r.Done {
		var again bool
		switch r.Phase {
		case "backup":
			again = s.followBackup(ctx, r)
		case "verify":
			again = s.followVerify(ctx, r)
		case "destroy":
			again = s.followDestroy(ctx, r)
		default:
			s.fail(r, "the run is in no known phase")
		}
		if !again {
			return
		}
	}
}

// taskEnd learns whether the task of the run's phase has ended, and how.
// known is false while the task is not found or its state cannot be read.
func (s *server) taskEnd(ctx context.Context, r *run) (known bool, exit string) {
	if r.UPID == "" {
		// The start was sent, and its answer lost.
		found, err := s.pve.tasks(ctx, taskType(r), r.VMID, r.SentAt-taskWindow)
		if err != nil {
			return false, ""
		}
		fresh := []string{}
		for _, id := range found {
			if !slices.Contains(r.Before, id) {
				fresh = append(fresh, id)
			}
		}
		switch {
		case len(fresh) == 1:
			r.UPID = fresh[0]
		case len(fresh) > 1:
			// Which is the run's is unknown: it stays running until a person looks.
			slog.Warn("freeze_run_ambiguous", "key", r.Key, "tasks", len(fresh))
			r.Ambiguous = true
			return false, ""
		case s.now().Sub(time.Unix(r.SentAt, 0)) >= resendAfter:
			var api *apiError
			if err := s.launch(ctx, r); errors.As(err, &api) {
				// Refused now; the first request never started a task.
				s.fail(r, "PVE refused the "+r.Phase+": "+api.Error())
			}
			return false, ""
		default:
			return false, ""
		}
	}
	ended, exit, err := s.pve.taskStatus(ctx, r.UPID)
	if err != nil || !ended {
		return false, ""
	}
	return true, exit
}

func (s *server) followBackup(ctx context.Context, r *run) bool {
	known, exit := s.taskEnd(ctx, r)
	if !known || r.Done {
		return false
	}
	if exit != "OK" {
		s.abort(ctx, r, "the PVE backup task failed: "+exit)
		return false
	}
	r.Phase, r.UPID, r.Before, r.SentAt = "verify", "", nil, 0
	r.VerifyBy = s.now().Add(s.verifyWait).Unix()
	return true
}

// followVerify waits for the backup server to verify the backup, protects
// it, and starts the removal of the machine.
func (s *server) followVerify(ctx context.Context, r *run) bool {
	b, err := s.pve.backupOf(ctx, r.Storage, r.VMID, r.Note)
	if err != nil {
		slog.Warn("freeze_backup_unreadable", "key", r.Key, "error", err)
		return false
	}
	if b == nil {
		s.abort(ctx, r, "the backup is not on the storage; the machine is unchanged")
		return false
	}
	overdue := s.now().Unix() >= r.VerifyBy
	switch b.Verification.State {
	case "failed":
		s.abort(ctx, r, "the backup failed its verification and was removed; the machine is unchanged")
		return false
	case "ok":
	default:
		if overdue {
			s.abort(ctx, r, "the backup was not verified in time; it was removed and the machine is unchanged")
		}
		return false
	}
	// The wait can take minutes: the machine must be what the backup holds.
	// A start and a stop in the wait leave it stopped, so power is not enough.
	if same, err := s.unchanged(ctx, r); err != nil {
		return false
	} else if !same {
		s.abort(ctx, r, changed)
		return false
	}
	if b.Protected == 0 {
		if err := s.pve.protect(ctx, r.Storage, b.Volid, true); err != nil {
			slog.Warn("freeze_protect_failed", "key", r.Key, "error", err)
			if overdue {
				s.abort(ctx, r, "the backup could not be protected; it was removed and the machine is unchanged")
			}
			return false
		}
		// Protecting can wait on the server too: the same check once more.
		if same, err := s.unchanged(ctx, r); err != nil {
			return false
		} else if !same {
			s.abort(ctx, r, changed)
			return false
		}
	}
	if b.Size <= 0 || !backupVolume.MatchString(b.Volid) {
		s.abort(ctx, r, "the backup could not be verified; the machine is unchanged")
		return false
	}
	r.Volid, r.Size = b.Volid, b.Size
	r.Phase, r.UPID, r.Before, r.SentAt = "destroy", "", nil, 0
	return true
}

// followDestroy removes the machine from the cluster. A failure here keeps
// the backup: a half removed machine leaves it the only whole copy.
func (s *server) followDestroy(ctx context.Context, r *run) bool {
	if r.UPID == "" && r.SentAt == 0 {
		exists, err := s.pve.exists(ctx, r.Kind, r.VMID)
		if err != nil {
			return false
		}
		if !exists {
			r.Done, r.State = true, "succeeded"
			return false
		}
		// Nothing is removed yet: the last chance to see a change.
		if same, err := s.unchanged(ctx, r); err != nil {
			return false
		} else if !same {
			s.abort(ctx, r, changed)
			return false
		}
		var api *apiError
		if err := s.launch(ctx, r); errors.As(err, &api) {
			// Nothing was removed: the backup is not needed.
			s.abort(ctx, r, "PVE refused to remove the machine: "+api.Error())
		}
		return false
	}
	known, exit := s.taskEnd(ctx, r)
	if !known || r.Done {
		return false
	}
	exists, err := s.pve.exists(ctx, r.Kind, r.VMID)
	if err != nil {
		return false
	}
	if exists {
		s.fail(r, "the machine was not removed ("+exit+"); the backup "+r.Volid+" is kept")
		return false
	}
	r.Done, r.State = true, "succeeded"
	return false
}

// abort ends the run as failed and removes the backup it made, if any: the
// machine is as it was.
func (s *server) abort(ctx context.Context, r *run, message string) {
	if b, err := s.pve.backupOf(ctx, r.Storage, r.VMID, r.Note); err != nil {
		message += "; the backup could not be looked up"
	} else if b != nil {
		if err := s.pve.removeBackup(ctx, r.Storage, b); err != nil {
			message += "; the backup " + b.Volid + " could not be removed: " + err.Error()
		}
	}
	s.fail(r, message)
}

func (s *server) GetOperation(ctx context.Context, req *pluginpb.GetRequest) (*pluginpb.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runs.dir == "" {
		return nil, refuse(codes.Unavailable, "%s", s.problem)
	}
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

// Cancel stops a freeze that has not begun to remove the machine, and
// removes its backup: the machine stays as it was. Once the removal has
// started it cannot be undone, and Cancel answers how the run stands.
func (s *server) Cancel(ctx context.Context, req *pluginpb.CancelRequest) (*pluginpb.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runs.dir == "" {
		return nil, refuse(codes.Unavailable, "%s", s.problem)
	}
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
	if !r.Done && r.Phase != "destroy" {
		if r.UPID != "" {
			if ended, _, err := s.pve.taskStatus(ctx, r.UPID); err == nil && !ended {
				if err := s.pve.stopTask(ctx, r.UPID); err != nil {
					return nil, refuse(codes.Unavailable, "stop the backup task: %v", err)
				}
			}
		}
		s.abort(ctx, r, "cancelled")
		r.State = "cancelled"
		if err := s.runs.save(r); err != nil {
			return nil, refuse(codes.Unavailable, "save the run: %v", err)
		}
	}
	return s.answer(ctx, r), nil
}

// NewServer reads the environment. A plugin that cannot run here still
// answers Describe, and says why in Probe.
func NewServer() pluginpb.PluginServer { return newServer() }

func newServer() *server {
	s := &server{runs: store{dir: os.Getenv("STATE_DIRECTORY")}, now: time.Now,
		storage: strings.TrimSpace(os.Getenv("CARREL_BACKUP_STORAGE")), verifyWait: defaultVerifyWait}
	if v := strings.TrimSpace(os.Getenv("CARREL_FREEZE_VERIFY_WAIT")); v != "" {
		// Seconds; at most an hour, as the node agent bounded it.
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 3600 {
			s.problem = "CARREL_FREEZE_VERIFY_WAIT must be a number of seconds from 0 to 3600"
		} else {
			s.verifyWait = time.Duration(n) * time.Second
		}
	}
	base := os.Getenv("CARREL_PVE_URL")
	if base == "" {
		base = "https://localhost:8006"
	}
	ca := os.Getenv("CARREL_PVE_CA")
	if ca == "" {
		ca = "/etc/carrel/plugins/freeze-ca.pem"
	}
	token, node := os.Getenv("CARREL_PVE_TOKEN"), os.Getenv("CARREL_PVE_NODE")
	switch {
	case s.problem != "":
	case s.storage == "":
		s.problem = noStorage
	case s.runs.dir == "":
		s.problem = "no STATE_DIRECTORY"
	case token == "" || node == "":
		s.problem = "CARREL_PVE_TOKEN and CARREL_PVE_NODE must be set in /etc/carrel/plugins/freeze.env"
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

var backupVolume = regexp.MustCompile(`^[a-z][a-z0-9_.-]*:backup/[A-Za-z0-9_./:+-]+$`)
