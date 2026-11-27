package freeze

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"

	"github.com/NYCU-WinLab/carrel/internal/pluginpb"
)

// freezeNote starts the notes of every backup a freeze makes. The plugin
// removes no backup whose notes do not start with it: the cluster's own
// backups are never its to touch.
const freezeNote = "carrel-freeze "

// sweepAgeSchema bounds the age a sweep removes at: an hour to a year.
const sweepAgeSchema = `"older_than":{"type":"integer","minimum":3600,"maximum":31536000}`

// adminOperations are the operations only an admin may call. They have no
// machine: carrel calls them to delete a frozen machine and to sweep.
func adminOperations() []*pluginpb.OperationType {
	return []*pluginpb.OperationType{
		{Name: "frozen_delete", DryRun: true, Idempotent: true, Destructive: true,
			Description: "Remove the backup of a frozen machine, after carrel has deleted the frozen record. " +
				"With vmid, kind and name it first removes what a cut-off thaw restored under that VMID, if the guest is that machine's half. " +
				"Only a backup whose notes start with carrel-freeze is removed.",
			ParamsSchema: `{"type":"object","properties":{"volid":{"type":"string","minLength":1,"maxLength":256},` +
				`"note":{"type":"string","maxLength":256},"vmid":{"type":"integer","minimum":1},` +
				`"kind":{"type":"string","enum":["vm","ct"]},"name":{"type":"string","minLength":1,"maxLength":63}},` +
				`"required":["volid"],"additionalProperties":false}`},
		{Name: "backup_sweep", DryRun: true, Idempotent: true, Destructive: true,
			Description: "List the freeze backups on the backup storage that no record names: not in keep (notes) and not in keep_volids. " +
				"With older_than (seconds) it also removes the listed ones older than that. A backup whose age is unknown stays.",
			ParamsSchema: `{"type":"object","properties":{"keep":{"type":"array","maxItems":100000,"items":{"type":"string","maxLength":256}},` +
				`"keep_volids":{"type":"array","maxItems":100000,"items":{"type":"string","maxLength":256}},` + sweepAgeSchema + `},"additionalProperties":false}`},
	}
}

// guestState says what a guest of the thaw's VMID is.
type guestState int

const (
	guestAbsent  guestState = iota
	guestWhole              // the machine itself, restored and unlocked
	guestHalf               // a restore that was cut off: locked "create", of this machine or unnamed
	guestForeign            // anything else holds the VMID
)

func (s *server) guestOf(ctx context.Context, kind string, vmid int, name string) (guestState, error) {
	exists, err := s.pve.exists(ctx, kind, vmid)
	if err != nil || !exists {
		return guestAbsent, err
	}
	lock, got, err := s.pve.guestConfig(ctx, kind, vmid)
	if err != nil {
		return guestAbsent, err
	}
	switch {
	case lock == "" && got == name && name != "":
		return guestWhole, nil
	case lock == "create" && (got == "" || got == name):
		return guestHalf, nil
	}
	return guestForeign, nil
}

// ownBackup says whether the notes of a backup are those of a freeze, and
// the record's note when it gave one.
func ownBackup(b *backup, note string) bool {
	notes := strings.TrimSpace(b.Notes)
	return strings.HasPrefix(notes, freezeNote) && (note == "" || notes == note)
}

func (s *server) volumeOK(volid string) error {
	if !backupVolume.MatchString(volid) || strings.SplitN(volid, ":", 2)[0] != s.storage {
		return refuse(codes.InvalidArgument, "the backup volume %q is not on the site's backup storage", volid)
	}
	return nil
}

func (s *server) runKey(req *pluginpb.StartRequest) error {
	if req.DryRun {
		return nil
	}
	if req.Reservation == "" && req.Operation == "machine_thaw" {
		return refuse(codes.InvalidArgument, "a thaw needs carrel's reservation")
	}
	if !keyPattern.MatchString(req.IdempotencyKey) {
		return refuse(codes.InvalidArgument, "%s needs an idempotency key of letters, digits and _.:-", req.Operation)
	}
	return nil
}

// parseThaw reads a start of machine_thaw. carrel sends the frozen record's
// facts: the VMID, the kind, the name and the backup's volume and note.
func (s *server) parseThaw(req *pluginpb.StartRequest) (*run, error) {
	var params struct {
		Machine string `json:"machine"`
	}
	var f struct {
		VMID  int    `json:"vmid"`
		Kind  string `json:"kind"`
		Name  string `json:"name"`
		Volid string `json:"backup_volid"`
		Store string `json:"backup_storage"`
		Note  string `json:"backup_note"`
	}
	if json.Unmarshal([]byte(req.Params), &params) != nil || json.Unmarshal([]byte(req.Machine), &f) != nil {
		return nil, refuse(codes.InvalidArgument, "params and machine must be JSON objects")
	}
	if f.VMID <= 0 || params.Machine != strconv.Itoa(f.VMID) {
		return nil, refuse(codes.InvalidArgument, "the machine's facts do not name the machine of the params")
	}
	if kinds[f.Kind] == "" || f.Name == "" {
		return nil, refuse(codes.InvalidArgument, "a thaw needs the machine's kind (vm or ct) and name")
	}
	if f.Store != "" && f.Store != s.storage {
		return nil, refuse(codes.InvalidArgument, "the backup is on %q, not on the site's backup storage", f.Store)
	}
	if err := s.volumeOK(f.Volid); err != nil {
		return nil, err
	}
	if err := s.runKey(req); err != nil {
		return nil, err
	}
	return &run{Key: req.IdempotencyKey, Operation: req.Operation, Kind: f.Kind, VMID: f.VMID, Name: f.Name,
		Volid: f.Volid, Storage: s.storage, Target: s.guestStorage, Note: strings.TrimSpace(f.Note)}, nil
}

// parseDelete reads a start of frozen_delete.
func (s *server) parseDelete(req *pluginpb.StartRequest) (*run, error) {
	var p struct {
		Volid string `json:"volid"`
		Note  string `json:"note"`
		VMID  int    `json:"vmid"`
		Kind  string `json:"kind"`
		Name  string `json:"name"`
	}
	if json.Unmarshal([]byte(req.Params), &p) != nil {
		return nil, refuse(codes.InvalidArgument, "params must be a JSON object")
	}
	if err := s.volumeOK(p.Volid); err != nil {
		return nil, err
	}
	r := &run{Key: req.IdempotencyKey, Operation: req.Operation, Volid: p.Volid, Storage: s.storage, Note: strings.TrimSpace(p.Note)}
	if p.VMID != 0 || p.Kind != "" || p.Name != "" {
		if p.VMID <= 0 || kinds[p.Kind] == "" || p.Name == "" {
			return nil, refuse(codes.InvalidArgument, "vmid, kind and name go together")
		}
		r.VMID, r.Kind, r.Name, r.Discard = p.VMID, p.Kind, p.Name, true
	}
	if err := s.runKey(req); err != nil {
		return nil, err
	}
	return r, nil
}

// volidVMID is the VMID in a backup volume, such as 10100 in
// pbs:backup/vm/10100/2026-11-27T00:00:00Z, or 0.
func volidVMID(volid string) int {
	parts := strings.Split(strings.SplitN(volid, ":", 2)[1], "/")
	if len(parts) < 3 {
		return 0
	}
	n, _ := strconv.Atoi(parts[2])
	return n
}

// startThaw starts machine_thaw or frozen_delete. Everything is checked
// before anything is sent: a refusal proves nothing ran.
func (s *server) startThaw(ctx context.Context, req *pluginpb.StartRequest) (*pluginpb.Operation, error) {
	var r *run
	var err error
	if req.Operation == "machine_thaw" {
		r, err = s.parseThaw(req)
	} else {
		r, err = s.parseDelete(req)
	}
	if err != nil {
		return nil, err
	}
	backupVMID := volidVMID(r.Volid)
	if backupVMID <= 0 || (req.Operation == "machine_thaw" && backupVMID != r.VMID) {
		return nil, refuse(codes.InvalidArgument, "the backup volume does not belong to the machine")
	}
	b, err := s.pve.backupVolid(ctx, r.Storage, backupVMID, r.Volid)
	if err != nil {
		return nil, refuse(codes.Unavailable, "list the backups: %v", err)
	}
	if b != nil && !ownBackup(b, r.Note) {
		return nil, refuse(codes.FailedPrecondition, "the backup %s is not the backup of a frozen machine", r.Volid)
	}
	state := guestAbsent
	if r.Kind != "" {
		if state, err = s.guestOf(ctx, r.Kind, r.VMID, r.Name); err != nil {
			return nil, refuse(codes.Unavailable, "read the guest: %v", err)
		}
	}
	if req.Operation == "machine_thaw" {
		switch {
		case state == guestForeign:
			return nil, refuse(codes.FailedPrecondition, "the VMID %d is in use by another guest", r.VMID)
		case state == guestWhole && b == nil:
			// A thaw that finished and removed its backup, asked again.
			r.Done, r.State, r.Result = true, "succeeded", thawResult(r, nil)
		case state != guestWhole && b == nil:
			return nil, refuse(codes.FailedPrecondition, "the backup %s is not on the storage", r.Volid)
		case state != guestWhole && b.Verification.State != "ok":
			return nil, refuse(codes.FailedPrecondition, "the backup %s is not verified", r.Volid)
		}
	} else if state == guestForeign || state == guestWhole {
		// A delete removes a cut-off restore, never a machine that came back.
		return nil, refuse(codes.FailedPrecondition, "the VMID %d holds a machine that is not a cut-off restore", r.VMID)
	}
	if req.DryRun {
		return done(req.IdempotencyKey, "succeeded"), nil
	}
	switch {
	case r.Done:
	case state == guestHalf:
		r.Phase = "discard"
	case req.Operation == "machine_thaw" && state == guestAbsent:
		r.Phase = "restore"
	default:
		r.Phase = "remove"
	}
	if r.Phase == "restore" || r.Phase == "discard" {
		if err := s.launch(ctx, r); err != nil {
			var api *apiError
			if !errors.As(err, &api) {
				return nil, refuse(codes.Unavailable, "%v", err)
			}
			// PVE refused the request and started no task: nothing ran.
			s.fail(r, "PVE refused the "+r.Phase+": "+api.Error()+"; the backup is kept")
		}
	}
	if err := s.runs.save(r); err != nil {
		return nil, refuse(codes.Unavailable, "save the run: %v", err)
	}
	return s.answer(ctx, r), nil
}

// thawResult is what a thaw ends with. A backup that could not be removed is
// reported as thaw_backup, so machine_delete can remove it later.
func thawResult(r *run, left *backup) string {
	res := map[string]any{"machine": map[string]any{"vmid": r.VMID, "name": r.Name, "state": "stopped"}, "backup_removed": left == nil}
	if left != nil {
		res["thaw_backup"] = map[string]any{"volid": left.Volid, "note": strings.TrimSpace(left.Notes)}
	}
	raw, _ := json.Marshal(res)
	return string(raw)
}

// followThaw moves a thaw or a delete as far as PVE shows it can go.
func (s *server) followThaw(ctx context.Context, r *run) bool {
	switch r.Phase {
	case "restore":
		return s.followRestore(ctx, r)
	case "discard":
		return s.followDiscard(ctx, r)
	case "remove":
		return s.followRemove(ctx, r)
	}
	s.fail(r, "the run is in no known phase")
	return false
}

// lose ends a thaw that did not restore the machine; the backup is kept.
func (s *server) lose(r *run, message string) {
	s.fail(r, message+"; the backup "+r.Volid+" is kept")
	if r.Cancelled {
		r.State = "cancelled"
	}
}

func (s *server) followRestore(ctx context.Context, r *run) bool {
	known, exit := s.taskEnd(ctx, r)
	if !known || r.Done {
		return false
	}
	if exit == "OK" {
		state, err := s.guestOf(ctx, r.Kind, r.VMID, r.Name)
		if err != nil {
			return false
		}
		if state != guestWhole {
			s.lose(r, "the restore ended but the machine is not there as the backup holds it")
			return false
		}
		r.Phase, r.UPID, r.Before, r.SentAt = "remove", "", nil, 0
		return true
	}
	message := "the PVE restore task failed: " + exit
	if r.Cancelled {
		message = "cancelled"
	}
	state, err := s.guestOf(ctx, r.Kind, r.VMID, r.Name)
	if err != nil {
		return false
	}
	if state != guestHalf {
		s.lose(r, message)
		return false
	}
	// PVE leaves a failed restore locked: take the half away.
	r.Error = message
	r.Phase, r.UPID, r.Before, r.SentAt = "discard", "", nil, 0
	var api *apiError
	if err := s.launch(ctx, r); errors.As(err, &api) {
		s.lose(r, message+"; PVE refused to remove the half restored machine: "+api.Error())
	}
	return false
}

func (s *server) followDiscard(ctx context.Context, r *run) bool {
	known, exit := s.taskEnd(ctx, r)
	if !known || r.Done {
		return false
	}
	state, err := s.guestOf(ctx, r.Kind, r.VMID, r.Name)
	if err != nil {
		return false
	}
	if state != guestAbsent {
		message := "the half restored machine was not removed (" + exit + ")"
		if state == guestHalf {
			// PVE destroys a locked guest only with skiplock, which only
			// root@pam may set, never an API token.
			message += "; it is locked: an admin on the node runs `" + map[string]string{"vm": "qm", "ct": "pct"}[r.Kind] +
				" unlock " + strconv.Itoa(r.VMID) + "` and asks again"
		}
		if r.Error != "" {
			message += "; " + r.Error
		}
		s.lose(r, message)
		return false
	}
	switch {
	case r.Error != "":
		// A restore that failed: its half is gone.
		s.lose(r, r.Error+"; the half restored machine was removed")
		return false
	case r.Operation == "machine_thaw":
		// A cut-off thaw of an earlier run: restore again.
		r.Phase, r.UPID, r.Before, r.SentAt = "restore", "", nil, 0
		var api *apiError
		if err := s.launch(ctx, r); errors.As(err, &api) {
			s.lose(r, "PVE refused the restore: "+api.Error())
			return false
		}
		return false
	}
	r.Phase, r.UPID, r.Before, r.SentAt = "remove", "", nil, 0
	return true
}

// followRemove removes the backup. A thaw has its machine by now, so a backup
// that stays is reported, not failed; a delete fails.
func (s *server) followRemove(ctx context.Context, r *run) bool {
	b, err := s.pve.backupVolid(ctx, r.Storage, volidVMID(r.Volid), r.Volid)
	if err != nil {
		slog.Warn("freeze_backup_unreadable", "key", r.Key, "error", err)
		return false
	}
	if b != nil && !ownBackup(b, r.Note) {
		s.fail(r, "the backup "+r.Volid+" is not the backup of a frozen machine")
		return false
	}
	var left *backup
	var cause string
	if b != nil {
		if err := s.pve.removeBackup(ctx, r.Storage, b); err != nil {
			left, cause = b, err.Error()
		}
	}
	if r.Operation == "machine_thaw" {
		r.Done, r.State, r.Result = true, "succeeded", thawResult(r, left)
		if left != nil {
			slog.Warn("freeze_thaw_backup_kept", "key", r.Key, "volid", left.Volid, "error", cause)
		}
		return false
	}
	if left != nil {
		s.fail(r, "the backup "+r.Volid+" could not be removed: "+cause)
		return false
	}
	res, _ := json.Marshal(map[string]any{"deleted": true, "volid": r.Volid})
	r.Done, r.State, r.Result = true, "succeeded", string(res)
	return false
}

// sweep lists the freeze backups no record names and, with older_than,
// removes those older than that.
func (s *server) sweep(ctx context.Context, req *pluginpb.StartRequest) (*pluginpb.Operation, error) {
	var p struct {
		Keep       []string `json:"keep"`
		KeepVolids []string `json:"keep_volids"`
		OlderThan  int64    `json:"older_than"`
	}
	if json.Unmarshal([]byte(req.Params), &p) != nil {
		return nil, refuse(codes.InvalidArgument, "params must be a JSON object")
	}
	list, err := s.pve.backupList(ctx, s.storage, map[string][]string{"content": {"backup"}})
	if err != nil {
		return nil, refuse(codes.Unavailable, "list the backups: %v", err)
	}
	orphans, removed, failed := []string{}, []string{}, []string{}
	for i := range list {
		b := &list[i]
		notes := strings.TrimSpace(b.Notes)
		if !strings.HasPrefix(notes, freezeNote) || slices.Contains(p.Keep, notes) || slices.Contains(p.KeepVolids, b.Volid) || !backupVolume.MatchString(b.Volid) {
			continue
		}
		orphans = append(orphans, b.Volid)
		// Only a backup whose age is known goes.
		if p.OlderThan > 0 && !req.DryRun && b.CTime > 0 && b.CTime < s.now().Unix()-p.OlderThan {
			if err := s.pve.removeBackup(ctx, s.storage, b); err != nil {
				failed = append(failed, b.Volid)
			} else {
				removed = append(removed, b.Volid)
			}
		}
	}
	res, _ := json.Marshal(map[string]any{"orphans": orphans, "removed": removed, "failed": failed})
	op := done(req.IdempotencyKey, "succeeded")
	op.Result = string(res)
	return op, nil
}
