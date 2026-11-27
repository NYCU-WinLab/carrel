package carrel

// Plugin objects (#663): what a plugin operation creates on a machine, such
// as a disk snapshot, carrel keeps a record of, so that quota, admission and
// the core actions that must not run over it (freeze, migrate, drain,
// backfill, delete) read it at once, as they read carrel's own rows. The
// record is generic: a plugin declares its object kinds, what each charges
// and what each holds, and its operations name the kind and the effect.
//
// The record is reserved, and the tenant charged, before the plugin starts,
// under the writer, so a concurrent call sees it. It is dropped only on
// proof that the object does not exist: a first start the agent or the
// plugin refused, or a delete the plugin answers not_found. Any other failure
// keeps it charged and holding; a delete clears it. A record keeps the holds
// it was made with, so it holds while its plugin is not reported.

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"time"
)

// pluginObjectRows is the store kind of plugin object records.
const pluginObjectRows = "plugin_objects"

// pluginQuotaRows keeps, in the site table, the quota dimensions of every
// plugin that has charged a tenant, so their limits hold while the plugin is
// not reported.
const pluginQuotaRows = "plugin_quota"

var (
	pluginHolds   = []string{"freeze", "migrate", "backfill", "delete"}
	pluginEffects = []string{"create", "delete", "use", "list"}
	// pluginPer are the machine facts a charge may be counted per.
	pluginPer = []string{"", "cpu", "memory_mb", "disk_gb"}
)

// MaxPluginObjectName bounds the name a caller gives an object.
const MaxPluginObjectName = 64

type pluginObject struct {
	ID     string             `json:"id"`
	Plugin string             `json:"plugin"`
	Kind   string             `json:"kind"`
	Name   string             `json:"name"`
	VMID   int                `json:"vmid"`
	State  string             `json:"state"`
	Charge map[string]float64 `json:"charge,omitempty"`
	Holds  []string           `json:"holds,omitempty"`
	// DiskGB is what the object may hold on its node's storage.
	DiskGB      int    `json:"disk_gb,omitempty"`
	OperationID string `json:"operation_id,omitempty"`
	// Run is the plugin run key the record was made for: only that run's
	// refused first start proves the object was never made.
	Run string `json:"run,omitempty"`
	// Spec is the declaration the record was charged and holds by
	// (PluginOperationSpec).
	Spec string `json:"spec,omitempty"`
	// DeletingBy is the delete operation that holds the object now, and Was
	// the state it had before, which a refused delete gives back.
	DeletingBy string `json:"deleting_by,omitempty"`
	Was        string `json:"was,omitempty"`
	// Configuration is the machine's resources and NICs when a disk object
	// was made: a rewind to it is refused once they changed.
	Configuration D `json:"configuration,omitempty"`
}

// diskConfiguration is what a disk rewind must find unchanged. iso_volume: a
// rewind brings the guest's ide2 back, so the record must match.
func diskConfiguration(m D) D { return pick(m, "cpu", "memory_mb", "disk_gb", "nics", "iso_volume") }

// titled is s with its first letter in upper case.
func titled(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// pluginObjectView is a record as a member sees it.
func pluginObjectView(o pluginObject) D {
	v := D{"id": fmt.Sprintf("%d-%s", o.VMID, o.Name), "vmid": o.VMID, "name": o.Name, "disk_gb": o.DiskGB}
	if o.Configuration != nil {
		v["configuration"] = o.Configuration
	}
	if o.OperationID != "" {
		v["operation_id"] = o.OperationID
	}
	if o.State != "" {
		v["state"] = o.State
	}
	return v
}

// pluginResultKeys are the keys carrel adds to an object operation's result
// for kind: the record, the list and the storage. A kind whose keys would be
// one of carrel's own cannot be declared.
func pluginResultKeys(kind string) []string { return []string{kind, kind + "s", kind + "_storage"} }

func (k PluginObjectKind) holds(action string) bool { return slices.Contains(k.Holds, action) }

func (pl PluginInfo) kind(name string) (PluginObjectKind, bool) {
	for _, k := range pl.Objects {
		if k.Name == name {
			return k, true
		}
	}
	return PluginObjectKind{}, false
}

// pluginObjectProblem says why an operation's object declaration cannot be
// a tool, or "".
func pluginObjectProblem(pl PluginInfo, op PluginOperation) string {
	if op.ObjectKind == "" && op.ObjectEffect == "" && op.ObjectParam == "" {
		return ""
	}
	k, ok := pl.kind(op.ObjectKind)
	if !ok {
		return fmt.Sprintf("object kind %q is not one the plugin declares", op.ObjectKind)
	}
	if !slices.Contains(pluginEffects, op.ObjectEffect) {
		return fmt.Sprintf("object effect %q is not create, delete, use or list", op.ObjectEffect)
	}
	if op.ReadOnly && op.ObjectEffect != "use" && op.ObjectEffect != "list" {
		return "a read_only operation cannot create or delete an object"
	}
	for _, key := range pluginResultKeys(k.Name) {
		if slices.Contains(pluginReserved, key) || slices.Contains(pluginCarrelKeys, key) {
			return fmt.Sprintf("object kind %s would name the result key %s, which is carrel's", k.Name, key)
		}
	}
	var s map[string]any
	_ = json.Unmarshal(op.Params, &s)
	props, _ := s["properties"].(map[string]any)
	required, _ := s["required"].([]any)
	if op.ObjectEffect == "list" {
		if !op.ReadOnly || op.ObjectParam != "" || op.Rewinds || op.Stopped {
			return "a list of objects is read_only and names no object_param"
		}
	} else if param, _ := props[op.ObjectParam].(map[string]any); op.ObjectParam == "machine" || param == nil || param["type"] != "string" || !contains(required, op.ObjectParam) {
		return fmt.Sprintf("object_param %q must be a required string parameter other than machine", op.ObjectParam)
	}
	if _, ok := props["machine"]; !ok || !contains(required, "machine") {
		return `an operation on an object must require a top-level "machine"`
	}
	for _, h := range k.Holds {
		if !slices.Contains(pluginHolds, h) {
			return fmt.Sprintf("object kind %s holds %q, not one of freeze, migrate, backfill and delete", k.Name, h)
		}
	}
	declared := map[string]bool{}
	for _, q := range pl.Quota {
		if _, core := DefaultQuota[q.Name]; core {
			return fmt.Sprintf("quota dimension %s is one carrel counts itself", q.Name)
		}
		declared[q.Name] = true
	}
	for _, c := range k.Charges {
		if !declared[c.Dimension] {
			return fmt.Sprintf("object kind %s charges %s, which the plugin does not declare", k.Name, c.Dimension)
		}
		if !slices.Contains(pluginPer, c.Per) {
			return fmt.Sprintf("object kind %s charges per %q, not cpu, memory_mb or disk_gb", k.Name, c.Per)
		}
	}
	return ""
}

// pluginObjectSpec is what a tool's object declaration is on one node: two
// nodes that declare it differently do not run the same tool.
func pluginObjectSpec(pl PluginInfo, op PluginOperation) string { return PluginOperationSpec(pl, op) }

// PluginOperationSpec is a digest of what carrel does around an operation:
// its object declaration (the kind with its charges, holds and disk, the
// effect, the parameter and the plugin's dimensions) and whether it stops
// the guest or rewinds its disk; "" for an operation with none of these.
// The control plane sends the one it acted by with the start, and the agent
// starts only a plugin that declares the same now.
func PluginOperationSpec(pl PluginInfo, op PluginOperation) string {
	if op.ObjectKind == "" && op.ObjectEffect == "" && op.ObjectParam == "" && !op.Stopped && !op.Rewinds {
		return ""
	}
	k, _ := pl.kind(op.ObjectKind)
	return digest(string(encoded(D{"op": []string{op.ObjectKind, op.ObjectEffect, op.ObjectParam}, "kind": k, "quota": pl.Quota,
		"stopped": op.Stopped, "rewinds": op.Rewinds})))
}

// pluginPowerProblem says why an operation's power declaration cannot be a
// tool, or "".
func pluginPowerProblem(op PluginOperation) string {
	if !op.Stopped && !op.Rewinds {
		return ""
	}
	if op.Rewinds && !op.Stopped {
		return "an operation that rewinds the disk must also declare stopped"
	}
	if op.ReadOnly {
		return "a read_only operation cannot stop the machine"
	}
	var s map[string]any
	_ = json.Unmarshal(op.Params, &s)
	props, _ := s["properties"].(map[string]any)
	required, _ := s["required"].([]any)
	if _, ok := props["machine"]; !ok || !contains(required, "machine") {
		return `an operation that stops the machine must require a top-level "machine"`
	}
	return ""
}

// pluginInfo is the plugin as one node reports it, supported.
func (p *Platform) pluginInfo(node, plugin string) (PluginInfo, bool) {
	for _, pl := range p.Hub.Plugins(node, time.Now()) {
		if pl.Name == plugin && pl.Supported {
			return pl, true
		}
	}
	return PluginInfo{}, false
}

// pluginDims are the plugin quota dimensions carrel knows: those kept since a
// plugin charged a tenant, then those a node reports now.
func (e *Execution) pluginDims() map[string]PluginQuota {
	out := map[string]PluginQuota{}
	for _, r := range e.S.SiteRows(pluginQuotaRows) {
		out[str(r["name"])] = PluginQuota{Name: str(r["name"]), DefaultLimit: num(r["default_limit"]), Unit: str(r["unit"]), Measured: boolean(r["measured"])}
	}
	now := time.Now()
	for _, n := range e.P.Config.Nodes {
		for _, pl := range e.P.Hub.Plugins(n.Name, now) {
			if !pl.Supported {
				continue
			}
			for _, q := range pl.Quota {
				if _, core := DefaultQuota[q.Name]; !core && pluginDimension.MatchString(q.Name) {
					out[q.Name] = q
				}
			}
		}
	}
	return out
}

// pluginCharge is what one object of kind k on machine m charges.
func pluginCharge(k PluginObjectKind, m D) D {
	out := D{}
	for _, c := range k.Charges {
		v := c.Amount
		if c.Per != "" {
			v *= num(m[c.Per])
		}
		out[c.Dimension] = math.Round((num(out[c.Dimension])+v)*100) / 100
	}
	return out
}

func pluginObjectID(plugin, kind string, vmid any, name string) string {
	return fmt.Sprintf("%s/%s/%d/%s", plugin, kind, integer(vmid), name)
}

// planPluginObject checks an object operation against the record, the quota
// and the node, and changes nothing. It returns the record's id, the record
// if there is one, and what a create charges the record.
func (e *Execution) planPluginObject(pl PluginInfo, op PluginOperation, a, t, m D) (string, *pluginObject, D) {
	name := str(a[op.ObjectParam])
	if name == "" || WireLen(name) > MaxPluginObjectName {
		fail("invalid", fmt.Sprintf("%s must name the %s in at most %d bytes", op.ObjectParam, op.ObjectKind, MaxPluginObjectName))
	}
	k, _ := pl.kind(op.ObjectKind)
	if m["resize_from"] != nil && (k.Disk && op.ObjectEffect == "create" || op.Rewinds) {
		fail("conflict", fmt.Sprintf("Finish the pending machine_resize before %s operations", op.ObjectKind), D{"recovery": "resolve_prerequisite"})
	}
	id := pluginObjectID(pl.Name, op.ObjectKind, m["vmid"], name)
	row, found := rowOf[pluginObject](e.S, pluginObjectRows, id)
	ours := func(owner string) bool { return e.Op != nil && owner == str(e.Op["id"]) }
	switch op.ObjectEffect {
	case "create":
		if found {
			if ours(row.OperationID) {
				// A retry runs on the record it made, so only under the
				// declaration that record holds by.
				if row.Spec != PluginOperationSpec(pl, op) {
					fail("conflict", fmt.Sprintf("Plugin %s now declares a %s otherwise than when this operation reserved it; delete the %s, then create it again", pl.Name, op.ObjectKind, op.ObjectKind),
						D{"recovery": "revise_request"})
				}
				return id, &row, nil
			}
			fail("conflict", titled(op.ObjectKind)+" exists", D{"recovery": "revise_request", "state": row.State})
		}
		charge := pluginCharge(k, m)
		q := e.Quota(t, e.pluginDelta(integer(t["n"]), charge))
		// A measured dimension holds nothing new yet, so there is no size to
		// check: a tenant already over its limit gets no more.
		measured, _ := e.measuredNow(integer(t["n"]))
		for _, d := range slices.Sorted(maps.Keys(charge)) {
			if used, limit := obj(q["used"])[d], obj(q["limit"])[d]; measured[d] && num(used) > num(limit) {
				over := D{"dimension": d, "used": used, "limit": limit}
				fail("quota_exceeded", "Tenant quota would be exceeded", merge(over, D{"violations": []D{over}, "quota_after": q}))
			}
		}
		if k.Disk {
			e.Admission(e.P.nodeOf(m), 0, 0, num(m["disk_gb"]), nil, true)
		}
		return id, nil, charge
	case "delete":
		if !found {
			fail("not_found", titled(op.ObjectKind)+" not found")
		}
	default:
		if !found {
			fail("not_found", titled(op.ObjectKind)+" not found")
		}
		if row.State != "ready" {
			fail("conflict", fmt.Sprintf("The %s %s is %s", op.ObjectKind, name, row.State), D{"recovery": "resolve_prerequisite"})
		}
		// A record with no configuration cannot show the machine unchanged.
		if op.Rewinds && (row.Configuration == nil || !equal(row.Configuration, diskConfiguration(m))) {
			fail("conflict", fmt.Sprintf("Resources or NICs changed since this %s; administrator review required", op.ObjectKind))
		}
	}
	return id, &row, nil
}

// reservePluginObject records the object before the plugin starts: a create
// as creating and charged, a delete as deleting. It runs under the writer.
func (e *Execution) reservePluginObject(pl PluginInfo, op PluginOperation, a, t, m D) {
	plug := obj(e.Op["plugin"])
	id, row, charge := e.planPluginObject(pl, op, a, t, m)
	plug["object"], plug["object_effect"], plug["object_kind"], plug["object_name"] = id, op.ObjectEffect, op.ObjectKind, a[op.ObjectParam]
	plug["operation_spec"] = PluginOperationSpec(pl, op)
	n := integer(t["n"])
	k, _ := pl.kind(op.ObjectKind)
	plug["object_dims"] = pluginKindDims(k)
	if plug["quota_before"] == nil {
		// The quota before the first run changed anything: the result's
		// delta is counted from it, as a core action's is.
		plug["quota_before"] = e.Quota(t)
	}
	switch {
	case op.ObjectEffect == "create" && row == nil:
		for _, q := range pl.Quota {
			e.S.SitePut(pluginQuotaRows, q.Name, D{"name": q.Name, "default_limit": q.DefaultLimit, "unit": q.Unit, "measured": q.Measured, "plugin": pl.Name})
		}
		rec := pluginObject{ID: id, Plugin: pl.Name, Kind: op.ObjectKind, Name: str(a[op.ObjectParam]), VMID: integer(m["vmid"]),
			State: "creating", Holds: k.Holds, Run: str(plug["key"]), Spec: PluginOperationSpec(pl, op)}
		for d, v := range charge {
			if rec.Charge == nil {
				rec.Charge = map[string]float64{}
			}
			rec.Charge[d] = num(v)
		}
		if k.Disk {
			rec.DiskGB, rec.Configuration = integer(m["disk_gb"]), diskConfiguration(m)
		}
		e.Put(pluginObjectRows, id, n, rec)
	case op.ObjectEffect == "delete":
		// What a member saw last, for the result once the record is gone.
		plug["object_view"] = pluginObjectView(*row)
		if row.State != "deleting" {
			row.Was = row.State
		}
		row.State, row.DeletingBy = "deleting", str(e.Op["id"])
		e.Put(pluginObjectRows, id, n, *row)
	}
}

// settlePluginObject brings the record in line with how the operation
// ended. It runs under the writer.
func (e *Execution) settlePluginObject(succeeded bool) {
	plug := obj(e.Op["plugin"])
	id := str(plug["object"])
	if id == "" {
		return
	}
	row, ok := rowOf[pluginObject](e.S, pluginObjectRows, id)
	if !ok {
		return
	}
	self := str(e.Op["id"])
	// refused: the first start was refused, or none was sent, so the run
	// never began.
	refused := boolean(plug["refused"]) || !boolean(plug["start_sent"])
	switch plug["object_effect"] {
	case "create":
		if row.OperationID != self || row.State != "creating" {
			return
		}
		if succeeded {
			row.State = "ready"
			e.Put(pluginObjectRows, id, integer(e.Op["tenant_n"]), row)
		} else if refused && row.Run == str(plug["key"]) {
			// A later run refused proves nothing of the run that made the
			// record, which may have left the object.
			e.S.Remove(pluginObjectRows, id)
		}
	case "delete":
		if row.DeletingBy != self {
			return
		}
		if succeeded || plug["plugin_code"] == "not_found" {
			e.S.Remove(pluginObjectRows, id)
		} else if refused {
			row.State, row.DeletingBy, row.Was = row.Was, "", ""
			if row.State == "" {
				row.State = "ready"
			}
			e.Put(pluginObjectRows, id, integer(e.Op["tenant_n"]), row)
		}
	}
}

// pluginObjects are the records of a tenant's machine.
func (e *Execution) pluginObjects(n int, vmid any) []pluginObject {
	out := []pluginObject{}
	for _, o := range rowsOf[pluginObject](e.S, pluginObjectRows, n) {
		if o.VMID == integer(vmid) {
			out = append(out, o)
		}
	}
	return out
}

// pluginHeld are the objects of a machine that hold action.
func (e *Execution) pluginHeld(n int, vmid any, action string) []D {
	out := []D{}
	for _, o := range e.pluginObjects(n, vmid) {
		if slices.Contains(o.Holds, action) {
			out = append(out, D{"plugin": o.Plugin, "kind": o.Kind, "name": o.Name, "state": o.State})
		}
	}
	return out
}

// refusePluginHeld fails an action a machine's plugin objects hold.
func (e *Execution) refusePluginHeld(n int, vmid any, action, verb string) {
	if held := e.pluginHeld(n, vmid, action); len(held) > 0 {
		fail("conflict", fmt.Sprintf("Delete the machine's %s %s first; %s cannot keep it", held[0]["kind"], held[0]["name"], verb),
			D{"recovery": "resolve_prerequisite", "plugin_objects": held})
	}
}

// pluginUsage adds what a tenant's plugin objects charge to used.
func (e *Execution) pluginUsage(n int, used D) {
	for name := range e.pluginDims() {
		if used[name] == nil {
			used[name] = 0
		}
	}
	measured, held := e.measuredNow(n)
	holders := map[string]bool{}
	for _, o := range rowsOf[pluginObject](e.S, pluginObjectRows, n) {
		for d, v := range o.Charge {
			if measured[d] {
				holders[d] = true
				continue
			}
			used[d] = math.Round((num(used[d])+v)*100) / 100
		}
	}
	for d := range holders {
		used[d] = held
	}
}

// heldSample is what a fresh storage sample says the tenant's disk objects
// hold, in GiB, and whether there is one.
func (e *Execution) heldSample(n int) (float64, bool) {
	u, ok := rowOf[storageUsage](e.S, "storage_usage", fmt.Sprint(n))
	// RefreshStorage dates a sample by this clock. One dated ahead of it was
	// not: it would stay fresh for as long as it is ahead.
	age := now() - u.SampledAt
	if !ok || !u.Available || age <= -60 || age >= snapshotSampleMaxAge {
		return 0, false
	}
	return math.Round(float64(u.RetainedSnapshotBytes)/GiB*100) / 100, true
}

// measuredNow are the plugin dimensions a fresh sample counts for tenant n,
// and what it says is held; none without one.
func (e *Execution) measuredNow(n int) (map[string]bool, float64) {
	out := map[string]bool{}
	held, ok := e.heldSample(n)
	if !ok {
		return out, 0
	}
	for name, q := range e.pluginDims() {
		if q.Measured {
			out[name] = true
		}
	}
	return out, held
}

// pluginDelta is what charging charge changes in the quota now: a measured
// dimension holds nothing new until the next sample.
func (e *Execution) pluginDelta(n int, charge D) D {
	measured, _ := e.measuredNow(n)
	out := D{}
	for d, v := range charge {
		if !measured[d] {
			out[d] = v
		}
	}
	return out
}

// pluginFreed is what dropping the records leaving frees now. What a
// measured dimension frees is known only after the next sample, unless they
// are all the tenant's records that charge it.
func (e *Execution) pluginFreed(n int, leaving []pluginObject) D {
	measured, held := e.measuredNow(n)
	gone := map[string]bool{}
	for _, o := range leaving {
		gone[o.ID] = true
	}
	out := D{}
	for _, o := range leaving {
		for _, d := range slices.Sorted(maps.Keys(o.Charge)) {
			if !measured[d] {
				out[d] = math.Round((num(out[d])-o.Charge[d])*100) / 100
			}
		}
	}
	for d := range measured {
		charged, all := false, true
		for _, o := range rowsOf[pluginObject](e.S, pluginObjectRows, n) {
			if _, ok := o.Charge[d]; ok {
				charged = charged || gone[o.ID]
				all = all && gone[o.ID]
			}
		}
		if charged && all {
			out[d] = -held
		}
	}
	return out
}

// pluginKindDims are the dimensions a kind charges.
func pluginKindDims(k PluginObjectKind) []string {
	out := []string{}
	for _, c := range k.Charges {
		if !slices.Contains(out, c.Dimension) {
			out = append(out, c.Dimension)
		}
	}
	return out
}

// objectStorage is the tenant's storage sample, for a kind charged to a
// measured dimension, with what each such dimension counts now: "held" from
// a fresh sample, "declared" without; nil for any other kind.
func (e *Execution) objectStorage(t D, dims []string) D {
	known := e.pluginDims()
	measured := []string{}
	for _, d := range dims {
		if known[d].Measured {
			measured = append(measured, d)
		}
	}
	if len(measured) == 0 {
		return nil
	}
	_, fresh := e.heldSample(integer(t["n"]))
	out := e.storageView(t)
	for _, d := range measured {
		out[d+"_counts"] = map[bool]string{true: "held", false: "declared"}[fresh]
	}
	return out
}

// pluginLimits fills in the default limit of each plugin dimension the
// tenant's quota does not set, and the units.
func (e *Execution) pluginLimits(limit, units D) {
	for name, q := range e.pluginDims() {
		if limit[name] == nil {
			limit[name] = q.DefaultLimit
		}
		if q.Unit != "" && units[name] == nil {
			units[name] = q.Unit
		}
	}
}

// pluginObjectsFreed is what deleting machine m frees of its plugin objects.
func (e *Execution) pluginObjectsFreed(n int, m D, delta D) {
	for d, v := range e.pluginFreed(n, e.pluginObjects(n, m["vmid"])) {
		delta[d] = num(delta[d]) + num(v)
	}
}
