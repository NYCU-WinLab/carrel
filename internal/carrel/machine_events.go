package carrel

import (
	"sort"
	"strconv"
	"strings"
)

// Machine and quota events (#642): a finished machine operation and a
// quota dimension nearing its limit go to the tenant's event log, so a
// member learns of them without polling operation_get or quota_get.

const (
	// quotaWarnAt is the share of a limit that sends quota.warning.
	quotaWarnAt = 0.9
	// quotaClearAt is the share a dimension must fall below before it can
	// warn again, so usage moving around the mark does not repeat it.
	quotaClearAt = 0.8
)

// machineEventTool says whether an operation's outcome is a machine event.
func machineEventTool(tool string) bool {
	return strings.HasPrefix(tool, "machine_") || strings.HasPrefix(tool, "snapshot_") || tool == "deployment_apply"
}

// emitOperationEvents writes the events of an operation that reached a
// terminal state: its outcome, and any quota dimension it pushed past
// quotaWarnAt. saveOutcome sees a terminal state once per run: a failure
// that cleans up first is saved as cleaning_up.
func (e *Execution) emitOperationEvents(op D) bool {
	if !contains(terminal, op["state"]) || !machineEventTool(str(op["tool"])) {
		return false
	}
	n := integer(op["tenant_n"])
	a := obj(op["args"])
	data := D{"operation": op["id"], "tool": op["tool"], "state": op["state"]}
	if name := fallback(a, "machine", a["name"]); name != nil {
		data["machine"] = name
	}
	if m := obj(obj(op["result"])["machine"]); m["name"] != nil {
		data["machine"] = m["name"]
	}
	typ := "machine.operation.succeeded"
	if op["state"] != "succeeded" {
		typ = "machine.operation.failed"
		if err := obj(op["error"]); len(err) > 0 {
			data["error"] = D{"code": err["code"], "message": err["message"]}
		}
	}
	e.emit(n, typ, data)
	e.emitQuotaWarnings(n)
	return true
}

// emitQuotaWarnings sends quota.warning for each dimension at or past
// quotaWarnAt of its limit that has not warned since it last fell below
// quotaClearAt.
func (e *Execution) emitQuotaWarnings(n int) {
	t := e.S.TenantN(n)
	if t == nil {
		return
	}
	var q D
	if attempt(func() { q = e.Quota(t) }) != nil {
		return
	}
	used, limit := obj(q["used"]), obj(q["limit"])
	id := strconv.Itoa(n)
	warned := e.S.SiteGet("quota_warnings", id)
	if warned == nil {
		warned = D{}
	}
	changed := false
	dims := []string{}
	for k := range used {
		dims = append(dims, k)
	}
	sort.Strings(dims)
	for _, k := range dims {
		max := num(limit[k])
		if max <= 0 {
			continue
		}
		share := num(used[k]) / max
		switch {
		case share >= quotaWarnAt && !boolean(warned[k]):
			warned[k] = true
			changed = true
			e.emit(n, "quota.warning", D{"dimension": k, "used": used[k], "limit": limit[k], "unit": obj(q["units"])[k]})
		case share < quotaClearAt && boolean(warned[k]):
			delete(warned, k)
			changed = true
		}
	}
	if changed {
		e.S.SitePut("quota_warnings", id, warned)
	}
}
