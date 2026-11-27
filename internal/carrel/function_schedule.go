package carrel

import (
	"sort"

	"github.com/NYCU-WinLab/carrel/internal/schedule"
)

// function_schedule keeps a function's cron schedules in its record. The
// function's host fires them (internal/fn/scheduler.go); the control plane
// only hands them over with the desired state (#643).
func (e *Execution) functionSchedule(f D, a D, dry bool) D {
	name := str(a["name"])
	kept := []any{}
	found := false
	for _, s := range arr(f["schedules"]) {
		if str(obj(s)["name"]) == name {
			found = true
			continue
		}
		kept = append(kept, s)
	}
	if boolean(a["remove"]) {
		if !found {
			fail("not_found", "The function has no schedule with this name")
		}
	} else {
		s := schedule.Schedule{Name: name, Cron: str(a["cron"]), TimeZone: textAt(a, "time_zone", "UTC"), Path: textAt(a, "path", "/"), Body: str(a["body"])}
		if err := s.Check(); err != nil {
			fail("invalid", err.Error(), D{"recovery": "revise_request"})
		}
		if len(kept) >= schedule.MaxPerFunction {
			fail("conflict", "A function has at most 10 schedules; remove one first")
		}
		entry := D{"name": s.Name, "cron": s.Cron, "time_zone": s.TimeZone, "path": s.Path}
		if s.Body != "" {
			entry["body"] = s.Body
		}
		kept = append(kept, entry)
	}
	sort.Slice(kept, func(i, j int) bool { return str(obj(kept[i])["name"]) < str(obj(kept[j])["name"]) })
	if len(kept) == 0 {
		delete(f, "schedules")
	} else {
		f["schedules"] = kept
	}
	if !dry {
		e.Transaction(func(tx *Execution) {
			tx.Put("functions", f["id"], integer(f["tenant_n"]), f)
			tx.bumpFunctions()
		})
	}
	return D{"dry_run": dry, "function": e.PublicFunction(f)}
}
