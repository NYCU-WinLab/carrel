package carrel

import (
	"sort"

	"github.com/NYCU-WinLab/carrel/internal/schedule"
)

// service_schedule keeps a service's cron schedules in its record. The
// service's host fires them (internal/svc/scheduler.go); the control plane
// only hands them over with the desired state (#643).
func (e *Execution) serviceSchedule(f D, a D, dry bool) D {
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
			fail("not_found", "The service has no schedule with this name")
		}
	} else {
		s := schedule.Schedule{Name: name, Cron: str(a["cron"]), TimeZone: textAt(a, "time_zone", "UTC"), Path: textAt(a, "path", "/"), Body: str(a["body"])}
		if err := s.Check(); err != nil {
			fail("invalid", err.Error(), D{"recovery": "revise_request"})
		}
		if len(kept) >= schedule.MaxPerService {
			fail("conflict", "A service has at most 10 schedules; remove one first")
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
			tx.Put("services", f["id"], integer(f["tenant_n"]), f)
			tx.bumpServices()
		})
	}
	return D{"dry_run": dry, "service": e.PublicService(f)}
}
