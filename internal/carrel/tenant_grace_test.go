package carrel

import (
	"context"
	"testing"
	"time"
)

// tenant_list shows the grace start, reason and stop date of a tenant in
// grace, and nulls for one that is not (#861).
func TestTenantListShowsGrace(t *testing.T) {
	p, _ := fixture(t)
	p.Config.AlumniGraceDays = 10
	start := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	p.Store.Exec("UPDATE tenants SET grace_started_at=?,grace_reason=? WHERE slug='alice'", start.Unix(), "graduated")
	out := p.execution(context.Background()).Admin("tenant_list", D{}, D{})
	seen := 0
	for _, row := range dicts(out["tenants"]) {
		switch row["slug"] {
		case "alice":
			seen++
			if row["grace_started_at"] != "2026-11-01T08:00:00Z" || row["grace_reason"] != "graduated" || row["stop_after"] != "2026-11-11T08:00:00Z" {
				t.Fatal("alice", encoded(row))
			}
		case "bob":
			seen++
			for _, k := range []string{"grace_started_at", "grace_reason", "stop_after"} {
				if v, ok := row[k]; !ok || v != nil {
					t.Fatal("bob", k, encoded(row))
				}
			}
		}
	}
	if seen != 2 {
		t.Fatal("tenants missing", encoded(out))
	}
}

func TestAlumniGraceDaysDefaultsTo30(t *testing.T) {
	if d := (Config{}).WithDefaults().AlumniGraceDays; d != 30 {
		t.Fatal(d)
	}
	if d := (Config{AlumniGraceDays: 2}).WithDefaults().AlumniGraceDays; d != 2 {
		t.Fatal(d)
	}
}
