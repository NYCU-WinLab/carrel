package schedule

import (
	"testing"
	"time"
)

func at(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04", s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestCronMatches(t *testing.T) {
	for _, c := range []struct {
		expr, when string
		want       bool
	}{
		{"* * * * *", "2026-11-27 10:03", true},
		{"*/5 * * * *", "2026-11-27 10:05", true},
		{"*/5 * * * *", "2026-11-27 10:06", false},
		{"0 9 * * 1-5", "2026-11-27 09:00", true},  // a Friday
		{"0 9 * * 1-5", "2026-11-29 09:00", false}, // a Sunday
		{"0 0 * * 7", "2026-11-29 00:00", true},    // 7 is Sunday too
		{"0 0 1 * 0", "2026-12-01 00:00", true},    // either day field
		{"0 0 1 * 0", "2026-11-29 00:00", true},
		{"0 0 1 * 0", "2026-11-30 00:00", false},
		{"15,45 1-3 * 2 *", "2027-02-10 02:45", true},
		{"10/20 * * * *", "2026-11-27 10:30", true},
		{"10/20 * * * *", "2026-11-27 10:20", false},
	} {
		cron, err := Parse(c.expr)
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		if got := cron.Matches(at(c.when)); got != c.want {
			t.Fatalf("%s at %s: %v", c.expr, c.when, got)
		}
	}
}

func TestCronRefusesWhatItCannotRead(t *testing.T) {
	for _, expr := range []string{"", "* * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8", "*/0 * * * *", "5-1 * * * *", "* * * JAN *", "@daily", "* * * * * *"} {
		if _, err := Parse(expr); err == nil {
			t.Fatalf("accepted %q", expr)
		}
	}
}

func TestScheduleCheckAndZone(t *testing.T) {
	good := Schedule{Name: "nightly", Cron: "0 3 * * *", TimeZone: "Asia/Taipei", Path: "/jobs/nightly?x=1"}
	if err := good.Check(); err != nil {
		t.Fatal(err)
	}
	// 03:00 in Taipei is 19:00 UTC the day before.
	if !good.Due(at("2026-11-26 19:00")) || good.Due(at("2026-11-27 03:00")) {
		t.Fatal("the time zone is not applied")
	}
	for _, bad := range []Schedule{
		{Name: "Bad", Cron: "* * * * *", TimeZone: "UTC", Path: "/"},
		{Name: "x", Cron: "* * * *", TimeZone: "UTC", Path: "/"},
		{Name: "x", Cron: "* * * * *", TimeZone: "Mars/Base", Path: "/"},
		{Name: "x", Cron: "* * * * *", TimeZone: "Local", Path: "/"},
		{Name: "x", Cron: "* * * * *", TimeZone: "UTC", Path: "jobs"},
		{Name: "x", Cron: "* * * * *", TimeZone: "UTC", Path: "//evil.test/"},
		{Name: "x", Cron: "* * * * *", TimeZone: "UTC", Path: "/", Body: string(make([]byte, MaxBody+1))},
	} {
		if bad.Check() == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}
