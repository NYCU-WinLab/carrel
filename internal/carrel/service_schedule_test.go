package carrel

import (
	"context"
	"testing"
)

func TestServiceSchedulesReachTheHost(t *testing.T) {
	p, a := serviceFixture(t)
	alice := person("alice", false)
	call := func(args D) D { return a.Call(context.Background(), "service_schedule", args, alice) }
	assertOK(t, a.Call(context.Background(), "service_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1"}, alice))
	before := p.Store.serviceRevision()

	r := call(D{"service": "hook", "name": "nightly", "cron": "0 3 * * *", "time_zone": "Asia/Taipei", "path": "/jobs/nightly"})
	assertOK(t, r)
	r = call(D{"service": "hook", "name": "beat", "cron": "*/5 * * * *", "body": `{"ping":true}`})
	assertOK(t, r)
	want := []any{
		D{"name": "beat", "cron": "*/5 * * * *", "time_zone": "UTC", "path": "/", "body": `{"ping":true}`},
		D{"name": "nightly", "cron": "0 3 * * *", "time_zone": "Asia/Taipei", "path": "/jobs/nightly"},
	}
	if !equal(obj(r["service"])["schedules"], want) {
		t.Fatalf("service: %s", encoded(r["service"]))
	}
	if p.Store.serviceRevision() <= before {
		t.Fatal("the hosts were not told")
	}
	if got := obj(arr(hostState(t, a)["services"])[0])["schedules"]; !equal(got, want) {
		t.Fatalf("desired state: %s", encoded(got))
	}
	// The same name replaces; a dry run changes nothing.
	assertOK(t, call(D{"service": "hook", "name": "beat", "cron": "0 * * * *"}))
	assertOK(t, call(D{"service": "hook", "name": "beat", "remove": true, "dry_run": true}))
	if s := arr(obj(a.Call(context.Background(), "service_get", D{"service": "hook"}, alice)["service"])["schedules"]); len(s) != 2 || obj(s[0])["cron"] != "0 * * * *" {
		t.Fatalf("schedules: %s", encoded(s))
	}
	assertOK(t, call(D{"service": "hook", "name": "beat", "remove": true}))
	assertOK(t, call(D{"service": "hook", "name": "nightly", "remove": true}))
	if s := obj(arr(hostState(t, a)["services"])[0])["schedules"]; s != nil {
		t.Fatalf("removed schedules still reach the host: %s", encoded(s))
	}
	assertCode(t, call(D{"service": "hook", "name": "nightly", "remove": true}), "not_found")
}

func TestServiceScheduleChecks(t *testing.T) {
	_, a := serviceFixture(t)
	alice := person("alice", false)
	call := func(args D) D { return a.Call(context.Background(), "service_schedule", args, alice) }
	assertOK(t, a.Call(context.Background(), "service_deploy", D{"name": "hook", "image": "ghcr.io/alice/hook:1"}, alice))
	for _, bad := range []D{
		{"cron": "* * * *"},
		{"cron": "61 * * * *"},
		{"cron": "* * * * *", "time_zone": "Mars/Base"},
		{"cron": "* * * * *", "path": "//evil.test/"},
	} {
		assertCode(t, call(merge(D{"service": "hook", "name": "x"}, bad)), "invalid")
	}
	for i := range 10 {
		assertOK(t, call(D{"service": "hook", "name": "s" + string(rune('a'+i)), "cron": "* * * * *"}))
	}
	assertCode(t, call(D{"service": "hook", "name": "eleventh", "cron": "* * * * *"}), "conflict")
	// Another tenant cannot name the service.
	r := a.Call(context.Background(), "service_schedule", D{"service": "hook", "name": "x", "cron": "* * * * *"}, person("bob", false))
	if boolean(r["ok"]) {
		t.Fatalf("bob scheduled alice's service: %s", encoded(r))
	}
}
