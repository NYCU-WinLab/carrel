package carrel

import (
	"context"
	"errors"
	"testing"
	"time"
)

func graceOf(p *Platform, slug string) (any, any) {
	r := p.Store.Rows("SELECT grace_started_at,grace_reason FROM tenants WHERE slug=?", slug)[0]
	return r["grace_started_at"], r["grace_reason"]
}

func TestCheckAlumni(t *testing.T) {
	p, _ := fixture(t)
	e := p.execution(context.Background())
	answers := map[string]KeycloakMember{
		"alice": {State: MemberEnabled, Groups: []string{"/lab-member/alumni"}},
		"bob":   {State: MemberEnabled, Groups: []string{"/lab-member/113"}},
	}
	fail := false
	lookup := func(sub string) (KeycloakMember, error) {
		if fail {
			return KeycloakMember{}, errors.New("down")
		}
		return answers[sub], nil
	}
	t0 := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)

	e.CheckAlumni(t0, lookup)
	if s, r := graceOf(p, "alice"); integer(s) != int(t0.Unix()) || r != "alumni" {
		t.Fatal("start", s, r)
	}
	if s, _ := graceOf(p, "bob"); s != nil {
		t.Fatal("bob started", s)
	}
	if s, _ := graceOf(p, "shared"); s != nil {
		t.Fatal("project checked", s)
	}

	// Within the hour nothing is asked.
	answers["alice"] = KeycloakMember{State: MemberEnabled, Groups: []string{"/lab-member/113"}}
	e.CheckAlumni(t0.Add(30*time.Minute), lookup)
	if s, _ := graceOf(p, "alice"); s == nil {
		t.Fatal("checked twice within the hour")
	}

	// Unknown changes nothing.
	fail = true
	e.CheckAlumni(t0.Add(2*time.Hour), lookup)
	if s, _ := graceOf(p, "alice"); s == nil {
		t.Fatal("unknown cleared the grace")
	}
	fail = false

	// Enabled and no longer alumni clears both.
	e.CheckAlumni(t0.Add(4*time.Hour), lookup)
	if s, r := graceOf(p, "alice"); s != nil || r != nil {
		t.Fatal("clear", s, r)
	}

	// A second pass keeps an existing start; a disabled account starts one.
	answers["bob"] = KeycloakMember{State: MemberDisabled}
	e.CheckAlumni(t0.Add(6*time.Hour), lookup)
	e.CheckAlumni(t0.Add(8*time.Hour), lookup)
	if s, r := graceOf(p, "bob"); integer(s) != int(t0.Add(6*time.Hour).Unix()) || r != "disabled" {
		t.Fatal("bob", s, r)
	}
	if n := len(p.Store.Rows("SELECT 1 FROM audit WHERE tool IN ('grace_started','grace_cleared')")); n != 3 {
		t.Fatal("audit rows", n)
	}
}

func TestCheckAlumniUnknownStateChangesNothing(t *testing.T) {
	p, _ := fixture(t)
	e := p.execution(context.Background())
	e.CheckAlumni(time.Now(), func(string) (KeycloakMember, error) { return KeycloakMember{State: MemberUnknown}, nil })
	if s, _ := graceOf(p, "alice"); s != nil {
		t.Fatal(s)
	}
}
