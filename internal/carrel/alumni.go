package carrel

import (
	"log/slog"
	"strings"
	"time"
)

// alumniInterval is the least time between two Keycloak checks of the tenants.
const alumniInterval = time.Hour

const alumniGroup = "lab-member/alumni"

// alumniState says whether a member's account ends the membership: disabled,
// or in no lab-member group except alumni.
func alumniState(m KeycloakMember) (reason string, left bool) {
	if m.State == MemberDisabled {
		return "disabled", true
	}
	alumni, current := false, false
	for _, g := range m.Groups {
		g = strings.TrimPrefix(g, "/")
		if g == alumniGroup {
			alumni = true
		} else if strings.HasPrefix(g, "lab-member/") {
			current = true
		}
	}
	if alumni && !current {
		return "alumni", true
	}
	return "", false
}

// CheckAlumni asks Keycloak about each active personal tenant, at most once
// per alumniInterval, and records or clears the grace start (PLAN 10.3). An
// unknown answer changes nothing, and the first one ends the pass, so an
// outage never starts or finishes a grace period. Project tenants are not
// checked yet: the lookup of #862 answers for users only.
func (e *Execution) CheckAlumni(now time.Time, lookup func(sub string) (KeycloakMember, error)) {
	if e.P.lastAlumni != (time.Time{}) && now.Sub(e.P.lastAlumni) < alumniInterval {
		return
	}
	e.P.lastAlumni = now
	for _, r := range e.S.Rows("SELECT n,subject,grace_started_at,grace_reason FROM tenants WHERE status='active' AND subject LIKE 'user:%' ORDER BY n") {
		sub := strings.TrimPrefix(str(r["subject"]), "user:")
		m, err := lookup(sub)
		if err != nil || m.State == MemberUnknown {
			slog.Warn("alumni_check_unknown", "type", "maintenance", "tenant", r["n"])
			return
		}
		reason, left := alumniState(m)
		started := r["grace_started_at"] != nil
		switch {
		case left && !started:
			e.S.Exec("UPDATE tenants SET grace_started_at=?,grace_reason=? WHERE n=?", now.Unix(), reason, r["n"])
			e.S.Log("system", r["n"], "grace_started", D{"reason": reason}, "ok")
		case !left && started:
			e.S.Exec("UPDATE tenants SET grace_started_at=NULL,grace_reason=NULL WHERE n=?", r["n"])
			e.S.Log("system", r["n"], "grace_cleared", D{}, "ok")
		}
	}
}

// checkAlumniNow runs CheckAlumni with the Keycloak lookup, when it is set up.
func (e *Execution) checkAlumniNow() {
	c := e.P.Config
	if c.KeycloakURL == "" || c.KeycloakRealm == "" || c.KeycloakClientID == "" || c.KeycloakClientSecretFile == "" {
		return
	}
	e.CheckAlumni(time.Now(), e.keycloakMember)
}
