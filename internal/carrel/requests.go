package carrel

import (
	"fmt"
	"time"
)

// requestKind is what one kind of member request adds to the shared flow:
// the fields its idempotency fingerprint hashes (the bytes must not change,
// keys stay valid for 30 days), its validation, and its pending cap.
type requestKind struct {
	name string
	// noun names the kind in the pending cap error; empty means no cap.
	noun string
	// quotaAfter adds the tenant's quota to the answer.
	quotaAfter  bool
	fingerprint func(a D) D
	// check refuses a bad request and returns the fields the kind stores.
	check func(e *Execution, a, t D) D
	// planned adds fields to the answer of a dry run.
	planned func(out, a, t D)
}

// FileRequest files a request of one kind: it reuses the request of an
// idempotency key, applies the kind's validation and pending cap, and writes
// the request unless the call is a dry run.
func (e *Execution) FileRequest(k requestKind, a, w, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	key := str(a["idempotency_key"])
	fingerprint := digest(string(encoded(k.fingerprint(a))))
	answer := func(r D) D {
		out := D{"request": without(r, "fingerprint", "idempotency_key")}
		if k.quotaAfter {
			out["quota_after"] = e.Quota(t)
		}
		return out
	}
	if key != "" && !dry {
		for _, old := range e.S.Objects("requests", n) {
			if old["idempotency_key"] == key {
				if old["fingerprint"] != fingerprint {
					fail("conflict", "Idempotency key was already used for different arguments", D{"recovery": "revise_request"})
				}
				out := answer(old)
				out["reused"] = true
				return out
			}
		}
	}
	fields := k.check(e, a, t)
	if k.noun != "" {
		pending := filter(e.S.Objects("requests", n), func(r D) bool { return r["kind"] == k.name && r["status"] == "pending" })
		if len(pending) >= maxPendingDomainRequests {
			fail("quota_exceeded", fmt.Sprintf("A tenant has at most %d pending %s requests; wait for a decision", maxPendingDomainRequests, k.noun), D{"recovery": "revise_request"})
		}
	}
	r := merge(D{"id": randomID()[:16], "tenant_n": n, "kind": k.name, "status": "pending", "reason": a["reason"], "actor": w["sub"], "created_at": time.Now().Unix()}, fields)
	if !dry {
		if key != "" {
			r["idempotency_key"], r["fingerprint"] = key, fingerprint
		}
		e.Put("requests", r["id"], n, r)
	} else {
		r = without(r, "id", "tenant_n", "actor", "created_at")
		r["status"] = "planned"
	}
	out := answer(r)
	out["dry_run"] = dry
	if dry && k.planned != nil {
		k.planned(out, a, t)
	}
	return out
}

// decideRequest records the decision on a pending request. An approval runs
// grant inside the transaction that saves the request; a dry run only marks
// the request as planned.
func (e *Execution) decideRequest(tool string, dry bool, w, r D, grant func(tx *Execution)) {
	approve := tool == "request_approve"
	switch {
	case dry && approve:
		r["status"] = "planned_approval"
	case dry:
		r["status"] = "planned_rejection"
	default:
		e.Transaction(func(tx *Execution) {
			if approve {
				grant(tx)
				r["status"] = "approved"
			} else {
				r["status"] = "rejected"
			}
			r["decided_by"] = w["sub"]
			tx.Put("requests", r["id"], integer(r["tenant_n"]), r)
		})
	}
}
