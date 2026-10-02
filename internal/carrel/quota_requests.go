package carrel

import "time"

func validateQuotaLimit(t D, dim string, amount any, increase bool) {
	validateDimension(dim)
	hard := D{"public_ports": 10, "networks": 99, "machines": 100, "ips": 100}
	maximum := num(fallback(hard, dim, 1000000))
	if num(amount) < 0 || num(amount) > maximum {
		fail("invalid", "Quota exceeds the fixed address or resource limit", D{"dimension": dim, "maximum": maximum})
	}
	if increase && num(amount) <= num(obj(t["quota"])[dim]) {
		fail("invalid", "Request a total limit greater than the current limit", D{"dimension": dim, "current_limit": obj(t["quota"])[dim]})
	}
}

func validateGrantExpiry(value any) {
	if str(value) != "" && !parseExpiry(str(value)).After(time.Now()) {
		fail("invalid", "Expiry must be in the future")
	}
}

func (e *Execution) QuotaRequest(a, w, t D) D {
	dry, n := boolean(a["dry_run"]), integer(t["n"])
	key := str(a["idempotency_key"])
	fingerprint := digest(pythonJSON(pick(a, "dimension", "amount", "reason", "until")))
	if key != "" && !dry {
		for _, old := range e.S.Objects("requests", n) {
			if old["idempotency_key"] == key {
				if old["fingerprint"] != fingerprint {
					fail("conflict", "Idempotency key was already used for different arguments", D{"recovery": "revise_request"})
				}
				return D{"request": without(old, "fingerprint", "idempotency_key"), "quota_after": e.Quota(t), "reused": true}
			}
		}
	}
	validateQuotaLimit(t, str(a["dimension"]), a["amount"], true)
	validateGrantExpiry(a["until"])
	r := D{"id": randomID()[:16], "tenant_n": n, "kind": "quota", "status": "pending", "dimension": a["dimension"], "amount": a["amount"], "reason": a["reason"], "until": a["until"], "actor": w["sub"], "created_at": time.Now().Unix()}
	if !dry {
		if key != "" {
			r["idempotency_key"], r["fingerprint"] = key, fingerprint
		}
		e.Put("requests", r["id"], n, r)
	} else {
		r = without(r, "id", "tenant_n", "actor", "created_at")
		r["status"] = "planned"
	}
	return D{"request": without(r, "fingerprint", "idempotency_key"), "dry_run": dry, "quota_after": e.Quota(t)}
}

func publicRequests(requests []D) []D {
	out := []D{}
	for _, r := range requests {
		out = append(out, without(r, "idempotency_key", "fingerprint"))
	}
	return out
}
