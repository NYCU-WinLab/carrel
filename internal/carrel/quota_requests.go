package carrel

import "time"

func (e *Execution) validateQuotaLimit(t D, dim string, amount any, increase bool) {
	if _, plugin := e.pluginDims()[dim]; !plugin {
		validateDimension(dim)
	}
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

// quotaRequestKind is the request flow of a higher quota limit.
var quotaRequestKind = requestKind{
	name: "quota", quotaAfter: true,
	fingerprint: func(a D) D { return pick(a, "dimension", "amount", "reason", "until") },
	check: func(e *Execution, a, t D) D {
		e.validateQuotaLimit(t, str(a["dimension"]), a["amount"], true)
		validateGrantExpiry(a["until"])
		return D{"dimension": a["dimension"], "amount": a["amount"], "until": a["until"]}
	},
	planned: func(out, a, t D) { out["current_limit"] = obj(t["quota"])[str(a["dimension"])] },
}

func (e *Execution) QuotaRequest(a, w, t D) D { return e.FileRequest(quotaRequestKind, a, w, t) }

func publicRequests(requests []D) []D {
	out := []D{}
	for _, r := range requests {
		out = append(out, without(r, "idempotency_key", "fingerprint"))
	}
	return out
}
