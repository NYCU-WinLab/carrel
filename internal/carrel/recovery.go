package carrel

func recoveryAction(op D) (string, string) {
	if op["state"] == "cleanup_failed" {
		return "operation_retry", "Finish cleanup of this operation before submitting replacements."
	}
	err := obj(op["error"])
	kind := str(err["recovery"])
	if kind == "" {
		switch err["code"] {
		case "invalid", "not_found":
			kind = "revise_request"
		case "quota_exceeded", "capacity_exhausted":
			kind = "resolve_capacity"
		case "forbidden":
			kind = "restore_access"
		case "guest_not_ready":
			kind = "repair_guest"
			if op["state"] == "rolled_back" {
				kind = "revise_request"
			}
		default:
			kind = "retry_infrastructure"
		}
	}
	switch kind {
	case "revise_request":
		return kind, "Correct the request and submit with a new idempotency_key. This operation keeps its original arguments; repeating them will not fix the blocker. Retained resources must be repaired or explicitly removed first."
	case "resolve_capacity":
		return kind, "Resolve the reported quota or shared capacity limit, then retry this operation. Do not stop or delete existing work without authorization."
	case "restore_access":
		return kind, "Restore tenant access or membership before retrying."
	case "repair_guest":
		return kind, "Use the retained machine's SSH details to repair initialization or the failed application checks, then operation_retry. Bootstrap commands are not automatically rerun on an existing guest."
	case "resolve_prerequisite":
		return kind, str(err["message"]) + ". Resolve this prerequisite only with the required authorization, then retry this operation."
	case "finish_cleanup":
		return kind, "Finish the earlier resource removal operation, then retry this request."
	default:
		return "operation_retry", "Resolve the infrastructure fault identified by error code/component and retry this operation with its original allocation."
	}
}
