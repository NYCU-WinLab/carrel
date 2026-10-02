package carrel

import (
	"fmt"
	"math"
)

// Compact only the MCP presentation. Durable results retain the full accounting
// and allocation identities for retries, diagnostics and detail=full clients.
func memberResponse(tool string, args, result D) D {
	if named("admin_tools", tool) || args["detail"] == "full" || boolean(args["dry_run"]) || !boolean(result["ok"]) {
		return result
	}
	r := clone(result)
	if op, ok := r["operation"]; ok {
		r["operation"] = operationSummary(obj(op))
	}
	if ops, ok := r["operations"]; ok {
		out := []D{}
		for _, op := range dicts(ops) {
			out = append(out, operationSummary(op))
		}
		r["operations"] = out
	}
	if tool == "machine_get" || tool == "machine_list" {
		out := []D{}
		for _, m := range dicts(r["machines"]) {
			summary := machineSummary(m)
			if tool == "machine_list" {
				delete(summary, "ssh_config")
				summary["state_source"] = "recorded"
			}
			out = append(out, summary)
		}
		r["machines"] = out
	}
	if tool == "ssh_key_add" || tool == "ssh_key_remove" {
		return without(r, "quota_before", "quota_after", "delta", "dry_run")
	}
	return r
}

func operationSummary(op D) D {
	// Failures, partial cleanup and recovery instructions must stay intact.
	if op["state"] != "succeeded" {
		return op
	}
	r := pick(op, "id", "tool", "state", "next_action", "resource_changes")
	if op["created_at"] != nil && op["updated_at"] != nil {
		r["duration_seconds"] = math.Round((num(op["updated_at"])-num(op["created_at"]))*1000) / 1000
	}
	result := without(obj(op["result"]), "quota_before", "quota_after", "dry_run")
	if len(obj(result["delta"])) == 0 {
		delete(result, "delta")
	}
	if m, ok := result["machine"]; ok {
		result["machine"] = machineSummary(obj(m))
	}
	if ms, ok := result["machines"]; ok {
		out := []D{}
		for _, m := range dicts(ms) {
			out = append(out, machineSummary(m))
		}
		result["machines"] = out
	}
	if snapshot, ok := result["snapshot"]; ok {
		result["snapshot"] = pick(obj(snapshot), "name", "state", "disk_gb")
		delete(result, "snapshot_storage")
	}
	if port, ok := result["port"]; ok {
		pub := pick(obj(port), "id", "public_port", "port", "proto", "state")
		if op["tool"] == "port_open" {
			pub["endpoint"] = fmt.Sprintf("carrel.winlab.tw:%d", integer(pub["public_port"]))
			pub["verification"] = "routing_configured"
		}
		result["port"] = pub
	}
	r["result"] = result
	return r
}

func machineSummary(m D) D {
	r := pick(m, "name", "kind", "image", "cpu", "memory_mb", "disk_gb", "state", "power_state", "ssh_ready", "runtime", "reason", "ssh", "ssh_short", "ssh_config", "ssh_short_requires")
	if readiness, ok := m["readiness"]; ok {
		r["readiness"] = pick(obj(readiness), "ssh_ready", "initialization_status", "application_status", "reported_at", "failed_step")
		if len(arr(obj(readiness)["checks"])) > 0 {
			obj(r["readiness"])["checks"] = obj(readiness)["checks"]
		}
	}
	return r
}
