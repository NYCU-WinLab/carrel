package carrel

// Readiness observations expire independently of power state and allocations.
func fresh(at any) bool { return num(at) > now()-120 && num(at) <= now()+5 }

func presentReadiness(m D, report guestReport) {
	r := obj(m["readiness"])
	r["freshness"] = "unknown"
	if report.ReportedAt != nil {
		r["freshness"] = "stale"
		if fresh(*report.ReportedAt) {
			r["freshness"] = "fresh"
		}
	}
	if m["kind"] == "ct" {
		r["freshness"] = "not_applicable"
	}
	r["ssh_checked_at"] = m["ssh_checked_at"]
	r["ssh_status"] = "unknown"
	if fresh(m["ssh_checked_at"]) {
		r["ssh_status"] = "unavailable"
		if boolean(m["ssh_ready"]) {
			r["ssh_status"] = "verified"
		}
	} else {
		m["ssh_ready"], r["ssh_ready"] = false, false
	}
	if m["kind"] == "vm" && r["freshness"] != "fresh" {
		unknownReport(r)
	}
	if contains([]string{"stopped", "paused"}, m["state"]) {
		m["ssh_ready"], r["ssh_ready"], r["ssh_status"] = false, false, "unavailable"
	}
	readinessState(m)
}

func unknownReport(r D) {
	r["initialization_status"], r["application_status"] = "unknown", "unknown"
	delete(r, "checks")
	delete(r, "failed_step")
	delete(r, "private_interfaces")
}

func readinessState(m D) {
	if contains([]string{"stopped", "paused", "deleting", "error", "provisioning", "initializing"}, m["state"]) {
		return
	}
	if unmanaged(m) {
		// No guest reports: SSH is only a hint for these machines.
		if m["power_state"] == "running" || m["state"] == "readiness_unknown" {
			m["state"] = bootState(m)
		}
		return
	}
	r := obj(m["readiness"])
	if r["initialization_status"] == "failed" || r["application_status"] == "failed" {
		m["state"] = "needs_owner_fix"
	} else if boolean(m["ssh_ready"]) && r["initialization_status"] == "complete" && contains([]string{"healthy", "not_checked"}, r["application_status"]) && (m["network_verification"] == nil || m["network_verification"] == "verified") {
		m["state"] = "ready"
	} else if m["state"] == "ready" || m["state"] == "running" {
		m["state"] = "readiness_unknown"
	}
}

func (e *Execution) ObserveSSH(m D) {
	r := obj(m["readiness"])
	if ports := servicePortsOf(m); len(ports) > 0 {
		// No SSH here (issue #94): ready means the first port answers.
		probe := probeServicePort
		if e.P.serviceProbe != nil {
			probe = e.P.serviceProbe
		}
		ready := m["power_state"] == "running" && probe(e.Ctx, m)
		r["service_port"], r["service_checked_at"] = ports[0], now()
		r["service_status"] = "unavailable"
		if ready {
			r["service_status"] = "verified"
		} else if m["state"] == "ready" {
			m["state"] = "initializing"
		}
		return
	}
	if m["power_state"] != "running" {
		m["ssh_ready"], r["ssh_ready"] = false, false
		r["ssh_status"] = "unavailable"
		return
	}
	probe := probeSSH
	if e.P.sshProbe != nil {
		probe = e.P.sshProbe
	}
	ready := probe(e.Ctx, m)
	m["ssh_ready"], r["ssh_ready"] = ready, ready
	r["ssh_checked_at"] = now()
	r["ssh_status"] = "unavailable"
	if ready {
		r["ssh_status"] = "verified"
	}
	readinessState(m)
}

// Configure offline guests without starting them or waiting for impossible reports.
func (e *Execution) NICReadiness(m, nic D) {
	if m["kind"] != "vm" || nic["ip"] == nil {
		return
	}
	state := powerState(obj(e.Call(D{"op": "status", "machine": m})))
	if !contains([]string{"running", "stopped", "paused"}, state) {
		fail("conflict", "Cannot determine guest power state after NIC configuration", D{"recovery": "retry_infrastructure"})
	}
	m["power_state"], m["state"], m["ssh_ready"] = state, state, false
	m["network_configured_at"] = now()
	m["network_verification"] = "pending_guest_start"
	if state == "paused" {
		m["network_verification"] = "pending_guest_resume"
	}
	if state == "running" && unmanaged(m) {
		m["state"] = bootState(m)
	} else if state == "running" {
		m["state"], m["network_verification"] = "initializing", "pending_guest_report"
	}
	e.Put("machines", m["vmid"], integer(m["tenant_n"]), m)
}

// The caller holds the writer. Deadlines survive process restarts, but explicit
// retries start a new verification window after the owner resolves the cause.
func (e *Execution) readinessDeadline(vmid, phase string, seconds int) float64 {
	if e.Op == nil {
		return now() + float64(seconds)
	}
	deadlines := obj(e.Op["readiness_deadlines"])
	key := vmid + ":" + phase
	if deadlines[key] == nil {
		deadlines[key] = now() + float64(seconds)
		e.Op["readiness_deadlines"] = deadlines
		e.P.Operations.Save(e.Op)
	}
	return num(deadlines[key])
}
