package carrel

// Called outside the infrastructure writer. The reserved domain and machine
// bindings persist before slow DNS/ACME work and are checked again on return.
func (e *Execution) PreparePublication() {
	op := e.Op
	if op["tool"] != "deployment_apply" && op["tool"] != "domain_add" {
		return
	}
	ids := arr(obj(obj(op["deployment"])["grants"])["domains"])
	if op["tool"] == "domain_add" {
		ref := arr(op["domain_target"])
		if len(ref) != 2 {
			fail("conflict", "Missing reserved domain identity")
		}
		ids = []any{ref[0]}
	}
	if len(ids) == 0 {
		return
	}
	var tenant D
	check := func() {
		tenant = e.S.TenantN(integer(op["tenant_n"]))
		e.RequireActive(integer(tenant["n"]))
		if op["tool"] == "deployment_apply" {
			e.CheckBindings(tenant, obj(op["deployment"]))
		} else {
			e.BindMachine(tenant)
		}
		for _, id := range ids {
			d, ok := rowOf[domainRecord](e.S, "domains", str(id))
			if !ok || d.State == "deleting" || d.TenantN != integer(tenant["n"]) {
				fail("conflict", "Publication removed during preparation")
			}
			if op["tool"] == "domain_add" && !equal([]any{d.ID, orNil(d.OperationID)}, op["domain_target"]) {
				fail("conflict", "Publication replaced during preparation")
			}
		}
	}
	err := attempt(func() {
		e.P.writer.Lock()
		defer e.P.writer.Unlock()
		check()
		op["phase"] = "preparing_publication"
		e.P.Operations.Save(op)
	})
	if err != nil {
		panic(err)
	}
	certificate := e.EnsureCertificate(tenant)
	e.P.writer.Lock()
	defer e.P.writer.Unlock()
	check()
	for _, id := range ids {
		d, _ := rowOf[domainRecord](e.S, "domains", str(id))
		if d.State == "ready" {
			continue
		}
		// The certificate's state, and when it is queued, its time.
		d.State = str(certificate["state"])
		if at, ok := certificate["ready_at"]; ok {
			d.ReadyAt = num(at)
		}
		if d.State == "ready" {
			d.State = "configuring"
		}
		e.Put("domains", id, integer(tenant["n"]), d)
	}
	if certificate["state"] != "ready" {
		panic(Waiting{"waiting_for_certificate", num(certificate["ready_at"])})
	}
	e.publicationPrepared = true
}
