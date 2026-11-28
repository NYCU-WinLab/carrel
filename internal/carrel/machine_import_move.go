package carrel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The confirmed machine_import (PLAN 10.6). The control plane drives the
// source's own API with the token source_add recorded: it prepares the guest,
// asks the source to remote-migrate it to the target cluster, and then has
// the target node move offline volumes from the directory storage they landed
// on to the guest storage. The source ends stopped with lock: migrate and is
// never deleted. Normalization and verification are separate steps.

var (
	// importPoll is how often a Proxmox task on the source is read. A variable
	// so tests can shorten it.
	importPoll = 5 * time.Second
	// importTaskLimit bounds one task: a disk copy at the migration limit.
	importTaskLimit = 4 * time.Hour
	// importShutdownSeconds is how long a CT's shutdown gets before pct stop;
	// importVMShutdownSeconds is how long a VM gets (Proxmox's own default).
	importShutdownSeconds   = 60
	importVMShutdownSeconds = 180

	importLabel      = regexp.MustCompile(`[^a-z0-9-]+`)
	importTargetHost = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$`)
)

// sourceWrite sends one form request to the source and returns its data,
// the task ID for a call that starts a task.
func sourceWrite(ctx context.Context, client *http.Client, method, base, tokenID, secret, path string, form url.Values) D {
	req, err := http.NewRequestWithContext(ctx, method, base+"/api2/json"+path, strings.NewReader(form.Encode()))
	must(err)
	req.Header.Set("Authorization", "PVEAPIToken="+tokenID+"="+secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, errSourceCertMatch) {
			fail("invalid", "The source's certificate does not match the fingerprint", D{"recovery": "revise_request"})
		}
		fail("backend_unavailable", "The source could not be reached", D{"component": "source", "backend_code": "source_transport_failed", "recovery": "retry_infrastructure"})
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		fail("invalid", "The source refused the token for this change; it needs permission to modify and migrate the guest", D{"recovery": "revise_request"})
	}
	var d D
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d) != nil {
		fail("backend_unavailable", "The source refused the request", D{"component": "source", "backend_code": "source_request_failed", "recovery": "retry_infrastructure"})
	}
	return d
}

// sourceTask waits for a task of the source to stop and returns whether it
// finished OK. A read that fails on the way (the source busy or briefly
// unreachable during an hours long copy) is tried again until the task's
// time is up. The task's own log never reaches a result.
func sourceTask(ctx context.Context, client *http.Client, base, tokenID, secret, node, upid string) bool {
	if !matches(`^UPID:[A-Za-z0-9.:@!_-]{1,300}$`, upid) {
		fail("backend_unavailable", "The source did not answer as a Proxmox host", D{"component": "source", "backend_code": "source_response_invalid", "recovery": "retry_infrastructure"})
	}
	deadline := time.Now().Add(importTaskLimit)
	for time.Now().Before(deadline) {
		var st D
		if f := attempt(func() {
			st = obj(sourceGet(ctx, client, base, tokenID, secret, "/nodes/"+url.PathEscape(node)+"/tasks/"+url.PathEscape(upid)+"/status")["data"])
		}); f != nil {
			if failure, ok := f.(Failure); !ok || obj(failure.Result["error"])["code"] != "backend_unavailable" {
				panic(f)
			}
		}
		if st["status"] == "stopped" {
			return st["exitstatus"] == "OK"
		}
		if !sleep(ctx, importPoll) {
			fail("backend_unavailable", "The import was interrupted", D{"recovery": "retry_infrastructure"})
		}
	}
	fail("backend_unavailable", "A task on the source did not finish in time", D{"component": "source", "backend_code": "source_task_timeout", "recovery": "contact_administrator"})
	return false
}

// importName picks the machine name: the guest's own when it fits.
func (e *Execution) importName(t, config D, vmid int) string {
	name := strings.Trim(importLabel.ReplaceAllString(strings.ToLower(textAt(config, "name", str(config["hostname"]))), "-"), "-")
	if len(name) > 30 {
		name = strings.Trim(name[:30], "-")
	}
	if name == "" || name[0] < 'a' || name[0] > 'z' {
		name = "import-" + strconv.Itoa(vmid)
	}
	taken := func(n string) bool {
		return find(e.S.Objects("machines", integer(t["n"])), func(m D) bool { return m["name"] == n }) != nil || e.frozenMachine(t, n) != nil || e.goneMachine(t, n) != nil
	}
	if taken(name) {
		name = fmt.Sprintf("%s-%d", name, vmid)
		if len(name) > 32 {
			name = "import-" + strconv.Itoa(vmid)
		}
	}
	if taken(name) {
		fail("conflict", "Machine name is already allocated", D{"recovery": "revise_request", "machine": name})
	}
	return name
}

// importTargetSecret reads the secret of the token on the target cluster.
func (e *Execution) importTargetSecret() string {
	b, err := readSmall(e.sourceSecretPath("_target"), 4096)
	if err != nil || !sourceSecret.MatchString(strings.TrimSpace(string(b))) {
		fail("invalid", "Place the secret of the target's API token on the control plane as _target.secret in the source directory", D{"recovery": "resolve_prerequisite"})
	}
	return strings.TrimSpace(string(b))
}

// importStart runs under the writer: it checks what the move needs, reserves
// the machine record (which is also the quota reservation) and leaves the
// slow part to PerformMachineImport.
func (e *Execution) importStart(a D, c importContext, plan D) D {
	cfg := e.P.Config
	if cfg.ImportTargetEndpoint == "" || cfg.ImportTargetNode == "" || cfg.ImportTargetTokenID == "" || cfg.ImportTargetFingerprint == "" {
		fail("invalid", "This site does not say where imported guests go: set import_target_endpoint, import_target_node, import_target_token_id and import_target_fingerprint", D{"recovery": "resolve_prerequisite"})
	}
	if !importTargetHost.MatchString(cfg.ImportTargetEndpoint) || !sourceTokenID.MatchString(cfg.ImportTargetTokenID) || !sourceFingerprint.MatchString(cfg.ImportTargetFingerprint) ||
		!matches(`^[a-z][a-z0-9_.-]{0,62}$`, cfg.ImportHopStorage) {
		fail("invalid", "The import target settings of this site are malformed", D{"recovery": "contact_administrator"})
	}
	e.importTargetSecret()
	if c.Target.Name != cfg.ImportTargetNode {
		fail("conflict", "The import was planned for another node; plan it again", D{"recovery": "revise_request"})
	}
	t := c.Tenant
	e.RequireActive(integer(t["n"]))
	name := e.importName(t, c.Config, c.VMID)
	// The same guest is not imported twice at once.
	for _, m := range e.S.Objects("machines", integer(t["n"])) {
		if (m["state"] == "importing" || m["state"] == "import_failed") && obj(m["import"])["source"] == c.Source && integer(obj(m["import"])["guest"]) == c.VMID {
			fail("conflict", "This guest is already being imported", D{"recovery": "resolve_prerequisite"})
		}
	}
	cloudInitKey := ""
	if c.Kind == "vm" {
		for _, d := range c.Disks {
			if d.CloudInit {
				cloudInitKey = d.Key
			}
		}
	}
	// Every guest moves offline, so every volume from a source that is not
	// ZFS lands on the hop storage on its way to the guest storage.
	hop := c.Hop
	job := D{"source": c.Source, "guest": c.VMID, "node": c.SourceNode, "api": c.API, "kind": c.Kind, "running": c.Running,
		"cloud_init_key": cloudInitKey, "hop": hop, "target_node": c.Target.Name, "target_vmid": integer(obj(obj(plan["plan"])["target"])["vmid"])}
	spec := D{"name": name, "kind": c.Kind, "image": "imported", "cpu": c.CPU, "memory_mb": c.Memory, "disk_gb": c.DiskGiB, "node": c.Target.Name,
		"public_ssh": false, "imported": true, "import": pickImport(job)}
	m, _ := e.AllocateMachine(t, spec)
	if integer(m["vmid"]) != integer(job["target_vmid"]) {
		e.S.Remove("machines", m["vmid"])
		fail("conflict", "The target slot changed; plan the import again", D{"recovery": "revise_request"})
	}
	// Not provisioning: nothing waits for a guest report on this machine yet.
	m["state"] = "importing"
	e.Put("machines", m["vmid"], integer(m["tenant_n"]), m)
	e.Op["import"] = job
	e.P.Operations.Save(e.Op)
	return D{"machine": D{"name": name}, "state": "importing", "plan": plan["plan"]}
}

func pickImport(job D) D { return pick(job, "source", "guest", "kind") }

func init() {
	registerPhases(Phases{Perform: (*Execution).PerformMachineImport, Finish: func(e *Execution, t D) D { return e.FinishMachineImport(t) }}, "machine_import")
}

// PerformMachineImport moves the guest without the writer lock. A failure
// before carrel sent anything to the source removes the machine record, which
// gives the quota back. Once the source was asked to shut down or change, or
// to migrate (the guest may then exist on the target), a failure keeps the
// record (its VMID and quota) as import_failed for an admin to finish or
// delete. The source is left as it was or stopped, never deleted.
func (e *Execution) PerformMachineImport() {
	if e.Op["tool"] != "machine_import" || e.Op["import"] == nil {
		return
	}
	vmid := integer(obj(e.Op["import"])["target_vmid"])
	problem := attempt(func() { e.moveGuest(obj(e.Op["import"])) })
	if problem == nil {
		return
	}
	e.P.writer.Lock()
	defer e.P.writer.Unlock()
	if e.P.ctx.Err() != nil {
		// The control plane is stopping; the job resumes from its record.
		panic(problem)
	}
	if m := e.S.Get("machines", str(vmid)); m != nil && m["operation_id"] == e.Op["id"] {
		if job := obj(e.Op["import"]); job["migrate_sent"] == true || job["source_changed"] == true {
			m["state"] = "import_failed"
			m["import"] = merge(obj(m["import"]), D{"failed_at": str(obj(e.Op["import"])["step"])})
			e.Put("machines", m["vmid"], integer(m["tenant_n"]), m)
		} else {
			e.S.Remove("machines", vmid)
		}
	}
	panic(problem)
}

func (e *Execution) moveGuest(job D) {
	cfg := e.P.Config
	rec := e.S.SiteGet("source", str(job["source"]))
	if rec == nil {
		fail("not_found", "This source is not registered; add it with source_add", D{"recovery": "resolve_prerequisite"})
	}
	secret, _ := e.sourceSecretOf(D{}, str(job["source"]))
	client := sourceClient(str(rec["fingerprint"]))
	defer client.CloseIdleConnections()
	base, tokenID := str(rec["api_url"]), str(rec["token_id"])
	node, api, vmid := str(job["node"]), str(job["api"]), integer(job["guest"])
	if !matches(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$`, node) || (api != "qemu" && api != "lxc") {
		fail("invalid", "The import job is malformed")
	}
	path := "/nodes/" + url.PathEscape(node) + "/" + api + "/" + strconv.Itoa(vmid)
	note := func(k string, v any) {
		e.P.writer.Lock()
		defer e.P.writer.Unlock()
		e.Op["import"] = merge(obj(e.Op["import"]), D{k: v})
		e.Op["phase"] = "importing_guest"
		e.P.Operations.Save(e.Op)
	}
	// A job resumed after a restart skips what it already did.
	if job["migrated"] != true {
		if upid := str(job["upid"]); upid != "" {
			note("step", "remote_migrate")
			if !sourceTask(e.Ctx, client, base, tokenID, secret, node, upid) {
				fail("backend_unavailable", "The source could not migrate the guest; it stays on the source, stopped", D{"component": "source", "backend_code": "remote_migrate_failed", "recovery": "contact_administrator"})
			}
		} else {
			if job["migrate_sent"] == true {
				// The request went out but its task ID was not saved.
				fail("backend_unavailable", "The import was interrupted while the migration started; check both sides", D{"component": "source", "backend_code": "remote_migrate_unknown", "recovery": "contact_administrator"})
			}
			e.startMigration(job, client, base, tokenID, secret, path, note)
		}
		note("migrated", true)
	}

	// Tags the guest too, so the node agent accepts it (#917); without a hop
	// there is no volume to move and no hop storage to name.
	hopStorage := ""
	if job["hop"] == true {
		note("step", "move_volumes")
		hopStorage = cfg.ImportHopStorage
	} else {
		note("step", "tag_guest")
	}
	e.Call(D{"op": "import_finish", "tenant_n": e.Op["tenant_n"], "vmid": job["target_vmid"], "kind": job["kind"], "hop_storage": hopStorage, "bwlimit": cfg.MigrationBwlimitKiB}, e.importTargetNode(str(job["target_node"])))
}

// startMigration prepares the guest on the source, sends remote_migrate and
// waits for its task. The task ID is saved before the wait, so a restarted
// job polls the same task instead of starting another.
func (e *Execution) startMigration(job D, client *http.Client, base, tokenID, secret, path string, note func(string, any)) {
	cfg := e.P.Config
	node := str(job["node"])
	wait := func(r D) bool {
		return sourceTask(e.Ctx, client, base, tokenID, secret, node, str(r["data"]))
	}
	note("step", "prepare")

	// Every guest moves stopped. A running VM cannot move online: the tenant
	// bridge has a smaller MTU than the old network, and Proxmox refuses to
	// start the VM there (staging, #902). Shutdown first. A CT that does not
	// finish is stopped (PLAN 10.6). A VM is never stopped by force: the
	// source is the rollback copy, so the import ends and the VM is left to
	// finish its own shutdown or keep running.
	// A shutdown that times out is not cancelled: the guest may still power
	// off later, so its state is read again instead of trusted.
	stopped := func() bool {
		return str(obj(sourceGet(e.Ctx, client, base, tokenID, secret, path+"/status/current")["data"])["status"]) == "stopped"
	}
	// HA may have taken the guest since the plan: Proxmox would then
	// force-stop it on shutdown and refuse to migrate it.
	for _, g := range dicts(sourceGet(e.Ctx, client, base, tokenID, secret, "/cluster/resources?type=vm")["data"]) {
		if integer(g["vmid"]) == integer(job["guest"]) && str(g["hastate"]) != "" {
			fail("conflict", "The guest is managed by Proxmox HA on the source; remove it from HA there first", D{"component": "source", "backend_code": "source_ha", "recovery": "resolve_prerequisite"})
		}
	}
	if job["running"] == true && str(job["stopped_with"]) == "" {
		note("step", "stop")
		cmd, seconds := "qm", importVMShutdownSeconds
		if job["kind"] == "ct" {
			cmd, seconds = "pct", importShutdownSeconds
		}
		used := cmd + " shutdown"
		// A job resumed while its shutdown ran waits for that task instead of
		// sending a second one that would queue behind the guest's lock.
		var shutdown D
		if upid := str(job["shutdown_upid"]); upid != "" {
			shutdown = D{"data": upid}
		}
		if shutdown == nil && stopped() {
			// The owner shut it down meanwhile, or a resumed job.
			used = "already stopped"
		} else {
			// From here the source may change: a failure keeps the record.
			note("source_changed", true)
			if shutdown == nil {
				shutdown = sourceWrite(e.Ctx, client, "POST", base, tokenID, secret, path+"/status/shutdown", url.Values{"timeout": {strconv.Itoa(seconds)}})
				if upid := str(shutdown["data"]); matches(`^UPID:[A-Za-z0-9.:@!_-]{1,300}$`, upid) {
					note("shutdown_upid", upid)
				}
			}
			if !wait(shutdown) && !stopped() {
				if job["kind"] != "ct" {
					fail("conflict", "The VM did not shut down in time and was not stopped by force. It may still power off by itself; check it on the source", D{"component": "source", "backend_code": "source_shutdown_timeout", "recovery": "contact_administrator"})
				}
				used = "pct stop"
				if !wait(sourceWrite(e.Ctx, client, "POST", base, tokenID, secret, path+"/status/stop", url.Values{})) {
					fail("backend_unavailable", "The source could not stop the container", D{"component": "source", "backend_code": "source_stop_failed", "recovery": "contact_administrator"})
				}
			}
		}
		note("stopped_with", used)
	}
	// Nothing changes on a guest that runs: it may have been started again on
	// the source since the plan or since a saved stop.
	if !stopped() {
		fail("conflict", "The guest runs on the source; shut it down there or import again", D{"component": "source", "backend_code": "source_running", "recovery": "resolve_prerequisite"})
	}
	// A shutdown applies pending changes, so a disk detached then would
	// travel as unusedN, never counted or moved off the hop.
	config := obj(sourceGet(e.Ctx, client, base, tokenID, secret, path+"/config")["data"])
	for key := range config {
		if matches(`^unused[0-9]+$`, key) {
			fail("conflict", "The guest has a detached disk ("+key+"); delete or reattach it on the source, then import again", D{"component": "source", "backend_code": "source_changed", "recovery": "contact_administrator"})
		}
	}
	// The cloud-init disk does not move: carrel writes its own after the
	// move. The guest is stopped, so the delete applies at once instead of
	// staying pending. The slot is read again and the delete carries the
	// config digest, so a disk put there since is never detached.
	if key := str(job["cloud_init_key"]); key != "" && job["cloud_init_dropped"] != true {
		current := str(config[key])
		// An empty slot means a resumed job already deleted it.
		if current != "" && !strings.Contains(strings.SplitN(current, ",", 2)[0], "cloudinit") {
			fail("conflict", "The guest's "+key+" is no longer its cloud-init disk; plan the import again", D{"component": "source", "backend_code": "source_changed", "recovery": "revise_request"})
		}
		note("source_changed", true)
		if current != "" {
			form := url.Values{"delete": {key}}
			if d := str(config["digest"]); d != "" {
				form.Set("digest", d)
			}
			sourceWrite(e.Ctx, client, "PUT", base, tokenID, secret, path+"/config", form)
		}
		note("cloud_init_dropped", true)
	}

	storage := importTargetStorage
	if job["hop"] == true {
		storage = cfg.ImportHopStorage
	}
	targetSecret := e.importTargetSecret()
	endpoint := "apitoken=PVEAPIToken=" + cfg.ImportTargetTokenID + "=" + targetSecret + ",host=" + cfg.ImportTargetEndpoint + ",fingerprint=" + strings.ToUpper(cfg.ImportTargetFingerprint)
	if host, port, ok := strings.Cut(cfg.ImportTargetEndpoint, ":"); ok {
		endpoint = "apitoken=PVEAPIToken=" + cfg.ImportTargetTokenID + "=" + targetSecret + ",host=" + host + ",port=" + port + ",fingerprint=" + strings.ToUpper(cfg.ImportTargetFingerprint)
	}
	// The guest joins its tenant's bridge, the one carrel machines use, never
	// the node underlay: it arrives isolated, and normalization only changes
	// its address.
	bridge := fmt.Sprintf("t%03d", integer(e.Op["tenant_n"]))
	form := url.Values{"target-endpoint": {endpoint}, "target-vmid": {strconv.Itoa(integer(job["target_vmid"]))}, "target-bridge": {bridge}, "target-storage": {storage}}
	note("step", "remote_migrate")
	// From here the guest may exist on the target: a failure keeps the record.
	note("migrate_sent", true)
	r := sourceWrite(e.Ctx, client, "POST", base, tokenID, secret, path+"/remote_migrate", form)
	upid := str(r["data"])
	if matches(`^UPID:[A-Za-z0-9.:@!_-]{1,300}$`, upid) {
		note("upid", upid)
	}
	if !wait(r) {
		fail("backend_unavailable", "The source could not migrate the guest; it stays on the source, stopped", D{"component": "source", "backend_code": "remote_migrate_failed", "recovery": "contact_administrator"})
	}
}

func (e *Execution) importTargetNode(name string) string {
	n, ok := e.nodeNamed(name)
	if !ok {
		fail("conflict", "The target node is no longer configured")
	}
	return n.Target
}

// FinishMachineImport records the machine as imported but not yet verified.
func (e *Execution) FinishMachineImport(t D) D {
	job := obj(e.Op["import"])
	if job == nil || e.Op["tool"] != "machine_import" {
		return D{}
	}
	m := e.S.Get("machines", str(job["target_vmid"]))
	if m == nil {
		fail("not_found", "The imported machine record is gone")
	}
	m["state"] = "imported_unverified"
	e.Put("machines", m["vmid"], integer(m["tenant_n"]), m)
	e.P.invalidateInventory()
	r := D{"machine": D{"name": m["name"]}, "state": "imported_unverified", "source": D{"name": job["source"], "guest": job["guest"], "state": "stopped", "lock": "migrate"}}
	if used := str(job["stopped_with"]); used != "" {
		r["stopped_with"] = used
	}
	return r
}

// importNotNormalized lists the states of an imported machine whose network
// is not normalized yet (PLAN 10.6). Its tags let the node agent act on it,
// so the control plane must refuse anything that boots or changes it.
var importNotNormalized = []string{"importing", "import_failed", "imported_unverified"}

// refuseUnnormalizedImport fails with a conflict for an imported machine that
// is not normalized yet. Reading, stopping and deleting it stay allowed.
func refuseUnnormalizedImport(m D) {
	if contains(importNotNormalized, m["state"]) {
		fail("conflict", "The imported machine is not normalized yet", D{"state": m["state"], "recovery": "resolve_prerequisite"})
	}
}
