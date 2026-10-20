package carrel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsureCertificateIssuesAndBundlesTheLivePair(t *testing.T) {
	p, _ := fixture(t)
	cf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"success":true,"result":[]}`)) }))
	defer cf.Close()
	p.Config["cloudflare_api"], p.Config["cloudflare_zone"], p.Config["certificate_dir"] = cf.URL, "test", t.TempDir()
	crt, key := testPair(t)
	domains := []string{}
	p.issue = func(_ context.Context, domain string) ([]byte, []byte, error) {
		domains = append(domains, domain)
		return crt, key, nil
	}
	e := p.execution(context.Background())
	tenant := p.Store.TenantN(1)
	if e.EnsureCertificate(tenant)["state"] != "ready" || len(domains) != 1 || domains[0] != "*."+str(tenant["slug"])+".winlab.tw" {
		t.Fatal("did not issue the tenant wildcard", domains)
	}
	if e.EnsureCertificate(tenant)["state"] != "ready" || len(domains) != 1 {
		t.Fatal("a current certificate was ordered again", domains)
	}
	record := p.Store.Objects("certificates", 1)[0]
	if record["fullchain_path"] != nil || record["issued_at"] == nil {
		t.Fatal("the record must not pin files", record)
	}
	bundle := e.CertificateBundles([]D{{"tenant_n": 1, "state": "ready"}})[0]
	if bundle["fullchain"] != string(crt) || bundle["privkey"] != string(key) {
		t.Fatal("bundle is not the live pair")
	}
	p.issue = func(context.Context, string) ([]byte, []byte, error) { return nil, nil, errors.New("rate limited") }
	// A renewal that fails keeps the pair it would have replaced.
	must(os.Remove(filepath.Join(str(p.Config["certificate_dir"]), "live", str(tenant["slug"]))))
	if f := attempt(func() { e.EnsureCertificate(tenant) }); f == nil || obj(failureResult(f)["error"])["backend_code"] != "certificate_issuance_failed" {
		t.Fatal("an ACME failure must fail the issuance", f)
	}
	if _, _, ok := e.livePair(str(tenant["slug"])); ok {
		t.Fatal("a failed issuance created a live pair")
	}
}

func TestCertificatePreparationDoesNotBlockUnrelatedPower(t *testing.T) {
	p, b := fixture(t)
	seedMachine(p, "web", 10100)
	seedMachine(p, "other", 10101)
	cf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"result":[]}`))
	}))
	defer cf.Close()
	p.Config["cloudflare_api"], p.Config["cloudflare_zone"] = cf.URL, "test"
	entered, release := make(chan struct{}), make(chan struct{})
	p.certificatePrepare = func(D) D {
		close(entered)
		select {
		case <-release:
		case <-p.ctx.Done():
		}
		return D{"state": "ready"}
	}
	b.call = func(r D, _ string) (any, error) {
		if r["action"] == "shutdown" {
			return D{"power_state": "stopped", "changed": true}, nil
		}
		return D{}, nil
	}
	runQueue(p)
	ctx, who := context.Background(), person("alice", false)
	r := p.Execute(ctx, "domain_add", D{"machine": "web", "sub": "web", "target_port": 8080, "wait_seconds": 0}, who)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("certificate stage did not start")
	}
	id := str(obj(r["operation"])["id"])
	if p.Store.Get("operations", id)["prepared_result"] == nil {
		t.Fatal("publication reservation not checkpointed")
	}
	blocked := p.Execute(ctx, "machine_power", D{"machine": "web", "action": "shutdown", "wait_seconds": 0}, who)
	awaitState(t, p, str(obj(blocked["operation"])["id"]), "waiting_for_machine_operation")
	other := p.Execute(ctx, "machine_power", D{"machine": "other", "action": "shutdown", "wait_seconds": 0}, who)
	awaitState(t, p, str(obj(other["operation"])["id"]), "succeeded")
	if contains(terminal, p.Store.Get("operations", id)["state"]) {
		t.Fatal("publication claimed complete before certificate")
	}
	close(release)
	done := awaitState(t, p, id, "succeeded")
	if obj(obj(done["result"])["domain"])["state"] != "ready" {
		t.Fatal("publication not finalized")
	}
	awaitState(t, p, str(obj(blocked["operation"])["id"]), "succeeded")
}

func TestApplicationDeadlineSurvivesRestart(t *testing.T) {
	p, b := fixture(t)
	m := seedMachine(p, "recover", 10100)
	m["state"], m["operation_id"] = "initializing", "restarted"
	p.Store.Put("machines", 10100, 1, m)
	p.Store.Put("guest_reports", 10100, 1, D{"reported_at": now(), "initialization_status": "complete", "application_status": "failed", "checks": []D{{"index": 0, "status": "failed"}}})
	p.sshProbe = func(context.Context, D) bool { return true }
	p.Operations.Save(D{"id": "restarted", "tenant_n": 1, "who": person("alice", false), "tool": "machine_create", "state": "running", "phase": "waiting_for_guest", "args": D{}, "prepared_result": D{"machine": D{"name": "recover"}}, "readiness_deadlines": D{"10100:guest": now() + 30, "10100:application": now() - 1}})
	runQueue(p)
	op := awaitState(t, p, "restarted", "failed")
	if obj(op["error"])["code"] != "guest_not_ready" || b.count("create") != 0 || b.count("action") != 0 {
		t.Fatal("restart reset readiness or replayed mutation")
	}
	if publicOperation(op)["next_action"] != "repair_guest" || len(arr(op["recovery_machines"])) != 1 {
		t.Fatal("repair lacks retained machine")
	}
}
