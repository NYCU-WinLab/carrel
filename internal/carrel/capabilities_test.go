package carrel

import (
	"context"
	"strings"
	"testing"
)

// catalog_get lists each feature with a reason where the site lacks it, and
// a tool of a missing feature fails with that reason before it does anything.
func TestSiteFeaturesGateTools(t *testing.T) {
	p, _, _ := originFixture(t)
	p.Config.Site = "b09"
	p.Config.BackupStorage, p.Config.Fetch, p.Config.FunctionHosts = "", false, nil
	p.Config.Nodes = p.Config.Nodes[:1]
	e := p.execution(context.Background())
	member := person("alice", false)
	catalog, _ := e.Dispatch("catalog_get", D{}, member)
	sites := dicts(catalog["sites"])
	if len(sites) != 1 || sites[0]["name"] != "b09" {
		t.Fatal(encoded(sites))
	}
	features := obj(sites[0]["features"])
	if obj(features["snapshot"])["available"] != true {
		t.Fatal(encoded(features))
	}
	for _, name := range []string{"machine_freeze", "machine_migrate", "image_import", "functions"} {
		if f := obj(features[name]); f["available"] != false || str(f["reason"]) == "" {
			t.Fatalf("%s: %v", name, f)
		}
	}
	for tool, feature := range map[string]string{"machine_freeze": "machine_freeze", "machine_thaw": "machine_freeze", "iso_import": "image_import", "function_deploy": "functions", "node_drain": "machine_migrate"} {
		r := failureResult(attempt(func() { e.Dispatch(tool, D{"tenant": "alice"}, person("admin", true)) }))
		err := obj(r["error"])
		if err["code"] != "unsupported" || err["feature"] != feature || !strings.Contains(str(err["message"]), "does not support") || len(arr(err["sites_with_feature"])) != 0 {
			t.Fatalf("%s: %v", tool, r)
		}
	}
	// A member asking for an admin tool learns only that it is forbidden.
	if r := failureResult(attempt(func() { e.Dispatch("node_drain", D{}, member) })); obj(r["error"])["code"] != "forbidden" {
		t.Fatalf("member node_drain: %v", r)
	}
	// With the features configured, the gate lets the tools through.
	p.Config.BackupStorage, p.Config.Fetch = "pbs", true
	for _, tool := range []string{"machine_freeze", "iso_import"} {
		if r := attempt(func() { p.requireFeature(tool) }); r != nil {
			t.Fatalf("%s: %v", tool, r)
		}
	}
}
