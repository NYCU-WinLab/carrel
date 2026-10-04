package carrel

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func normalizeParity(v any) any {
	switch x := v.(type) {
	case map[string]any:
		r := D{}
		for k, v := range x {
			if k == "checked_at" || k == "observed_at" || k == "version" {
				continue
			}
			if k == "admission" && obj(v)["reason"] == "no_compute_or_storage_growth" {
				r[k] = D{"accepted": true, "reserved": false}
				continue
			}
			if k == "nics" {
				ns := []any{}
				for _, n := range arr(v) {
					ns = append(ns, without(obj(n), "operation_id"))
				}
				r[k] = normalizeParity(ns)
				continue
			}
			r[k] = normalizeParity(v)
		}
		return r
	case []any:
		r := []any{}
		for _, v := range x {
			r = append(r, normalizeParity(v))
		}
		return r
	}
	return v
}
func TestPythonBehaviorParity(t *testing.T) {
	content, err := os.ReadFile("testdata/python-parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []D
	must(json.Unmarshal(content, &cases))
	for i, tc := range cases {
		t.Run(fmt.Sprintf("%02d_%s", i, str(tc["tool"])), func(t *testing.T) {
			s, err := OpenStore(filepath.Join(t.TempDir(), "parity.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.DB.Close()
			for _, tenant := range dicts(obj(tc["seed"])["tenants"]) {
				s.Exec("INSERT INTO tenants(n,subject,slug,quota,status) VALUES(?,?,?,?,?)", integer(tenant["n"]), tenant["subject"], tenant["slug"], string(encoded(tenant["quota"])), tenant["status"])
			}
			for _, o := range dicts(obj(tc["seed"])["objects"]) {
				s.Exec("INSERT INTO objects VALUES(?,?,?,?)", o["kind"], o["id"], integer(o["tenant"]), o["data"])
			}
			p := NewPlatform(s, &fakeBackend{inventory: baseInventory()}, D{})
			defer p.Close()
			// The frozen 0.5 fixtures retain their explicit legacy defaults. Current
			// default selection and quotas are covered by defaults_test.go.
			args := clone(obj(tc["args"]))
			legacySpec := func(a D) D {
				swap := 4096
				if a["kind"] == "ct" {
					swap = 0
				}
				return merge(D{"image": "debian-13", "size": "small", "swap_mb": swap}, a)
			}
			if tc["tool"] == "machine_create" {
				args = legacySpec(args)
			}
			if tc["tool"] == "deployment_plan" || tc["tool"] == "deployment_apply" {
				if args["machines"] != nil {
					machines := []D{}
					for _, m := range dicts(args["machines"]) {
						machines = append(machines, legacySpec(m))
					}
					args["machines"] = machines
				}
			}
			got := p.Execute(context.Background(), str(tc["tool"]), args, obj(tc["who"]))
			a := normalizeParity(copyValue(got))
			b := normalizeParity(tc["expected"])
			if tc["tool"] == "catalog_get" || tc["tool"] == "sizes_list" {
				delete(obj(obj(a)["sizes"]), "tiny")
			}
			if tc["tool"] == "catalog_get" || tc["tool"] == "images_list" {
				images := []D{}
				for _, im := range dicts(obj(a)["images"]) {
					if im["name"] == "debian-13-minimal" {
						continue
					}
					im = without(im, "environment", "default_size", "default_swap_mb")
					if im["name"] == "debian-13" {
						im["default"] = true
					}
					images = append(images, im)
				}
				obj(a)["images"] = images
			}
			// The legacy fixture predates VM pause and live top-level power state.
			// Validate those additions in actions_test.go; compare the rest unchanged.
			if tc["tool"] == "whoami" || tc["tool"] == "catalog_get" {
				delete(obj(obj(a)["capabilities"]), "machine_pause")
				delete(obj(obj(a)["capabilities"]), "existing_machine_access")
			}
			// Scope regressions cover the intentionally changed observation and
			// presentation fields. Compare the remaining legacy allocation contract.
			if (tc["tool"] == "machine_get" || tc["tool"] == "machine_list") && boolean(obj(a)["ok"]) {
				for _, m := range dicts(obj(b)["machines"]) {
					if tc["tool"] == "machine_get" {
						m["power_state"] = "running"
					}
					m["ssh_ready"], m["state"] = false, "readiness_unknown"
					r := obj(m["readiness"])
					r["application_status"] = "unknown"
					r["freshness"], r["ssh_status"], r["ssh_checked_at"] = "unknown", "unknown", nil
					if tc["tool"] == "machine_get" {
						r["ssh_status"] = "unavailable"
					}
					for _, k := range []string{"checks", "failed_step", "private_interfaces"} {
						delete(r, k)
					}
				}
				for _, m := range dicts(obj(a)["machines"]) {
					obj(m["readiness"])["ssh_checked_at"] = nil
				}
			}
			if tc["tool"] == "port_list" {
				for _, port := range dicts(obj(a)["ports"]) {
					for _, k := range []string{"machine", "endpoint", "verification"} {
						delete(port, k)
					}
				}
			}
			if tc["tool"] == "deployment_plan" || tc["tool"] == "deployment_apply" {
				if len(arr(obj(a)["access"])) == 0 {
					delete(obj(a), "access")
				}
			}
			delete(obj(obj(a)["error"]), "recovery")
			switch tc["tool"] {
			case "machine_create":
				delete(obj(obj(a)["error"]), "machine")
			case "port_open", "port_close":
				for _, k := range []string{"machine", "endpoint", "verification"} {
					if obj(obj(b)["port"])[k] == nil {
						delete(obj(obj(a)["port"]), k)
					}
				}
			case "domain_add":
				delete(obj(obj(a)["domain"]), "url")
			case "peer_allow":
				for _, k := range []string{"machine", "from_tenant", "from_machine"} {
					delete(obj(obj(a)["peer"]), k)
				}
			}
			if !equal(a, b) {
				t.Fatalf("Go: %s\nPython: %s", encoded(a), encoded(b))
			}
		})
	}
}
