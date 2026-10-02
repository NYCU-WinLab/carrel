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
			got := p.Execute(context.Background(), str(tc["tool"]), obj(tc["args"]), obj(tc["who"]))
			a := normalizeParity(copyValue(got))
			b := normalizeParity(tc["expected"])
			if !equal(a, b) {
				t.Fatalf("Go: %s\nPython: %s", encoded(a), encoded(b))
			}
		})
	}
}
