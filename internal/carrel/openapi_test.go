package carrel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every route registered on the mux has an entry in openapi.json, with its
// method, and every entry says who may call it.
func TestOpenAPIDescribesEveryRoute(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(openAPI, &doc); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob("*.go")
	route := regexp.MustCompile(`mux\.Handle(?:Func)?\("([^"]+)"`)
	seen := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range route.FindAllStringSubmatch(string(src), -1) {
			seen++
			method, path, ok := strings.Cut(m[1], " ")
			if !ok {
				method, path = "", m[1]
			}
			ops, found := doc.Paths[path]
			if !found && strings.HasSuffix(path, "/") {
				// A subtree route ("/oauth/") is described by its leaves.
				for p, o := range doc.Paths {
					if strings.HasPrefix(p, path) {
						found, ops = true, o
						break
					}
				}
			}
			if !found {
				t.Errorf("%s: route %q has no entry in openapi.json", f, m[1])
				continue
			}
			if method != "" && ops[strings.ToLower(method)] == nil {
				t.Errorf("%s: route %q has no %s operation in openapi.json", f, m[1], method)
			}
		}
	}
	if seen < 30 {
		t.Fatalf("found only %d routes; the scan is broken", seen)
	}
	audiences := map[string]bool{"public": true, "ci": true, "member": true, "agent": true, "internal": true}
	for path, ops := range doc.Paths {
		for method, op := range ops {
			if !audiences[str(op["x-carrel-audience"])] {
				t.Errorf("%s %s: x-carrel-audience must be one of public, ci, member, agent, internal", method, path)
			}
		}
	}
}
