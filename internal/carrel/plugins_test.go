package carrel

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestAPluginReportOutsideTheBoundsIsRefused(t *testing.T) {
	ok := PluginInfo{Name: "snapshot", Contract: 1, Supported: true,
		Operations: []PluginOperation{{Name: "snapshot", Params: json.RawMessage(`{"type":"object"}`)}}}
	if msg := CheckPlugins([]PluginInfo{ok, {Name: "freeze", Reason: "no backup storage"}}); msg != "" {
		t.Fatal(msg)
	}
	many := make([]PluginInfo, MaxPlugins+1)
	for i := range many {
		many[i] = PluginInfo{Name: fmt.Sprintf("p%d", i)}
	}
	ops := make([]PluginOperation, MaxPluginOperations+1)
	for i := range ops {
		ops[i] = PluginOperation{Name: fmt.Sprintf("o%d", i), Params: json.RawMessage(`{}`)}
	}
	big := json.RawMessage(`{"x":"` + strings.Repeat("a", MaxPluginSchema) + `"}`)
	for name, report := range map[string][]PluginInfo{
		"too many plugins": many,
		"bad name":         {{Name: "../snapshot"}},
		"same name twice":  {ok, ok},
		"too many ops":     {{Name: "x", Operations: ops}},
		"schema not JSON":  {{Name: "x", Operations: []PluginOperation{{Name: "o", Params: json.RawMessage(`[1]`)}}}},
		"schema too big":   {{Name: "x", Operations: []PluginOperation{{Name: "o", Params: big}}}},
		"bad op name":      {{Name: "x", Operations: []PluginOperation{{Name: "Do It", Params: json.RawMessage(`{}`)}}}},
	} {
		if CheckPlugins(report) == "" {
			t.Errorf("%s: accepted", name)
		}
	}
}
