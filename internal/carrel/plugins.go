package carrel

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// Plugins (#564): services on unix sockets on each node, speaking the
// contract in proto/plugin/v1. carrel-agent describes and probes them and
// reports them in every claim; the control plane keeps the latest report
// per node and relays operations to them as jobs with op "plugin" (#660).

// PluginContracts are the contract revisions agents serve: the current one
// and the previous one, as agentProtocols are for agents.
var PluginContracts = []uint32{1}

// Bounds on what an agent may report, so a bad plugin cannot grow a claim.
const (
	MaxPlugins          = 32
	MaxPluginOperations = 32
	MaxPluginSchema     = 64 << 10
)

type PluginOperation struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Params      json.RawMessage `json:"params_schema"`
}

// PluginInfo is one plugin as an agent found it. A plugin that does not
// answer, or speaks a contract the agent does not serve, is reported with
// Supported false and the reason.
type PluginInfo struct {
	Name       string            `json:"name"`
	Version    string            `json:"version,omitempty"`
	Contract   uint32            `json:"contract,omitempty"`
	Operations []PluginOperation `json:"operations,omitempty"`
	Supported  bool              `json:"supported"`
	Reason     string            `json:"reason,omitempty"`
}

// pluginName is a plugin's name: its socket is <name>.sock and its tools
// will carry the name.
var pluginName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// PluginName reports whether s is a valid plugin name.
func PluginName(s string) bool { return pluginName.MatchString(s) }

// CheckPlugins reports what is wrong with an agent's plugin report, or "".
func CheckPlugins(plugins []PluginInfo) string {
	if len(plugins) > MaxPlugins {
		return fmt.Sprintf("At most %d plugins per node", MaxPlugins)
	}
	seen := map[string]bool{}
	for _, pl := range plugins {
		if !pluginName.MatchString(pl.Name) || seen[pl.Name] {
			return fmt.Sprintf("Plugin name %q is not a unique name of a-z, 0-9 and -", pl.Name)
		}
		seen[pl.Name] = true
		if len(pl.Operations) > MaxPluginOperations {
			return fmt.Sprintf("Plugin %s declares more than %d operations", pl.Name, MaxPluginOperations)
		}
		for _, op := range pl.Operations {
			var schema map[string]any
			if !pluginName.MatchString(op.Name) || len(op.Params) > MaxPluginSchema || json.Unmarshal(op.Params, &schema) != nil {
				return fmt.Sprintf("Plugin %s operation %q needs a name of a-z, 0-9 and - and a JSON object schema", pl.Name, op.Name)
			}
		}
	}
	return ""
}
