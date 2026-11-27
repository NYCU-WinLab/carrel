package carrel

import (
	"encoding/json"
	"fmt"
	"math"
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
	MaxPluginOperations = 16
	// MaxPluginKinds bounds a plugin's quota dimensions and object kinds,
	// and a kind's charges.
	MaxPluginKinds  = 8
	MaxPluginSchema = 8 << 10
	// MaxPluginText bounds a version, a description or a reason.
	MaxPluginText = 1 << 10
	// MaxPluginReport bounds the whole report as JSON, well inside a claim
	// (maxAgentClaim) beside the ids the agent holds.
	MaxPluginReport = 256 << 10
)

type PluginOperation struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Params      json.RawMessage `json:"params_schema"`
	Member      bool            `json:"member,omitempty"`
	ReadOnly    bool            `json:"read_only,omitempty"`
	Destructive bool            `json:"destructive,omitempty"`
	Idempotent  bool            `json:"idempotent,omitempty"`
	Toolset     string          `json:"toolset,omitempty"`
	// DryRun: the plugin honours dry_run on a start of this operation.
	DryRun bool `json:"dry_run,omitempty"`
	// The object the operation acts on (#663): a kind of the plugin's
	// Objects, the effect (create, delete or use) and the parameter that
	// names the object.
	ObjectKind   string `json:"object_kind,omitempty"`
	ObjectEffect string `json:"object_effect,omitempty"`
	ObjectParam  string `json:"object_param,omitempty"`
	// Stopped: the machine is stopped while it runs; Rewinds: it may bring
	// the disk back to an earlier state.
	Stopped bool `json:"stopped,omitempty"`
	Rewinds bool `json:"rewinds,omitempty"`
}

// PluginQuota is a quota dimension a plugin's objects are charged to.
type PluginQuota struct {
	Name         string  `json:"name"`
	DefaultLimit float64 `json:"default_limit"`
	Unit         string  `json:"unit,omitempty"`
	// Measured: a fresh storage sample counts what the tenant's disk
	// objects hold, not what they were charged.
	Measured bool `json:"measured,omitempty"`
}

// PluginCharge is what one object charges to a dimension: Amount, or
// Amount times the machine's Per (cpu, memory_mb or disk_gb).
type PluginCharge struct {
	Dimension string  `json:"dimension"`
	Amount    float64 `json:"amount"`
	Per       string  `json:"per,omitempty"`
}

// PluginObjectKind is a kind of object carrel keeps a record of.
type PluginObjectKind struct {
	Name    string         `json:"name"`
	Charges []PluginCharge `json:"charges,omitempty"`
	Holds   []string       `json:"holds,omitempty"`
	Disk    bool           `json:"disk,omitempty"`
}

// PluginInfo is one plugin as an agent found it. A plugin that does not
// answer, or speaks a contract the agent does not serve, is reported with
// Supported false and the reason.
type PluginInfo struct {
	Name       string             `json:"name"`
	Version    string             `json:"version,omitempty"`
	Contract   uint32             `json:"contract,omitempty"`
	Operations []PluginOperation  `json:"operations,omitempty"`
	Quota      []PluginQuota      `json:"quota,omitempty"`
	Objects    []PluginObjectKind `json:"objects,omitempty"`
	Supported  bool               `json:"supported"`
	Reason     string             `json:"reason,omitempty"`
}

// pluginName is a plugin's name: its socket is <name>.sock and its tools
// will carry the name.
var pluginName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// pluginDimension is a quota dimension's name, as carrel's own are.
var pluginDimension = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 }

// PluginName reports whether s is a valid plugin name.
func PluginName(s string) bool { return pluginName.MatchString(s) }

// WireLen is the length of s as JSON carries it, quotes left out: an agent
// and the control plane measure the same text the same way, whatever
// escaping or invalid UTF-8 it holds.
func WireLen(s string) int {
	b, _ := json.Marshal(s)
	return len(b) - 2
}

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
		if WireLen(pl.Version) > MaxPluginText || WireLen(pl.Reason) > MaxPluginText {
			return fmt.Sprintf("Plugin %s reports a version or reason over %d bytes", pl.Name, MaxPluginText)
		}
		if len(pl.Quota) > MaxPluginKinds || len(pl.Objects) > MaxPluginKinds {
			return fmt.Sprintf("Plugin %s declares more than %d quota dimensions or object kinds", pl.Name, MaxPluginKinds)
		}
		for _, q := range pl.Quota {
			if !pluginDimension.MatchString(q.Name) || !finite(q.DefaultLimit) || WireLen(q.Unit) > 16 {
				return fmt.Sprintf("Plugin %s quota dimension %q needs a name of a-z, 0-9 and _, a finite limit of 0 or more and a short unit", pl.Name, q.Name)
			}
		}
		for _, k := range pl.Objects {
			if !pluginName.MatchString(k.Name) || len(k.Charges) > MaxPluginKinds || len(k.Holds) > len(pluginHolds) {
				return fmt.Sprintf("Plugin %s object kind %q needs a name of a-z, 0-9 and - and at most %d charges", pl.Name, k.Name, MaxPluginKinds)
			}
			for _, c := range k.Charges {
				if !pluginDimension.MatchString(c.Dimension) || !finite(c.Amount) || WireLen(c.Per) > 16 {
					return fmt.Sprintf("Plugin %s object kind %s charges %q with an amount that is not finite and 0 or more", pl.Name, k.Name, c.Dimension)
				}
			}
			for _, h := range k.Holds {
				if WireLen(h) > 16 {
					return fmt.Sprintf("Plugin %s object kind %s names a hold over 16 bytes", pl.Name, k.Name)
				}
			}
		}
		for _, op := range pl.Operations {
			if WireLen(op.ObjectKind) > 32 || WireLen(op.ObjectEffect) > 16 || WireLen(op.ObjectParam) > 32 {
				return fmt.Sprintf("Plugin %s operation %s names an object kind, effect or parameter too long", pl.Name, op.Name)
			}
			if op.Toolset != "" && !pluginName.MatchString(op.Toolset) {
				return fmt.Sprintf("Plugin %s operation %s names toolset %q, not of a-z, 0-9 and -", pl.Name, op.Name, op.Toolset)
			}
			if WireLen(op.Description) > MaxPluginText {
				return fmt.Sprintf("Plugin %s operation %s has a description over %d bytes", pl.Name, op.Name, MaxPluginText)
			}
			var schema map[string]any
			wire, err := json.Marshal(op.Params)
			if !pluginName.MatchString(op.Name) || err != nil || len(wire) > MaxPluginSchema || json.Unmarshal(op.Params, &schema) != nil {
				return fmt.Sprintf("Plugin %s operation %q needs a name of a-z, 0-9 and - and a JSON object schema", pl.Name, op.Name)
			}
		}
	}
	if b, _ := json.Marshal(plugins); len(b) > MaxPluginReport {
		return fmt.Sprintf("The plugin report is over %d bytes", MaxPluginReport)
	}
	return ""
}
