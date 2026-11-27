package carrel

import (
	"fmt"
	"sort"
	"time"
)

// pluginToolRows keeps, in the site table, every plugin tool a node has
// listed. While no node reports its plugin, as during an agent restart, a
// call answers that the plugin is unavailable instead of an unknown tool,
// and quota_get still shows the storage of its object kind. A row stays
// after its plugin leaves the site for good.
const pluginToolRows = "plugin_tools"

// rememberPluginTools writes the listed tools when they differ from the
// last write: the registry is read on every list and call.
func (p *Platform) rememberPluginTools(tools map[string]*pluginTool, quota []D) {
	names := make([]string, 0, len(tools))
	for name := range tools {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := []D{}
	for _, name := range names {
		t := tools[name]
		dims := t.Dims
		if dims == nil {
			dims = []string{}
		}
		rows = append(rows, D{"name": name, "plugin": t.Plugin, "member": t.Member, "read_only": t.ReadOnly, "kind": t.ObjectKind, "dims": dims})
	}
	key := digest(string(encoded([]any{rows, quota})))
	p.rememberMu.Lock()
	defer p.rememberMu.Unlock()
	if key == p.remembered {
		return
	}
	for _, r := range rows {
		p.Store.SitePut(pluginToolRows, str(r["name"]), r)
	}
	// A dimension's row follows what its plugin reports now, so a default a
	// later version changes holds while the plugin is unreported (#680).
	for _, q := range quota {
		p.Store.SitePut(pluginQuotaRows, str(q["name"]), q)
	}
	p.remembered = key
}

// rememberedTool is the row of a plugin tool a node listed before, or nil.
func (p *Platform) rememberedTool(name string) D {
	if coreTools[name] {
		return nil
	}
	if r := p.Store.SiteGet(pluginToolRows, name); len(r) > 0 {
		return r
	}
	return nil
}

// refuseUnreported fails a call of a plugin tool that no node reports now.
func (e *Execution) refuseUnreported(tool string, w D) {
	r := e.P.rememberedTool(tool)
	if r == nil {
		return
	}
	if !boolean(r["member"]) && !boolean(w["admin"]) {
		fail("forbidden", "winlab-admin membership required")
	}
	fail("unavailable", fmt.Sprintf("No node reports the %s plugin now; try again in a minute", str(r["plugin"])),
		D{"recovery": "retry", "plugin": r["plugin"]})
}

// reportedQuota are the plugin quota dimensions the nodes report now, as
// their site rows hold them.
func (p *Platform) reportedQuota(now time.Time) []D {
	seen := map[string]D{}
	for _, n := range p.Config.Nodes {
		for _, pl := range p.Hub.Plugins(n.Name, now) {
			if !pl.Supported {
				continue
			}
			for _, q := range pl.Quota {
				if _, core := DefaultQuota[q.Name]; !core && pluginDimension.MatchString(q.Name) && seen[q.Name] == nil {
					seen[q.Name] = D{"name": q.Name, "default_limit": q.DefaultLimit, "unit": q.Unit, "measured": q.Measured, "plugin": pl.Name}
				}
			}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	out := []D{}
	for _, name := range names {
		out = append(out, seen[name])
	}
	return out
}
