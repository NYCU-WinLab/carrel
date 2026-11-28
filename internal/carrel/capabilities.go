package carrel

import "fmt"

// A feature is a group of tools a site may lack (PLAN 8.5). check names why
// this site lacks it, or returns "" when it has it. Every site has the core.
type feature struct {
	name  string
	tools []string
	check func(p *Platform) string
}

// features are decided from the configuration alone, so catalog_get and
// the gate never call a node.
var features = []feature{
	// Guest storage must be a ZFS pool (node-agent.py), so every site has it.
	{"snapshot", []string{"snapshot_create", "snapshot_list", "snapshot_delete", "snapshot_rollback"}, func(*Platform) string { return "" }},
	{"machine_freeze", []string{"machine_freeze", "machine_thaw"}, func(p *Platform) string {
		if p.Config.BackupStorage == "" {
			return "The site has no backup storage (backup_storage) to freeze machines to"
		}
		return ""
	}},
	// node_undrain stays open: it undoes a drain made when there were more nodes.
	{"machine_migrate", []string{"machine_migrate", "node_drain"}, func(p *Platform) string {
		if len(p.Config.Nodes) < 2 {
			return "The site has one node, so there is nowhere to move a machine"
		}
		return ""
	}},
	{"image_import", []string{"image_import", "iso_import"}, func(p *Platform) string {
		if !p.Config.Fetch {
			return "The site has no image fetcher (fetch)"
		}
		return ""
	}},
	{"services", []string{"service_deploy"}, func(p *Platform) string {
		if len(p.Config.ServiceHosts) == 0 {
			return "The site has no service host (service_hosts)"
		}
		return ""
	}},
}

// siteName is this control plane's one site until a second one joins (8.4).
func (p *Platform) siteName() string {
	if p.Config.Site != "" {
		return p.Config.Site
	}
	return "default"
}

// sites is what catalog_get shows: each site and, for every feature, whether
// it has it and why not.
func (p *Platform) sites() []D {
	out := D{}
	for _, f := range features {
		if reason := f.check(p); reason != "" {
			out[f.name] = D{"available": false, "reason": reason, "tools": f.tools}
		} else {
			out[f.name] = D{"available": true, "tools": f.tools}
		}
	}
	return []D{{"name": p.siteName(), "features": out, "plugins": p.pluginCatalog()}}
}

// requireFeature fails a tool whose feature the site lacks, naming the
// sites that have it.
func (p *Platform) requireFeature(tool string) {
	for _, f := range features {
		for _, t := range f.tools {
			if t != tool {
				continue
			}
			reason := f.check(p)
			if reason == "" {
				return
			}
			have := []string{}
			for _, s := range p.sites() {
				if obj(obj(s["features"])[f.name])["available"] == true {
					have = append(have, str(s["name"]))
				}
			}
			fail("unsupported", fmt.Sprintf("This site does not support %s: %s", f.name, reason),
				D{"feature": f.name, "site": p.siteName(), "sites_with_feature": have, "recovery": "revise_request"})
		}
	}
}
