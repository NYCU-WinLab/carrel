package carrel

// skills_list and skill_get serve the embedded skills (PLAN 4.5.2, #851). Both
// only read. Config.SkillsHidden removes names from both, so a bench can hide
// a skill for its control arm.

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/NYCU-WinLab/carrel/skills"
)

// visibleSkills is every embedded skill not hidden by the configuration.
func (e *Execution) visibleSkills() []skills.Skill {
	all, err := skills.List()
	if err != nil {
		fail("internal", "skills are unavailable: "+err.Error())
	}
	hidden := map[string]bool{}
	for _, n := range e.P.Config.SkillsHidden {
		hidden[n] = true
	}
	out := []skills.Skill{}
	for _, s := range all {
		if !hidden[s.Name] {
			out = append(out, s)
		}
	}
	return out
}

func (e *Execution) skillsList() D {
	list := []D{}
	for _, s := range e.visibleSkills() {
		list = append(list, D{"name": s.Name, "description": s.Description, "version": s.Version})
	}
	return D{"skills": list}
}

func (e *Execution) skillGet(name string) D {
	names := []string{}
	for _, s := range e.visibleSkills() {
		if s.Name == name {
			return D{"skill": D{"name": s.Name, "description": s.Description, "version": s.Version, "requires_tools": s.RequiresTools, "verified": s.Verified, "body": s.Body}}
		}
		names = append(names, s.Name)
	}
	sort.Strings(names)
	fail("not_found", "Unknown skill "+name+". Valid names: "+strings.Join(names, ", "))
	return nil
}

// skillErrorWindow is how many of a session's next calls count against a
// skill read: the same 20 calls PLAN 4.6 attaches to an issue.
const skillErrorWindow = 20

// skillUsage is the skills section of usage_report: per skill and version,
// how often it was read, and how many error results followed in the same
// session within the next skillErrorWindow calls. The audit log has no session
// id, so a caller (the actor) stands for its session.
func (e *Execution) skillUsage() []D {
	type key struct{ name, version string }
	type count struct{ reads, errors int }
	counts := map[key]*count{}
	byActor := map[string][]D{}
	for _, r := range e.S.Rows("SELECT actor,tool,args,outcome FROM audit ORDER BY id") {
		byActor[str(r["actor"])] = append(byActor[str(r["actor"])], r)
	}
	for _, calls := range byActor {
		for i, c := range calls {
			if c["tool"] != "skill_get" || c["outcome"] != "ok" {
				continue
			}
			var args D
			_ = json.Unmarshal([]byte(str(c["args"])), &args)
			k := key{str(args["name"]), str(args["skill_version"])}
			if counts[k] == nil {
				counts[k] = &count{}
			}
			counts[k].reads++
			for _, next := range calls[i+1 : min(i+1+skillErrorWindow, len(calls))] {
				if o := str(next["outcome"]); o != "ok" && o != "queued" {
					counts[k].errors++
				}
			}
		}
	}
	out := []D{}
	for k, c := range counts {
		out = append(out, D{"name": k.name, "version": k.version, "reads": c.reads, "errors_after": c.errors})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i]["name"] != out[j]["name"] {
			return str(out[i]["name"]) < str(out[j]["name"])
		}
		return str(out[i]["version"]) < str(out[j]["version"])
	})
	return out
}
