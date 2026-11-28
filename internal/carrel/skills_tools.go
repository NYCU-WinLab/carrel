package carrel

// skills_list and skill_get serve the embedded skills (PLAN 4.5.2, #851). Both
// only read. Config.SkillsHidden removes names from both, so a bench can hide
// a skill for its control arm.

import (
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
