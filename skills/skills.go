// Package skills holds the skills carrel serves to agents (PLAN 4.5.2): one
// SKILL.md per directory, embedded into the binary.
package skills

import (
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
)

//go:embed */SKILL.md
var source embed.FS

// Skill is one parsed SKILL.md.
type Skill struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	Version       string   `json:"version"`
	RequiresTools []string `json:"requires_tools"`
	Verified      string   `json:"verified"`
	Body          string   `json:"body"`
}

var (
	semver    = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
	namePart  = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	knownKeys = map[string]bool{"name": true, "description": true, "version": true, "requires_tools": true, "verified": true}
)

// Parse reads one SKILL.md. dir is the directory name the file lives in; the
// name field must equal it. Errors name the skill and the field.
func Parse(dir string, data []byte) (Skill, error) {
	label := dir
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	rest, ok := strings.CutPrefix(text, "---\n")
	if !ok {
		return Skill{}, fmt.Errorf("skill %q: frontmatter: file must start with ---", label)
	}
	head, body, ok := strings.Cut(rest, "\n---\n")
	if !ok {
		if head, ok = strings.CutSuffix(rest, "\n---"); !ok {
			return Skill{}, fmt.Errorf("skill %q: frontmatter: closing --- not found", label)
		}
	}
	vals := map[string]string{}
	var lists = map[string][]string{}
	for _, line := range strings.Split(head, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || !knownKeys[k] {
			return Skill{}, fmt.Errorf("skill %q: frontmatter: unknown or malformed line %q", label, line)
		}
		if _, dup := vals[k]; dup {
			return Skill{}, fmt.Errorf("skill %q: field %s: given twice", label, k)
		}
		vals[k] = v
		if k == "requires_tools" {
			if !strings.HasPrefix(v, "[") || !strings.HasSuffix(v, "]") {
				return Skill{}, fmt.Errorf("skill %q: field requires_tools: must be a list like [a, b]", label)
			}
			for _, item := range strings.Split(v[1:len(v)-1], ",") {
				if item = strings.Trim(strings.TrimSpace(item), `"'`); item != "" {
					lists[k] = append(lists[k], item)
				}
			}
		}
	}
	for _, k := range []string{"name", "description", "version", "requires_tools"} {
		if _, ok := vals[k]; !ok {
			return Skill{}, fmt.Errorf("skill %q: field %s: missing", label, k)
		}
	}
	s := Skill{
		Name:          vals["name"],
		Description:   vals["description"],
		Version:       vals["version"],
		RequiresTools: lists["requires_tools"],
		Verified:      vals["verified"],
		Body:          strings.TrimLeft(body, "\n"),
	}
	if !namePart.MatchString(s.Name) {
		return Skill{}, fmt.Errorf("skill %q: field name: %q must be lowercase words joined by hyphens", label, s.Name)
	}
	if s.Name != dir {
		return Skill{}, fmt.Errorf("skill %q: field name: %q does not match the directory", label, s.Name)
	}
	if s.Description == "" {
		return Skill{}, fmt.Errorf("skill %q: field description: empty", label)
	}
	if !semver.MatchString(s.Version) {
		return Skill{}, fmt.Errorf("skill %q: field version: %q is not SemVer", label, s.Version)
	}
	if len(s.RequiresTools) == 0 {
		return Skill{}, fmt.Errorf("skill %q: field requires_tools: empty", label)
	}
	return s, nil
}

func load(fsys fs.FS) ([]Skill, error) {
	dirs, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	var out []Skill
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		data, err := fs.ReadFile(fsys, d.Name()+"/SKILL.md")
		if err != nil {
			continue
		}
		s, err := Parse(d.Name(), data)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// List returns every embedded skill sorted by name. It fails on the first
// invalid skill.
func List() ([]Skill, error) { return load(source) }

// Get returns the skill with the given name.
func Get(name string) (Skill, bool, error) {
	all, err := List()
	if err != nil {
		return Skill{}, false, err
	}
	for _, s := range all {
		if s.Name == name {
			return s, true, nil
		}
	}
	return Skill{}, false, nil
}
