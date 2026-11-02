package carrel

import "strings"

// A suggestion names a Carrel feature that fits what the member just did but
// that the member has not used yet. It travels in the tool result, where the
// agent reads it at the moment of action. Each rule looks only at stored
// state; a rule that fails or finds nothing adds nothing. A result carries at
// most one suggestion so that agents do not learn to skip the field.
type suggestionRule func(e *Execution, tool string, a D, n int, r D) D

var suggestionRules = []suggestionRule{
	suggestAppLinkAfterDomain,
	suggestAppLinkOnMachine,
	suggestSavedKey,
}

func (e *Execution) addSuggestions(tool string, a D, n int, r D) {
	if n == 0 || boolean(a["dry_run"]) || !boolean(r["ok"]) {
		return
	}
	for _, rule := range suggestionRules {
		var s D
		if attempt(func() { s = rule(e, tool, a, n, r) }) == nil && s != nil {
			r["suggestions"] = []D{s}
			return
		}
	}
}

// websiteWithoutApp returns the first HTTPS domain on the machine when no app
// deploys to it: such a site is updated by hand over SSH.
func (e *Execution) websiteWithoutApp(n, vmid int) (domainRecord, bool) {
	if vmid == 0 || find(e.S.Objects("apps", n), func(o D) bool { return integer(o["vmid"]) == vmid }) != nil {
		return domainRecord{}, false
	}
	for _, d := range e.domains(n) {
		if d.VMID == vmid && d.State == "ready" && !strings.HasPrefix(d.Name, "_") {
			return d, true
		}
	}
	return domainRecord{}, false
}

func appLinkSuggestion(machine string, d domainRecord) D {
	return D{
		"tool": "app_link",
		"why":  "https://" + d.Name + " runs on " + machine + " without an app, so each update needs manual SSH work. If its code is in a GitHub repository, app_link deploys every push and rolls back a failed release.",
		"args": D{"machine": machine, "port": d.TargetPort},
	}
}

func (e *Execution) machineName(n, vmid int) string {
	if m := find(e.S.Objects("machines", n), func(m D) bool { return integer(m["vmid"]) == vmid }); m != nil {
		return str(m["name"])
	}
	return ""
}

func suggestAppLinkAfterDomain(e *Execution, tool string, a D, n int, r D) D {
	ops := dicts(r["operations"])
	if op, ok := r["operation"]; ok {
		ops = []D{obj(op)}
	}
	for _, op := range ops {
		if op["tool"] != "domain_add" || op["state"] != "succeeded" {
			continue
		}
		name := str(obj(obj(op["result"])["domain"])["name"])
		for _, d := range e.domains(n) {
			if d.Name != name {
				continue
			}
			if site, ok := e.websiteWithoutApp(n, d.VMID); ok && site.ID == d.ID {
				return appLinkSuggestion(e.machineName(n, d.VMID), d)
			}
		}
	}
	return nil
}

func suggestAppLinkOnMachine(e *Execution, tool string, a D, n int, r D) D {
	if tool != "machine_get" {
		return nil
	}
	for _, m := range dicts(r["machines"]) {
		stored := find(e.S.Objects("machines", n), func(s D) bool { return s["name"] == m["name"] })
		if stored == nil {
			continue
		}
		if d, ok := e.websiteWithoutApp(n, integer(stored["vmid"])); ok {
			return appLinkSuggestion(str(m["name"]), d)
		}
	}
	return nil
}

func suggestSavedKey(e *Execution, tool string, a D, n int, r D) D {
	if tool != "machine_create" || obj(r["operation"])["state"] != "succeeded" {
		return nil
	}
	saved := map[string]bool{}
	for _, k := range rowsOf[sshKey](e.S, "keys", n) {
		saved[keyBody(k.Key)] = true
	}
	for _, k := range arr(a["ssh_keys"]) {
		if key := str(k); key != "" && !saved[keyBody(key)] {
			return D{
				"tool": "ssh_key_add",
				"why":  "This key was passed inline and is not saved. ssh_key_add saves it once, so later machines need no key argument and the jump host admits it.",
			}
		}
	}
	return nil
}

// keyBody compares keys by type and data, ignoring the comment.
func keyBody(key string) string {
	f := strings.Fields(key)
	if len(f) >= 2 {
		return f[0] + " " + f[1]
	}
	return strings.TrimSpace(key)
}
