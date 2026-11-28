package carrel

// Phases are the slow steps an async tool runs outside the infrastructure
// writer. Each tool's own file registers them from an init function.
type Phases struct {
	Prepare func(*Execution)
	Perform func(*Execution)
	// Finish runs under the infrastructure writer and returns the fields
	// merged into the operation result.
	Finish func(*Execution, D) D
}

var operationPhases = map[string]Phases{}

func registerPhases(p Phases, tools ...string) {
	for _, tool := range tools {
		operationPhases[tool] = p
	}
}

// phasesOf are an operation's phases. A plugin operation's come from its
// record, not from the tool name, so they hold after a restart before any
// agent reports the plugin again.
func phasesOf(op D) (Phases, bool) {
	if p, ok := operationPhases[str(op["tool"])]; ok {
		return p, true
	}
	if op["plugin"] != nil {
		return pluginPhases, true
	}
	return Phases{}, false
}

func (e *Execution) runPhases() {
	p, ok := phasesOf(e.Op)
	if !ok {
		return
	}
	if p.Prepare != nil {
		p.Prepare(e)
	}
	if p.Perform != nil {
		p.Perform(e)
	}
}

func (e *Execution) runFinish(t D) D {
	if p, ok := phasesOf(e.Op); ok && p.Finish != nil {
		return p.Finish(e, t)
	}
	return nil
}
