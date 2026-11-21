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

func (e *Execution) runPhases() {
	p, ok := operationPhases[str(e.Op["tool"])]
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
	if p, ok := operationPhases[str(e.Op["tool"])]; ok && p.Finish != nil {
		return p.Finish(e, t)
	}
	return nil
}
