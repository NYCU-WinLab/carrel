package carrel

// Phases are the slow steps an async tool runs outside the infrastructure
// writer. Each tool's own file registers them from an init function.
type Phases struct {
	Prepare func(*Execution)
	Perform func(*Execution)
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
