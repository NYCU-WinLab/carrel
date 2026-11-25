package carrel

import "testing"

// done is true exactly in the terminal states (#583), and the summary of a
// succeeded operation keeps it.
func TestOperationDoneFollowsTheTerminalStates(t *testing.T) {
	for state, want := range map[string]bool{
		"queued": false, "running": false, "waiting": false, "cleaning_up": false,
		"succeeded": true, "failed": true, "rolled_back": true, "cleanup_failed": true,
	} {
		if got := publicOperation(D{"id": "op", "state": state})["done"]; got != want {
			t.Fatalf("%s: done %v", state, got)
		}
	}
	if operationSummary(publicOperation(D{"id": "op", "state": "succeeded"}))["done"] != true {
		t.Fatal("summary dropped done")
	}
}
