package carrel

import "testing"

func TestBuildIsADevelopmentBuildUnlessTheReleaseWorkflowSaysSo(t *testing.T) {
	b := Build()
	if b["version"] != Version || b["release"] != false || b["revision"] == "" {
		t.Fatalf("unexpected build %v", b)
	}
	Release = "true"
	defer func() { Release = "false" }()
	if Build()["release"] != true {
		t.Fatal("a release build must say so")
	}
}
