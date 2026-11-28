package skills

import (
	"strings"
	"testing"
)

const valid = "---\nname: demo\ndescription: A demo.\nversion: 1.2.3\nrequires_tools: [a, b]\nverified:\n---\n\n# Body\n"

func TestParseValid(t *testing.T) {
	s, err := Parse("demo", []byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "demo" || s.Version != "1.2.3" || len(s.RequiresTools) != 2 || s.Verified != "" || !strings.HasPrefix(s.Body, "# Body") {
		t.Fatalf("unexpected skill: %+v", s)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct{ name, dir, text, want string }{
		{"missing field", "demo", strings.Replace(valid, "description: A demo.\n", "", 1), "field description"},
		{"bad semver", "demo", strings.Replace(valid, "1.2.3", "1.2", 1), "field version"},
		{"name mismatch", "other", valid, "field name"},
		{"no frontmatter", "demo", "# hi", "frontmatter"},
	}
	for _, c := range cases {
		_, err := Parse(c.dir, []byte(c.text))
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), c.dir) {
			t.Errorf("%s: error %v, want it to name %q and %q", c.name, err, c.dir, c.want)
		}
	}
}

func TestEmbedded(t *testing.T) {
	all, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Fatal("no skills embedded")
	}
	s, ok, err := Get("rescue")
	if err != nil || !ok || s.Verified != "" {
		t.Fatalf("rescue: %+v %v %v", s, ok, err)
	}
	if _, ok, _ := Get("nope"); ok {
		t.Fatal("Get found a skill that does not exist")
	}
}
