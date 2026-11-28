package carrel

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func skillSession(t *testing.T, p *Platform, sel selection) *mcp.ClientSession {
	t.Helper()
	app := NewApp(p, nil)
	ctx := context.WithValue(context.Background(), identityKey{}, person("alice", false))
	ct, st := mcp.NewInMemoryTransports()
	ss, err := app.mcpServer(false, sel).Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func callText(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	r, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return r.Content[0].(*mcp.TextContent).Text, r.IsError
}

func TestSkillToolsOverMCP(t *testing.T) {
	p, _ := fixture(t)
	for _, sel := range []selection{{}, {readOnly: true}} {
		cs := skillSession(t, p, sel)
		if out, bad := callText(t, cs, "skills_list", nil); bad || !strings.Contains(out, "rescue") {
			t.Fatalf("skills_list %+v: %s", sel, out)
		}
		if out, bad := callText(t, cs, "skill_get", map[string]any{"name": "rescue"}); bad || !strings.Contains(out, "rescue") || !strings.Contains(out, "machine_get") {
			t.Fatalf("skill_get %+v: %s", sel, out)
		}
		if out, bad := callText(t, cs, "skill_get", map[string]any{"name": "nope"}); !bad || !strings.Contains(out, "Valid names: rescue") {
			t.Fatalf("unknown skill %+v: %s", sel, out)
		}
	}
}

func TestHiddenSkillIsAbsent(t *testing.T) {
	p, _ := fixture(t)
	p.Config.SkillsHidden = []string{"rescue"}
	cs := skillSession(t, p, selection{})
	if out, _ := callText(t, cs, "skills_list", nil); strings.Contains(out, "rescue") {
		t.Fatalf("hidden skill listed: %s", out)
	}
	if out, bad := callText(t, cs, "skill_get", map[string]any{"name": "rescue"}); !bad || strings.Contains(out, "machine_get") || strings.Contains(out, "Valid names: rescue") {
		t.Fatalf("hidden skill served: %s", out)
	}
}
