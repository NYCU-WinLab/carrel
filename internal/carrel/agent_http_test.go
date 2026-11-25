package carrel

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func agentRequest(t *testing.T, p *Platform, path, token, from, body string) int {
	t.Helper()
	req := httptest.NewRequest("POST", "https://10.200.0.3:8443"+path, strings.NewReader(body))
	req.RemoteAddr = from + ":40000"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	p.AgentHandler().ServeHTTP(w, req)
	return w.Code
}

// Only the node's own token from the node's own address reaches the hub;
// a node on SSH has no agent at all.
func TestAgentRoutesCheckTokenAndSource(t *testing.T) {
	p, _, _ := originFixture(t)
	p.Config.Nodes = []NodeConfig{
		{Name: "pve1", Target: "carrel-node", Transport: "agent", AgentTokenSHA256: digest("cat_good"), AgentSource: "10.200.0.1"},
		{Name: "pve2", Target: "carrel02", AgentTokenSHA256: digest("cat_good"), AgentSource: "10.200.0.1"},
	}
	body := `{"session":"s","seq":1,"held":[]}`
	for _, c := range []struct {
		token, from, node string
		want              int
	}{
		{"", "10.200.0.1", "pve1", 403},
		{"cat_bad", "10.200.0.1", "pve1", 403},
		{"cat_good", "10.200.0.9", "pve1", 403},
		{"cat_good", "10.200.0.1", "pve2", 403},
		{"cat_good", "10.200.0.1", "nobody", 403},
	} {
		if code := agentRequest(t, p, "/sites/v1/agent/claim?node="+c.node, c.token, c.from, body); code != c.want {
			t.Errorf("%+v: %d", c, code)
		}
	}
	if code := agentRequest(t, p, "/sites/v1/agent/claim?node=pve1", "cat_good", "10.200.0.1", `{}`); code != 400 {
		t.Fatalf("no session: %d", code)
	}
	if code := agentRequest(t, p, "/sites/v1/agent/jobs/x?node=pve1", "cat_bad", "10.200.0.1", "{}"); code != 403 {
		t.Fatalf("answer with a bad token: %d", code)
	}
	if code := agentRequest(t, p, "/sites/v1/agent/jobs/x?node=pve1", "cat_good", "10.200.0.1", "{}"); code != 200 {
		t.Fatalf("answer to an unknown job: %d", code)
	}
	if len(p.Hub.nodes) != 1 {
		t.Fatalf("refused requests reached the hub: %v", p.Hub.nodes)
	}
}

func TestAgentTransportConfig(t *testing.T) {
	base := func(n NodeConfig, listen bool) Config {
		c := Config{PublicAddress: "192.0.2.1", Origin: "https://carrel.test", Database: "x", Nodes: []NodeConfig{n}}
		if listen {
			c.AgentListen, c.AgentCertFile, c.AgentKeyFile = "10.200.0.3:8443", "/c", "/k"
		}
		return c.WithDefaults()
	}
	good := NodeConfig{Name: "pve1", Target: "pve1", Transport: "agent", AgentTokenSHA256: digest("x"), AgentSource: "10.200.0.1"}
	if err := base(good, true).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		node   NodeConfig
		listen bool
		want   string
	}{
		{good, false, "agent_listen"},
		{NodeConfig{Name: "pve1", Target: "pve1", Transport: "telnet"}, false, "transport"},
		{NodeConfig{Name: "pve1", Target: "pve1", Transport: "agent", AgentSource: "10.200.0.1"}, true, "agent_token_sha256"},
		{NodeConfig{Name: "pve1", Target: "pve1", Transport: "agent", AgentTokenSHA256: digest("x")}, true, "agent_source"},
	} {
		if err := base(c.node, c.listen).Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v", c, err)
		}
	}
}

// An agent on a protocol this control plane no longer serves is refused with
// the release to install, before the hub sees it; a served one is recorded
// for node_list (#561).
func TestAgentProtocolIsChecked(t *testing.T) {
	p, _, _ := originFixture(t)
	p.Config.Nodes = []NodeConfig{
		{Name: "pve1", Target: "carrel-node", Transport: "agent", AgentTokenSHA256: digest("cat_good"), AgentSource: "10.200.0.1"},
	}
	claim := func(body string) (int, string) {
		req := httptest.NewRequest("POST", "https://10.200.0.3:8443/sites/v1/agent/claim?node=pve1", strings.NewReader(body))
		req.RemoteAddr = "10.200.0.1:40000"
		req.Header.Set("Authorization", "Bearer cat_good")
		w := httptest.NewRecorder()
		p.AgentHandler().ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	for _, old := range []string{`"protocol":"v0",`, ``} {
		code, body := claim(`{` + old + `"session":"s","seq":1,"held":[],"drain":true}`)
		if code != 426 || !strings.Contains(body, "protocol_unsupported") || !strings.Contains(body, "release "+Version) {
			t.Fatalf("%q: %d %s", old, code, body)
		}
	}
	if s := p.Hub.Status("pve1", time.Now()); s["connected"] != false {
		t.Fatalf("a refused agent was recorded: %v", s)
	}
	for i, protocol := range agentProtocols {
		code, body := claim(fmt.Sprintf(`{"protocol":%q,"release":"0.11.0","session":"s","seq":%d,"held":[],"drain":true}`, protocol, i+1))
		if code != 200 {
			t.Fatalf("%s: %d %s", protocol, code, body)
		}
	}
	s := p.Hub.Status("pve1", time.Now())
	if s["connected"] != true || s["protocol"] != AgentProtocol || s["release"] != "0.11.0" {
		t.Fatalf("status %v", s)
	}
	if s := p.Hub.Status("pve1", time.Now().Add(agentSilence)); s["connected"] != false {
		t.Fatalf("a silent agent still connected: %v", s)
	}
}

// node_list shows an agent node that cannot answer, with its agent status,
// and still lists the other nodes; one node alone keeps the status too.
func TestNodeListShowsAnAgentThatDoesNotAnswer(t *testing.T) {
	p, _, _ := nodeFixture(t)
	p.Config.Nodes[1].Transport = "agent"
	admin := person("admin", true)
	nodes := dicts(p.execution(context.Background()).Admin("node_list", D{}, admin)["nodes"])
	if len(nodes) != 3 || obj(nodes[1]["error"])["code"] != "agent_not_connected" || obj(nodes[1]["agent"])["connected"] != false {
		t.Fatal(encoded(nodes))
	}
	if obj(nodes[2]["inventory"])["node"] != "carrel03" || nodes[0]["agent"] != nil {
		t.Fatal(encoded(nodes))
	}
	p.Hub.Hello(p.Config.Nodes[1].Name, "s", "v1", "0.11.0")
	p.Hub.Heartbeat(p.Config.Nodes[1].Name, "s", 1, nil)
	nodes = dicts(p.execution(context.Background()).Admin("node_list", D{}, admin)["nodes"])
	if a := obj(nodes[1]["agent"]); a["connected"] != true || a["release"] != "0.11.0" || nodes[1]["inventory"] == nil {
		t.Fatal(encoded(nodes[1]))
	}
	p.Config.Nodes = p.Config.Nodes[1:2]
	p.Hub = NewAgentHub()
	one := p.execution(context.Background()).Admin("node_list", D{}, admin)
	if obj(one["agent"])["connected"] != false || obj(one["error"])["code"] != "agent_not_connected" {
		t.Fatal(encoded(one))
	}
}

// A replaced agent process's late poll does not overwrite what the new one
// reported.
func TestAgentHelloIgnoresAReplacedProcess(t *testing.T) {
	hub := NewAgentHub()
	hub.Hello("pve1", "old", "v1", "0.11.0")
	hub.Heartbeat("pve1", "old", 1, nil)
	hub.Hello("pve1", "new", "v1", "0.12.0")
	hub.Heartbeat("pve1", "new", 1, nil)
	hub.Hello("pve1", "old", "v1", "0.11.0")
	if s := hub.Status("pve1", time.Now()); s["release"] != "0.12.0" {
		t.Fatalf("status %v", s)
	}
}

// A stream is taken only by the node's own agent, with the stream upgrade,
// for a stream its current process was handed, and once.
func TestAgentStreamRouteRefusesStrangers(t *testing.T) {
	p, _, _ := originFixture(t)
	p.Config.Nodes = []NodeConfig{
		{Name: "pve1", Target: "carrel-node", Transport: "agent", AgentTokenSHA256: digest("cat_good"), AgentSource: "10.200.0.1"},
		{Name: "pve2", Target: "carrel02", Transport: "agent", AgentTokenSHA256: digest("cat_two"), AgentSource: "10.200.0.2"},
	}
	open := func(id, node, token, from, upgrade string) int {
		req := httptest.NewRequest("GET", "https://10.200.0.3:8443/sites/v1/agent/streams/"+id+"?node="+node, nil)
		req.RemoteAddr = from + ":40000"
		req.Header.Set("Authorization", "Bearer "+token)
		if upgrade != "" {
			req.Header.Set("Upgrade", upgrade)
		}
		w := httptest.NewRecorder()
		p.AgentHandler().ServeHTTP(w, req)
		return w.Code
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _, _ = p.Hub.Stream(ctx, D{"op": "console"}, "pve1") }()
	var id string
	deadline := time.Now().Add(5 * time.Second)
	for id == "" && time.Now().Before(deadline) {
		for _, j := range p.Hub.Claim(ctx, "pve1", "s", 1, nil, 100*time.Millisecond) {
			if j.Stream {
				id = j.ID
			}
		}
	}
	if id == "" {
		t.Fatal("the claim did not hand out the stream")
	}
	for _, c := range []struct {
		node, token, from, upgrade string
		want                       int
	}{
		{"pve1", "cat_bad", "10.200.0.1", "carrel-stream", 403},
		{"pve1", "cat_good", "10.200.0.9", "carrel-stream", 403},
		{"pve2", "cat_two", "10.200.0.2", "carrel-stream", 404},
		{"pve1", "cat_good", "10.200.0.1", "websocket", 400},
		{"pve1", "cat_good", "10.200.0.1", "", 400},
	} {
		if code := open(id, c.node, c.token, c.from, c.upgrade); code != c.want {
			t.Errorf("%+v: %d", c, code)
		}
	}
	if code := open("nothing", "pve1", "cat_good", "10.200.0.1", "carrel-stream"); code != 404 {
		t.Errorf("unknown stream: %d", code)
	}
	// A connection that cannot be taken over ends the stream; it is taken
	// once.
	if code := open(id, "pve1", "cat_good", "10.200.0.1", "carrel-stream"); code != 500 {
		t.Errorf("recorder: %d", code)
	}
	if code := open(id, "pve1", "cat_good", "10.200.0.1", "carrel-stream"); code != 404 {
		t.Errorf("second attach: %d", code)
	}
}

// A stream whose agent never connects back fails within its wait, and leaves
// nothing behind.
func TestAgentStreamThatNobodyOpens(t *testing.T) {
	hub := NewAgentHub()
	hub.streamWait = 200 * time.Millisecond
	if _, err := hub.Stream(context.Background(), D{"op": "console"}, "pve1"); err == nil {
		t.Fatal("a stream nobody opened succeeded")
	}
	if len(hub.nodes["pve1"].streams) != 0 {
		t.Fatal("the stream was left behind")
	}
}
