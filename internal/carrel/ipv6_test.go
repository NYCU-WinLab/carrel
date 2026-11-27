package carrel

import (
	"context"
	"net/netip"
	"testing"
)

func TestIPv6MachineAddressMatchesNodeAgent(t *testing.T) {
	p, err := ipv6Prefix("2a14:7581:880::/48")
	if err != nil {
		t.Fatal(err)
	}
	addr, gw, ok := v6Machine(p, 17, "10.200.17.11")
	if !ok || addr != netip.MustParseAddr("2a14:7581:880:170::11") || gw != netip.MustParseAddr("2a14:7581:880:170::1") {
		t.Fatalf("got %v %v %v", addr, gw, ok)
	}
	if a, _, _ := v6Machine(p, 254, "10.200.254.250"); a != netip.MustParseAddr("2a14:7581:880:2540::250") {
		t.Fatalf("got %v", a)
	}
	for _, ip := range []string{"10.200.18.11", "10.200.17.1", "10.200.17.255", "nope"} {
		if _, _, ok := v6Machine(p, 17, ip); ok {
			t.Fatalf("%s accepted", ip)
		}
	}
	p44, err := ipv6Prefix("2a14:7581:880::/44")
	if err != nil {
		t.Fatal(err)
	}
	if a, gw, _ := v6Machine(p44, 17, "10.200.17.11"); a != netip.MustParseAddr("2a14:7581:880:1700::11") || gw != netip.MustParseAddr("2a14:7581:880:1700::1") {
		t.Fatalf("/44 pool: %v %v", a, gw)
	}
	if n := v6Net(p44, 254); n != netip.MustParsePrefix("2a14:7581:882:5400::/64") {
		t.Fatalf("/44 pool: %v", n)
	}
	for _, bad := range []string{"2a14:7581:880::/56", "2a14:7581:880::/53", "2a14::/16", "fd00:1::/48", "10.0.0.0/8", "2a14:7581:880:1::/48", "2001:db8:880::/48", ""} {
		if _, err := ipv6Prefix(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestConfigRejectsABadIPv6Prefix(t *testing.T) {
	c := Config{PublicAddress: "140.113.60.184", Origin: "https://carrel.winlab.tw", Database: "x", Nodes: []NodeConfig{{Name: "n1"}}, IPv6Prefix: "fd00::/48"}
	if err := c.Validate(); err == nil {
		t.Fatal("private prefix accepted")
	}
}

func TestStatusShowsTheIPv6TunnelFromReconcile(t *testing.T) {
	p, b := fixture(t)
	p.Config.IPv6Prefix = "2a14:7581:880::/48"
	var node D
	b.call = func(r D, _ string) (any, error) {
		if r["op"] == "reconcile" {
			return node, nil
		}
		return D{}, nil
	}
	status := func() D {
		e := p.execution(context.Background())
		e.Reconcile()
		return e.PublicStatus()
	}
	node = D{"ipv6": D{"public_key": "pub=", "port": 51821}}
	if v6 := obj(status()["ipv6"]); v6["public_key"] != "pub=" || integer(v6["port"]) != 51821 {
		t.Fatalf("key and port: %s", encoded(v6))
	}
	node = D{"ipv6": D{"error": "CommandFailure: wg missing"}}
	if v6 := obj(status()["ipv6"]); v6["error"] != "CommandFailure: wg missing" || v6["public_key"] != nil {
		t.Fatalf("error: %s", encoded(v6))
	}
	node = D{"changed": []any{}}
	if s := status(); s["ipv6"] != nil {
		t.Fatalf("no ipv6 must show nothing: %s", encoded(s))
	}
}
