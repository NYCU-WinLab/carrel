package carrel

import (
	"net/netip"
	"strings"
	"testing"
)

func TestIPv6MachineAddressMatchesNodeAgent(t *testing.T) {
	p, err := ipv6Prefix("2a14:7581:880::/48")
	if err != nil {
		t.Fatal(err)
	}
	addr, gw, ok := v6Machine(p, 17, "10.200.17.11")
	if !ok || addr != netip.MustParseAddr("2a14:7581:880:17::11") || gw != netip.MustParseAddr("2a14:7581:880:17::1") {
		t.Fatalf("got %v %v %v", addr, gw, ok)
	}
	if a, _, _ := v6Machine(p, 254, "10.200.254.250"); a != netip.MustParseAddr("2a14:7581:880:254::250") {
		t.Fatalf("got %v", a)
	}
	for _, ip := range []string{"10.200.18.11", "10.200.17.1", "10.200.17.255", "nope"} {
		if _, _, ok := v6Machine(p, 17, ip); ok {
			t.Fatalf("%s accepted", ip)
		}
	}
	for _, bad := range []string{"2a14:7581:880::/56", "fd00:1::/48", "10.0.0.0/8", "2a14:7581:880:1::/48", "2001:db8:880::/48", ""} {
		if _, err := ipv6Prefix(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestConfigRejectsABadIPv6Prefix(t *testing.T) {
	c := Config{PublicAddress: "140.113.60.184", Origin: "https://carrel.example", Database: "x", Nodes: []NodeConfig{{Name: "n1"}}, IPv6Prefix: "fd00::/48"}
	if err := c.Validate(); err == nil {
		t.Fatal("private prefix accepted")
	}
}

func TestCheckIPv6Prefix(t *testing.T) {
	node := func(prefix string) D { return D{"ipv6": D{"public_key": "k", "port": 51820, "prefix": prefix}} }
	ok := node("2a14:7581:880::/48")
	checkIPv6Prefix("2a14:7581:880::/48", ok)
	if _, bad := ok["ipv6"].(D)["error"]; bad {
		t.Fatalf("equal prefixes reported %v", ok)
	}
	diff := node("2a14:7581:881::/48")
	checkIPv6Prefix("2a14:7581:880::/48", diff)
	msg, _ := diff["ipv6"].(D)["error"].(string)
	if !strings.Contains(msg, "2a14:7581:881::/48") || !strings.Contains(msg, "2a14:7581:880::/48") {
		t.Fatalf("error does not name both: %q", msg)
	}
	// No ipv6 result, or a site without ipv6: nothing to compare.
	for _, n := range []any{D{}, D{"ipv6": D{"error": "x"}}, "x"} {
		checkIPv6Prefix("2a14:7581:880::/48", n)
	}
	none := node("2a14:7581:880::/48")
	checkIPv6Prefix("", none)
	if _, bad := none["ipv6"].(D)["error"]; bad {
		t.Fatal("site without ipv6 reported")
	}
}
