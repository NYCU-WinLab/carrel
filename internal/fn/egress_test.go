//go:build linux

package fn

import (
	"net/netip"
	"strings"
	"testing"
)

func TestEgressLinksDoNotOverlap(t *testing.T) {
	seen := map[string]int{}
	network := netip.MustParsePrefix(egressNet)
	for n := range maxEgress {
		host, inside, err := egressAddrs(n)
		if err != nil {
			t.Fatal(err)
		}
		for _, address := range []string{host, inside} {
			if other, ok := seen[address]; ok {
				t.Fatalf("link %d and link %d share %s", n, other, address)
			}
			seen[address] = n
			if !network.Contains(netip.MustParseAddr(address)) {
				t.Fatalf("link %d: %s is outside %s", n, address, egressNet)
			}
		}
		link := netip.PrefixFrom(netip.MustParseAddr(host), 30).Masked()
		if !link.Contains(netip.MustParseAddr(inside)) || link.Addr() == netip.MustParseAddr(host) {
			t.Fatalf("link %d: %s and %s are not the two hosts of one /30", n, host, inside)
		}
	}
	for _, n := range []int{-1, maxEgress} {
		if _, _, err := egressAddrs(n); err == nil {
			t.Fatalf("link %d accepted", n)
		}
	}
}

// Every address a function must not reach has to be in the blocked list,
// and a public address must not be.
func TestBlockedCoversPrivateAddresses(t *testing.T) {
	var prefixes []netip.Prefix
	for _, entry := range blocked {
		prefixes = append(prefixes, netip.MustParsePrefix(entry))
	}
	covered := func(address string) bool {
		for _, prefix := range prefixes {
			if prefix.Contains(netip.MustParseAddr(address)) {
				return true
			}
		}
		return false
	}
	for _, address := range []string{
		"10.200.0.2",      // the platform gateway
		"10.200.17.10",    // a tenant machine
		"10.251.0.1",      // the function host's end of a link
		"172.16.0.1",      // the namespace's end of the guest link
		"192.168.19.101",  // a node
		"169.254.169.254", // a metadata service
		"100.100.1.4",     // a tailnet host
		"127.0.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "240.0.0.1",
	} {
		if !covered(address) {
			t.Errorf("%s is not blocked", address)
		}
	}
	for _, address := range []string{"1.1.1.1", "8.8.8.8", "140.113.60.184", "172.32.0.1", "11.0.0.1", "100.128.0.1", "223.255.255.1"} {
		if covered(address) {
			t.Errorf("%s is public but blocked", address)
		}
	}
	if !covered(strings.Split(egressNet, "/")[0]) {
		t.Errorf("the egress network %s is not blocked", egressNet)
	}
}

func TestEgressResolveChecksWhatGoesIntoRules(t *testing.T) {
	good, err := Egress{Uplink: "ens18", Blocked: []string{"140.113.60.189", "140.113.194.0/24"}}.resolve()
	if err != nil {
		t.Fatal(err)
	}
	if good.Blocked[0] != "140.113.60.189/32" || good.Blocked[1] != "140.113.194.0/24" {
		t.Fatalf("blocked = %v", good.Blocked)
	}
	for _, bad := range []Egress{
		{Uplink: `ens18" accept; #`},
		{Uplink: "cfnv3"},
		{Uplink: "interface-name-too-long"},
		{Uplink: "ens18", Blocked: []string{"example.com"}},
		{Uplink: "ens18", Blocked: []string{"1.1.1.1 } accept"}},
		{Uplink: "ens18", Blocked: []string{"2001:db8::/32"}},
	} {
		if _, err := bad.resolve(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

// The rules a reviewer asked for must stay: no forged source, no untracked
// packet, one way out, and nothing the namespace starts on its own.
func TestRulesKeepTheirGuards(t *testing.T) {
	e := Egress{Uplink: "ens18", Blocked: []string{"140.113.60.189/32"}}
	host, inside := hostRules(e), insideRules(e)
	for _, want := range []string{
		`iifname "cfnv*" ct state invalid drop`,
		`iifname "cfnv*" ip saddr != 10.251.0.0/16 drop`,
		`iifname "cfnv*" ip daddr @blocked drop`,
		`iifname "cfnv*" tcp dport 25 drop`,
		`iifname "cfnv*" meta nfproto ipv6 drop`,
		`iifname "cfnv*" oifname != "ens18" drop`,
		`oifname "cfnv*" drop`,
		`iifname "cfnv*" oifname "ens18" masquerade`,
		"140.113.60.189/32",
	} {
		if !strings.Contains(host, want) {
			t.Errorf("host rules lack %q", want)
		}
	}
	for _, want := range []string{
		`policy drop`,
		`ip saddr 172.16.0.2 ct state new,established,related ip daddr != @blocked accept`,
		`iifname "tap0" tcp dport 25 drop`,
		`type filter hook output priority filter; policy drop;`,
		`oifname "eth0" ip saddr != 10.251.0.0/16 drop`,
		"140.113.60.189/32",
	} {
		if !strings.Contains(inside, want) {
			t.Errorf("namespace rules lack %q", want)
		}
	}
	// Two each in forward, input and output, and the policies of the two postrouting chains.
	if strings.Count(inside, "accept") != 8 {
		t.Errorf("the namespace rules accept in %d places, want 8: every new accept needs a review", strings.Count(inside, "accept"))
	}
}
