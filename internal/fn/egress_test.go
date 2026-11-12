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
