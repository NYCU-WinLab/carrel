//go:build linux

package fn

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// A function may reach the internet and public names, and nothing else
// (PLAN 7.11). Every address below is dropped twice: once in the instance's
// own network namespace, and once on the function host.
var blocked = []string{
	"0.0.0.0/8",      // this network
	"10.0.0.0/8",     // private: tenant networks, the platform, the function host
	"100.64.0.0/10",  // carrier NAT and tailnets
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // link local, where metadata services live
	"172.16.0.0/12",  // private, and every guest's own link
	"192.168.0.0/16", // private: the nodes' management network
	"224.0.0.0/3",    // multicast, reserved and broadcast
}

const (
	// egressNet is carved into one /30 per slot for the link between an
	// instance's namespace and the host. It is not routed anywhere else.
	egressNet   = "10.251.0.0/16"
	maxEgress   = 1 << 14 // /30 links in a /16
	hostTable   = "carrel_fn"
	linkPrefix  = "cfnv" // host side of every link; the rules match this prefix
	insideLink  = "eth0"
	insideTable = "carrel_fn"
)

// egressAddrs returns the host's and the namespace's address on link n.
func egressAddrs(n int) (host, inside string, err error) {
	if n < 0 || n >= maxEgress {
		return "", "", fmt.Errorf("egress link %d is outside 0 to %d", n, maxEgress-1)
	}
	prefix := fmt.Sprintf("10.251.%d.", n>>6)
	last := (n & 63) << 2
	return prefix + strconv.Itoa(last+1), prefix + strconv.Itoa(last+2), nil
}

// hostRules is the function host's rule set. Loading it replaces the old
// table in one transaction.
func hostRules() string {
	return fmt.Sprintf(`add table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
	set blocked {
		type ipv4_addr
		flags interval
		elements = { %[2]s }
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
		iifname "%[3]s*" ip daddr @blocked drop
		iifname "%[3]s*" meta nfproto ipv6 drop
		oifname "%[3]s*" ct state established,related accept
		oifname "%[3]s*" drop
	}
	chain input {
		type filter hook input priority filter; policy accept;
		iifname "%[3]s*" drop
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		iifname "%[3]s*" oifname != "%[3]s*" masquerade
	}
}
`, hostTable, strings.Join(blocked, ", "), linkPrefix)
}

// insideRules is the rule set of one instance's network namespace. Only two
// flows pass: the guest to a public address, and the router to the guest.
func insideRules() string {
	return fmt.Sprintf(`add table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
	set blocked {
		type ipv4_addr
		flags interval
		elements = { %[2]s }
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
		iifname "tap0" oifname "%[3]s" ip daddr != @blocked accept
		iifname "%[3]s" oifname "tap0" ct state established,related accept
	}
	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		iifname "tap0" ct state established,related accept
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "%[3]s" masquerade
	}
}
`, insideTable, strings.Join(blocked, ", "), insideLink)
}

func nft(namespace, rules string) error {
	args := []string{"-f", "-"}
	name := "nft"
	if namespace != "" {
		name, args = "ip", append([]string{"netns", "exec", namespace, "nft"}, args...)
	}
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft in %q: %w: %s", namespace, err, bytes.TrimSpace(out))
	}
	return nil
}

// prepareHost loads the host's rules and lets it forward. The rules go in
// first: forwarding without them would route functions to private addresses.
func prepareHost() error {
	if err := nft("", hostRules()); err != nil {
		return err
	}
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644)
}

// connect gives a slot's namespace its link to the host. The namespace's
// rules are loaded before the link exists, so no packet crosses unfiltered.
func connect(namespace string, link int) error {
	host, inside, err := egressAddrs(link)
	if err != nil {
		return err
	}
	if err := nft(namespace, insideRules()); err != nil {
		return err
	}
	outside := linkPrefix + strconv.Itoa(link)
	_ = exec.Command("ip", "link", "del", outside).Run() // left over from an earlier run
	steps := [][]string{
		{"link", "add", outside, "type", "veth", "peer", "name", insideLink, "netns", namespace},
		{"addr", "add", host + "/30", "dev", outside},
		{"link", "set", outside, "up"},
		{"-n", namespace, "addr", "add", inside + "/30", "dev", insideLink},
		{"-n", namespace, "link", "set", insideLink, "up"},
		{"-n", namespace, "route", "add", "default", "via", host},
		{"netns", "exec", namespace, "sysctl", "-qw", "net.ipv4.ip_forward=1"},
	}
	for _, args := range steps {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("ip %v: %w: %s", args, err, bytes.TrimSpace(out))
		}
	}
	return nil
}
