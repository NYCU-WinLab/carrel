//go:build linux

package fn

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

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

// Egress is what the filter needs to know about the function host.
type Egress struct {
	// Uplink is the one interface functions may leave through. Empty means
	// the interface of the default route.
	Uplink string
	// Blocked adds addresses to the built-in list: a site's protected public
	// addresses (PLAN 6.6).
	Blocked []string
}

var linkNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// resolve fills the uplink and checks every value that goes into rule text.
func (e Egress) resolve() (Egress, error) {
	if e.Uplink == "" {
		out, err := exec.Command("ip", "-o", "-4", "route", "show", "default").Output()
		if err != nil {
			return e, fmt.Errorf("find the default route: %w", err)
		}
		fields := strings.Fields(string(out))
		for i, field := range fields {
			if field == "dev" && i+1 < len(fields) {
				e.Uplink = fields[i+1]
				break
			}
		}
	}
	if !linkNameRE.MatchString(e.Uplink) || strings.HasPrefix(e.Uplink, linkPrefix) {
		return e, fmt.Errorf("uplink interface %q is not usable", e.Uplink)
	}
	for i, entry := range e.Blocked {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			address, addrErr := netip.ParseAddr(entry)
			if addrErr != nil {
				return e, fmt.Errorf("blocked address %q: %w", entry, err)
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		if !prefix.Addr().Is4() {
			return e, fmt.Errorf("blocked address %q is not IPv4; IPv6 is dropped as a whole", entry)
		}
		e.Blocked[i] = prefix.Masked().String()
	}
	return e, nil
}

func (e Egress) blockedSet() string {
	return strings.Join(append(append([]string{}, blocked...), e.Blocked...), ", ")
}

// hostRules is the function host's rule set. Loading it replaces the old
// table in one transaction. e must come from resolve.
//
// It assumes the host has no other table that changes the source of a
// forwarded packet before the forward hook, and no other forward chain with
// policy drop: the first would get past the source check, the second would
// stop all egress. A function host runs nothing else (PLAN 7.11).
func hostRules(e Egress) string {
	return fmt.Sprintf(`add table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
	set blocked {
		type ipv4_addr
		flags interval
		auto-merge
		elements = { %[2]s }
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
		iifname "%[3]s*" ct state invalid drop
		iifname "%[3]s*" ip saddr != %[5]s drop
		iifname "%[3]s*" meta nfproto ipv6 drop
		iifname "%[3]s*" ip daddr @blocked drop
		iifname "%[3]s*" tcp dport 25 drop
		iifname "%[3]s*" oifname != "%[4]s" drop
		oifname "%[3]s*" ct state established,related accept
		oifname "%[3]s*" drop
	}
	chain input {
		type filter hook input priority filter; policy accept;
		iifname "%[3]s*" drop
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		iifname "%[3]s*" oifname "%[4]s" masquerade
	}
}
`, hostTable, e.blockedSet(), linkPrefix, e.Uplink, egressNet)
}

// insideRules is the rule set of one instance's network namespace. Only two
// flows pass: the guest to a public address, and the router to the guest.
// A packet that conntrack calls invalid would skip the address translation
// and leave with whatever source the guest wrote, so only tracked packets
// from the guest's one address are forwarded, and nothing leaves that was
// not translated to the link's own address.
func insideRules(e Egress) string {
	return fmt.Sprintf(`add table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
	set blocked {
		type ipv4_addr
		flags interval
		auto-merge
		elements = { %[2]s }
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
		iifname "tap0" tcp dport 25 drop
		iifname "tap0" oifname "%[3]s" ip saddr %[4]s ct state new,established,related ip daddr != @blocked accept
		iifname "%[3]s" oifname "tap0" ct state established,related accept
	}
	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		iifname "tap0" ct state established,related accept
	}
	chain output {
		type filter hook output priority filter; policy drop;
		oifname "lo" accept
		oifname "tap0" accept
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "%[3]s" masquerade
	}
	chain translated {
		type filter hook postrouting priority srcnat + 10; policy accept;
		oifname "%[3]s" ip saddr != %[5]s drop
	}
}
`, insideTable, e.blockedSet(), insideLink, guestAddr, egressNet)
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

// listTable returns the function table of the host, or of a namespace, as
// nft prints it. It is empty when the table is missing.
func listTable(namespace string) string {
	args := []string{"list", "table", "inet", hostTable}
	name := "nft"
	if namespace != "" {
		name, args = "ip", append([]string{"netns", "exec", namespace, "nft"}, args...)
	}
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// prepareHost lets the host forward behind its rules. The rules go in
// first: forwarding without them would route functions to private addresses.
// Only the router replaces the table. A build beside a running router keeps
// the router's rules, and loads its own only when there are none.
func prepareHost(e Egress, replace bool) error {
	if replace || exec.Command("nft", "list", "table", "inet", hostTable).Run() != nil {
		if err := nft("", hostRules(e)); err != nil {
			return err
		}
	}
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644)
}

// connect gives a slot's namespace its link to the host. The namespace's
// rules are loaded before the link exists, so no packet crosses unfiltered.
func connect(namespace string, link int, e Egress) error {
	host, inside, err := egressAddrs(link)
	if err != nil {
		return err
	}
	if err := nft(namespace, insideRules(e)); err != nil {
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
