//go:build linux

package fn

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
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

	// What one instance may use of the network, like a tenant machine's
	// primary NIC (PLAN 13.4). Each direction has its own rate.
	defaultRate = "100mbit"
	maxPackets  = 20000 // per second, in each direction
	maxConns    = 512   // tracked connections at once
	newConns    = 200   // new connections per second, with a burst of twice that
	// A connection that ends stays in the tracking table, uncounted, for as
	// long as its state's timeout: 120 seconds of TIME_WAIT by default. The
	// functions' connections end sooner, so the table holds at most
	// maxConns + newConns * shortTimeout entries per instance.
	shortTimeout = 10
	pings        = 20 // ICMP packets per second out of an instance; ICMP has no timeout object
)

// timeouts are the tracking timeouts of a function's connections, in both
// the host's table and each namespace's.
const timeouts = `	ct timeout fn_tcp {
		protocol tcp
		l3proto ip
		policy = { syn_sent: 30, syn_recv: 30, fin_wait: 10, close_wait: 10, last_ack: 10, time_wait: 10, close: 10 }
	}
	ct timeout fn_udp {
		protocol udp
		l3proto ip
		policy = { unreplied: 10, replied: 30 }
	}
`

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
	// Rate is what one instance may send, and receive, in tc's words, such
	// as 100mbit. Empty means defaultRate.
	Rate string
}

var rateRE = regexp.MustCompile(`^([1-9][0-9]{0,5})(kbit|mbit|gbit)$`)

// rateBits reads a rate that resolve accepted, in bits per second.
func rateBits(rate string) int64 {
	match := rateRE.FindStringSubmatch(rate)
	n, _ := strconv.ParseInt(match[1], 10, 64)
	return n * map[string]int64{"kbit": 1e3, "mbit": 1e6, "gbit": 1e9}[match[2]]
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
	if e.Rate == "" {
		e.Rate = defaultRate
	}
	if !rateRE.MatchString(e.Rate) {
		return e, fmt.Errorf("rate %q is not a number followed by kbit, mbit or gbit", e.Rate)
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
%[6]s	chain forward {
		type filter hook forward priority filter; policy accept;
		iifname "%[3]s*" ct state invalid drop
		iifname "%[3]s*" ct state new meta l4proto tcp ct timeout set "fn_tcp"
		iifname "%[3]s*" ct state new meta l4proto udp ct timeout set "fn_udp"
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
`, hostTable, e.blockedSet(), linkPrefix, e.Uplink, egressNet, timeouts)
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
%[10]s	chain forward {
		type filter hook forward priority filter; policy drop;
		iifname "tap0" tcp dport 25 drop
		iifname "tap0" meta l4proto icmp limit rate over %[11]d/second burst %[11]d packets drop
		iifname "tap0" limit rate over %[6]d/second burst %[6]d packets drop
		iifname "%[3]s" limit rate over %[6]d/second burst %[6]d packets drop
		iifname "tap0" ct state new ct original packets 1 limit rate over %[7]d/second burst %[8]d packets drop
		iifname "tap0" ct state new ct count over %[9]d drop
		iifname "tap0" ct state new meta l4proto tcp ct timeout set "fn_tcp"
		iifname "tap0" ct state new meta l4proto udp ct timeout set "fn_udp"
		iifname "tap0" oifname "%[3]s" ip saddr %[4]s ct state new,established,related ip daddr != @blocked accept
		iifname "%[3]s" oifname "tap0" ct state established,related accept
	}
	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		iifname "tap0" limit rate over %[6]d/second burst %[6]d packets drop
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
`, insideTable, e.blockedSet(), insideLink, guestAddr, egressNet, maxPackets, newConns, 2*newConns, maxConns, timeouts, pings)
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
// nft prints it.
func listTable(namespace string) (string, error) {
	args := []string{"list", "table", "inet", hostTable}
	name := "nft"
	if namespace != "" {
		name, args = "ip", append([]string{"netns", "exec", namespace, "nft"}, args...)
	}
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return "", fmt.Errorf("list the rule table in %q: %w", namespace, err)
	}
	return string(out), nil
}

const probePrefix = "cfnprobe"

// removeOldProbes deletes probe namespaces of processes that ended while
// they probed.
func removeOldProbes() {
	entries, _ := os.ReadDir("/run/netns")
	for _, entry := range entries {
		pid, ok := strings.CutPrefix(entry.Name(), probePrefix)
		if !ok {
			continue
		}
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		if _, err := os.Stat("/proc/" + pid); errors.Is(err, os.ErrNotExist) {
			_ = exec.Command("ip", "netns", "del", entry.Name()).Run()
		}
	}
}

// expectedListing loads rules into a namespace made for this and nothing
// else, and returns how nft lists them. Guard compares the real tables with
// it. It comes from the rules, not from the host, so a table that something
// changed while the router started is never taken as the right one.
func expectedListing(rules string) (string, error) {
	removeOldProbes()
	probe := fmt.Sprintf("%s%d", probePrefix, os.Getpid())
	_ = exec.Command("ip", "netns", "del", probe).Run()
	if out, err := exec.Command("ip", "netns", "add", probe).CombinedOutput(); err != nil {
		return "", fmt.Errorf("ip netns add %s: %w: %s", probe, err, bytes.TrimSpace(out))
	}
	defer exec.Command("ip", "netns", "del", probe).Run()
	if err := nft(probe, rules); err != nil {
		return "", err
	}
	listing, err := listTable(probe)
	if err == nil && listing == "" {
		err = errors.New("nft listed an empty rule table")
	}
	return listing, err
}

// forgetConnections removes the host's connection tracking entries of an
// egress link. The host translates each slot's connections and keeps the
// entries after the namespace is gone, for days when they were established,
// so without this a slot made new would start from zero while its old
// connections still filled the host's table.
func forgetConnections(link int) error {
	_, inside, err := egressAddrs(link)
	if err != nil {
		return err
	}
	out, err := exec.Command("conntrack", "-D", "--orig-src", inside).CombinedOutput()
	// conntrack exits 1 when nothing matched, which is the usual case.
	if err != nil && !bytes.Contains(out, []byte("0 flow entries have been deleted")) {
		return fmt.Errorf("conntrack -D --orig-src %s: %w: %s", inside, err, bytes.TrimSpace(out))
	}
	return nil
}

// trimAt is how many tracked connections a slot's namespace may hold before
// Guard removes its ended ones: the open ones it may have, the ended ones
// its new-connection rate leaves for shortTimeout, and some room.
const trimAt = maxConns + newConns*shortTimeout + 488

// guardSeconds is how often the router calls Guard.
const guardSeconds = 5

// GuardPeriod is how often the router must call Guard.
const GuardPeriod = guardSeconds * time.Second

// trimConnections removes a slot's ended TCP connections, in its namespace
// and on the host, once the namespace tracks more than trimAt. The limit on
// connections does not count ended ones, and a guest that keeps sending
// valid ACKs keeps an ended connection's timeout from running out, so
// without this a slot could fill the host's table one connection at a time.
func trimConnections(namespace string, link int) error {
	out, err := exec.Command("ip", "netns", "exec", namespace, "cat", "/proc/sys/net/netfilter/nf_conntrack_count").Output()
	if err != nil {
		return err
	}
	count, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || count <= trimAt {
		return err
	}
	_, inside, err := egressAddrs(link)
	if err != nil {
		return err
	}
	for _, state := range []string{"TIME_WAIT", "CLOSE"} {
		// conntrack exits 1 when nothing matched, so only the output tells.
		_ = exec.Command("ip", "netns", "exec", namespace, "conntrack", "-D", "-p", "tcp", "--state", state).Run()
		_ = exec.Command("conntrack", "-D", "-p", "tcp", "--state", state, "--orig-src", inside).Run()
	}
	slog.Warn("ended connections trimmed", "slot", namespace, "tracked", count)
	return nil
}

// sizeConntrack makes room in the host's connection tracking table for every
// slot at its limit: each of a function's connections is tracked twice, in
// its namespace and on the host. A larger table is left as it is.
func sizeConntrack(slots int) error {
	const path = "/proc/sys/net/netfilter/nf_conntrack_max"
	want := slots*(trimAt+newConns*guardSeconds)*2 + 65536 // and room for the host's own
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if have, err := strconv.Atoi(strings.TrimSpace(string(content))); err == nil && have >= want {
		return nil
	}
	return os.WriteFile(path, []byte(strconv.Itoa(want)), 0o644)
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
	// Commands go in batches: a slot is made again after every instance, on
	// a host whose CPUs run the guests, and every process costs.
	err = batch([]string{"ip", "-batch", "-"}, [][]string{
		{"link", "add", outside, "type", "veth", "peer", "name", insideLink, "netns", namespace},
		// No multicast or IPv6 on the link: an interface that comes up
		// announces itself, and those packets would fill the host's table.
		{"link", "set", outside, "multicast", "off"},
		{"addr", "add", host + "/30", "dev", outside},
		{"link", "set", outside, "up"},
	})
	if err == nil {
		err = batch([]string{"ip", "-n", namespace, "-batch", "-"}, [][]string{
			{"link", "set", insideLink, "multicast", "off"},
			{"addr", "add", inside + "/30", "dev", insideLink},
			{"link", "set", insideLink, "up"},
			{"route", "add", "default", "via", host},
		})
	}
	if err == nil {
		// Packet counts per connection (acct), so the new-connection limit
		// counts a flow once: a UDP flow with no answer stays new for every packet.
		err = batch([]string{"ip", "netns", "exec", namespace, "sysctl", "-qw",
			"net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1",
			"net.ipv4.ip_forward=1", "net.netfilter.nf_conntrack_acct=1"}, nil)
	}
	if err == nil {
		// Both rates are shaped inside the namespace: out of the instance on
		// the link to the host, into it on the tap. Everything the guest
		// sends is also policed where it enters: the answers to the router's
		// requests end in this namespace and never reach eth0. A small burst
		// makes TCP back off far below the rate (256 KB gave 27 Mbit/s at
		// 100mbit), so the burst is a quarter second of the rate.
		err = batch([]string{"ip", "netns", "exec", namespace, "tc", "-batch", "-"}, [][]string{
			{"qdisc", "replace", "dev", insideLink, "root", "tbf", "rate", e.Rate, "burst", "128kb", "latency", "50ms"},
			{"qdisc", "replace", "dev", "tap0", "root", "tbf", "rate", e.Rate, "burst", "128kb", "latency", "50ms"},
			{"qdisc", "add", "dev", "tap0", "ingress"},
			{"filter", "add", "dev", "tap0", "ingress", "matchall",
				"action", "police", "rate", e.Rate, "burst", strconv.FormatInt(rateBits(e.Rate)/8/4, 10), "conform-exceed", "drop"},
		})
	}
	return err
}

// batch runs a command once, with one line per entry on its standard
// input. Every word was checked or made here: none holds a space or a newline.
func batch(command []string, lines [][]string) error {
	cmd := exec.Command(command[0], command[1:]...)
	var input strings.Builder
	for _, line := range lines {
		input.WriteString(strings.Join(line, " ") + "\n")
	}
	cmd.Stdin = strings.NewReader(input.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(command, " "), err, bytes.TrimSpace(out))
	}
	return nil
}
