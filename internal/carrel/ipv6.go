package carrel

import (
	"errors"
	"net/netip"
	"strconv"
)

// IPv6 per machine (issue #142, PLAN 6.13). The site routes a block over a
// WireGuard tunnel from the first exit node. ipv6_prefix is the tenant pool
// in it (the site block's "tenants"): tenant N has the block 12 bits longer
// whose 12 bits spell N in decimal digits, and its network is the first /64
// of that. With a /48 pool, 10.200.17.11 is <pool>:170::11 and the gateway
// is <pool>:170::1. node-agent derives the same addresses (v6_net,
// v6_address); a machine opts in at creation.

// documentation is 2001:db8::/32 (RFC 3849), which node-agent refuses too.
var documentation = netip.MustParsePrefix("2001:db8::/32")

func ipv6Prefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() || p.Bits() < 32 || p.Bits() > 52 || p.Masked() != p || !p.Addr().IsGlobalUnicast() || p.Addr().IsPrivate() || documentation.Overlaps(p) {
		return netip.Prefix{}, errors.New("ipv6_prefix must be a global IPv6 /32 to /52")
	}
	return p, nil
}

// decimalDigits reads n's decimal digits as hexadecimal: 17 becomes 0x17.
func decimalDigits(n int) uint16 {
	v, _ := strconv.ParseUint(strconv.Itoa(n), 16, 16)
	return uint16(v)
}

// v6Net is tenant N's network: the first /64 of the pool's block for N.
func v6Net(prefix netip.Prefix, n int) netip.Prefix {
	a := prefix.Addr().As16()
	h := uint64(decimalDigits(n))
	// The 12 bits after the pool, written into the first 64 bits.
	hi := uint64(0)
	for i := 0; i < 8; i++ {
		hi = hi<<8 | uint64(a[i])
	}
	hi |= h << (64 - prefix.Bits() - 12)
	for i := 7; i >= 0; i-- {
		a[i] = byte(hi)
		hi >>= 8
	}
	return netip.PrefixFrom(netip.AddrFrom16(a), 64)
}

// v6Machine is a machine's address and gateway, or false when the IPv4
// address is not a host of its tenant network.
func v6Machine(prefix netip.Prefix, n int, ip string) (netip.Addr, netip.Addr, bool) {
	v4, err := netip.ParseAddr(ip)
	if err != nil || !v4.Is4() {
		return netip.Addr{}, netip.Addr{}, false
	}
	b := v4.As4()
	if b[0] != 10 || b[1] != 200 || int(b[2]) != n || b[3] < 2 || b[3] == 255 || n < 1 || n > 254 {
		return netip.Addr{}, netip.Addr{}, false
	}
	net := v6Net(prefix, n).Addr().As16()
	gw := net
	gw[15] = 1
	h := decimalDigits(int(b[3]))
	net[14], net[15] = byte(h>>8), byte(h)
	return netip.AddrFrom16(net), netip.AddrFrom16(gw), true
}

// machineIPv6 is what machine_get shows for an opted-in machine, or nil.
func (e *Execution) machineIPv6(m D) D {
	if m["ipv6"] != true || e.P.Config.IPv6Prefix == "" {
		return nil
	}
	prefix, err := ipv6Prefix(e.P.Config.IPv6Prefix)
	if err != nil {
		return nil
	}
	addr, gw, ok := v6Machine(prefix, integer(m["tenant_n"]), str(m["ip"]))
	if !ok {
		return nil
	}
	inbound := []string{"tcp/22", "the machine's open ports (port_open)"}
	if m["public_ssh"] == false {
		inbound = inbound[1:]
	}
	return D{"address": addr.String(), "prefix_length": 64, "gateway": gw.String(), "inbound_from_internet": inbound,
		"note": "Routed, not translated. Other tenants cannot reach this address."}
}

// recordIPv6 keeps the site tunnel's latest report from a reconcile: the
// exit node's public key and port, or the error it returned. A node that
// reports nothing (no ipv6 block, or an older agent) clears it.
func (e *Execution) recordIPv6(node any) {
	report := obj(obj(node)["ipv6"])
	switch {
	case report["public_key"] != nil:
		e.S.SitePut("ipv6", "tunnel", D{"public_key": str(report["public_key"]), "port": integer(report["port"])})
	case report["error"] != nil:
		e.S.SitePut("ipv6", "tunnel", D{"error": str(report["error"])})
	default:
		e.S.SiteRemove("ipv6", "tunnel")
	}
}

// ipv6Status is the tunnel as the site status shows it, or nil when the
// site has no IPv6 or nothing has been reported.
func (e *Execution) ipv6Status() D {
	if e.P.Config.IPv6Prefix == "" {
		return nil
	}
	return e.S.SiteGet("ipv6", "tunnel")
}
