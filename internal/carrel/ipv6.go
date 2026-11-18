package carrel

import (
	"errors"
	"net/netip"
	"strconv"
)

// IPv6 per machine (issue #142, PLAN 6.13). The site routes one /48 over a
// WireGuard tunnel from the first exit node; tenant N has <prefix>:N::/64,
// with N written in decimal digits, so 10.200.17.11 is <prefix>:17::11 and
// the gateway is <prefix>:17::1. node-agent derives the same addresses
// (v6_net, v6_address); a machine opts in at creation.

func ipv6Prefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() || p.Bits() != 48 || p.Masked() != p || !p.Addr().IsGlobalUnicast() || p.Addr().IsPrivate() {
		return netip.Prefix{}, errors.New("ipv6_prefix must be a global IPv6 /48")
	}
	return p, nil
}

// decimalDigits reads n's decimal digits as hexadecimal: 17 becomes 0x17.
func decimalDigits(n int) uint16 {
	v, _ := strconv.ParseUint(strconv.Itoa(n), 16, 16)
	return uint16(v)
}

func v6Net(prefix netip.Prefix, n int) netip.Prefix {
	a := prefix.Addr().As16()
	h := decimalDigits(n)
	a[6], a[7] = byte(h>>8), byte(h)
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
	return D{"address": addr.String(), "prefix_length": 64, "gateway": gw.String(), "inbound": []string{"tcp/22"},
		"note": "Routed, not translated. Inbound from the internet is SSH only; other ports stay closed on IPv6."}
}
