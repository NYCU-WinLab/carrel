#!/bin/sh
# Staging only (#569): a stand-in for the site's public network. The netns
# "edge" holds the public gateway 198.18.61.1 on VLAN 61 of vmbr0 and NATs
# both ways, so the staging site has an upstream without touching anvil.
set -e
ip netns add edge 2>/dev/null || true
ip link show edge-up >/dev/null 2>&1 || ip link add edge-up type veth peer name edge-ns netns edge
ip link show edge-br >/dev/null 2>&1 || ip link add edge-br type veth peer name edge-pub netns edge
ip addr replace 10.254.0.1/30 dev edge-up; ip link set edge-up up
ip link set edge-br master vmbr0; ip link set edge-br up
ip -n edge link set lo up
ip -n edge addr replace 10.254.0.2/30 dev edge-ns; ip -n edge link set edge-ns up
ip -n edge link set edge-pub up
ip -n edge link show edge-pub.61 >/dev/null 2>&1 || ip -n edge link add link edge-pub name edge-pub.61 type vlan id 61
ip -n edge addr replace 198.18.61.1/24 dev edge-pub.61; ip -n edge link set edge-pub.61 up
ip -n edge route replace default via 10.254.0.1
ip netns exec edge sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv4.ip_forward=1
ip route replace 198.18.61.0/24 via 10.254.0.2 dev edge-up
ip netns exec edge nft -f - <<N
table ip edge
delete table ip edge
table ip edge {
  chain post { type nat hook postrouting priority 100;
    oifname "edge-ns" masquerade
    oifname "edge-pub.61" ip saddr != 198.18.61.0/24 snat to 198.18.61.1
  }
}
N
nft -f - <<N
table ip stg_edge
delete table ip stg_edge
table ip stg_edge {
  chain post { type nat hook postrouting priority 100;
    ip saddr 10.254.0.0/30 oifname "vmbr0" masquerade
  }
}
N
