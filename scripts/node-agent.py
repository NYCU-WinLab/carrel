#!/usr/bin/env python3
"""Root node adapter, exposed only as an SSH forced command.

One bounded JSON request on stdin; no shell, arbitrary paths, guest exec or PVE
passthrough operations. Only tagged carrel tenant VMIDs may be changed. The
control plane owns authorization and quotas; this boundary owns host integrity.
"""

import contextlib
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse

STATE = Path("/var/lib/carrel")
NODE = socket.gethostname().split(".")[0]
CONFIG = Path("/etc/carrel/node.json")
STORAGE_CONFIG = Path("/etc/pve/storage.cfg")
PVE_NODES = Path("/etc/pve/nodes")
SITE = Path("/etc/carrel/site.json")
# Cluster-wide and root-only: every node reads the same token (configure-reader.py).
READER = Path("/etc/pve/priv/carrel-reader.json")
PVE_CA = "/etc/pve/pve-root-ca.pem"
# Platform CT templates (PLAN 7.1), pinned to the sha512 in Proxmox's signed
# appliance index. On a shared storage one rewritten file would reach every
# new CT of every node, so each use checks it.
CT_TEMPLATES = {
    "debian-13": ("debian-13-standard_13.6-1_amd64.tar.zst", "4c0c27ca6ceab5ef0b84db57825a00f26157ef1854bafe97297813e1cbe8ecb8cc9c453cab6b3b0efe1ba193a50c47ece1e41d950e411b8730b835b71e9e754b"),
    "ubuntu-24.04": ("ubuntu-24.04-standard_24.04-2_amd64.tar.zst", "45c2978e6b97fe292ada95fe06834276015e5739a594db4de2fdfd830fa0c37942e8ae118fc1e32ffd9154b3f9378b592738b668ea3957db41f2907b86f219de"),
}


def storage_id():
    # One guest storage id per site (PLAN 8.2), a ZFS pool.
    value = json.loads(CONFIG.read_text()).get("storage")
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,62}", value):
        raise ValueError("invalid storage id")
    return value


def storage_entry(storage, text=None):
    # Parse storage.cfg directly: pvesh would load every PVE module.
    found = None
    for line in (STORAGE_CONFIG.read_text() if text is None else text).splitlines():
        if line and not line[0].isspace():
            if found is not None:
                break
            kind, _, name = line.partition(":")
            if name.strip() == storage:
                found = {"type": kind.strip()}
        elif found is not None and line.strip():
            key, _, value = line.strip().partition(" ")
            found[key] = value.strip()
    return found


def storage_definition(storage, text=None):
    found = storage_entry(storage, text)
    if found is None or found["type"] != "zfspool":
        raise ValueError("guest storage must be a ZFS pool")
    return found


class StorageUnavailable(RuntimeError):
    pass


def content_storage(kind):
    # The site file names one storage per file kind (issue #92), "local" when
    # it names none; B09 keeps them once per site on its shared NFS storage.
    value = (json.loads(SITE.read_text()) if SITE.exists() else {}).get("content_storage", {}).get(kind, "local")
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,62}", value):
        raise ValueError("invalid content storage id")
    return value


def ct_template(image):
    name, digest = CT_TEMPLATES[image]
    storage = content_storage("vztmpl")
    entry = storage_entry(storage)
    if entry is None or entry["type"] not in ("dir", "nfs", "cifs") or "path" not in entry:
        raise ValueError("CT template storage must be a directory storage")
    # A hard NFS mount waits for its server forever: read in a child with a
    # deadline, before anything is created.
    try:
        found = run("sha512sum", Path(entry["path"]) / "template" / "cache" / name, timeout=60).split()[0]
    except (CommandFailure, subprocess.TimeoutExpired) as e:
        raise StorageUnavailable(f"CT template {name} missing or {storage} unreachable") from e
    if found != digest:
        raise ValueError("CT template checksum mismatch")
    return f"{storage}:vztmpl/{name}"


_reader = None


def pve_get(resource, **params):
    """Read the local PVE API over HTTPS with the read-only token.

    One connection per adapter run; a pvesh start costs about a second per read.
    Writes stay with pvesh as root. Never fall back after a read failure: stale
    or ACL-filtered inventories must not authorize allocations.
    """
    global _reader
    if _reader is None:
        context = ssl.create_default_context(cafile=PVE_CA)
        # The PVE root CA has no keyUsage extension, which strict X.509 rejects.
        # The chain and the node name are still verified.
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        connection = http.client.HTTPSConnection(NODE, 8006, context=context, timeout=60)
        _reader = connection, json.loads(READER.read_text())["authorization"]
    connection, authorization = _reader
    query = "?" + urllib.parse.urlencode(params) if params else ""
    for retry in (False, True):
        try:
            connection.request("GET", "/api2/json" + resource + query, headers={"Authorization": authorization})
            response = connection.getresponse()
            body = response.read(16 << 20)
            break
        except ConnectionError:
            # pveproxy closes a connection idle for 5 s, as it is after a slow
            # write. A GET is safe to send again; close() makes the next one reconnect.
            connection.close()
            if retry:
                raise
    if response.status != 200:
        raise CommandFailure(f"PVE GET returned HTTP {response.status}")
    data = json.loads(body).get("data")
    if data is None:
        raise CommandFailure("missing PVE observation")
    return data


def inventory_read(storage):
    # The token sees every volume only with Datastore.Allocate on the storage;
    # PVEAuditor alone silently omits volumes. Refuse incomplete authority.
    path = "/storage/" + storage
    authority = pve_get("/access/permissions", path=path).get(path, {})
    if authority.get("Datastore.Audit") != 1 or authority.get("Datastore.Allocate") != 1:
        raise RuntimeError("storage inventory authority is incomplete")
    return {
        "volumes": pve_get(f"/nodes/{NODE}{path}/content"),
        "resources": pve_get("/cluster/resources"),
        "storage": pve_get(f"/nodes/{NODE}{path}/status"),
        "status": pve_get(f"/nodes/{NODE}/status"),
    }


def topology_read():
    vnets = pve_get("/cluster/sdn/vnets")
    subnets = {
        v["vnet"]: pve_get(f"/cluster/sdn/vnets/{v['vnet']}/subnets")
        for v in vnets
        if re.fullmatch(r"t[0-9]{3}", v["vnet"])
    }
    return vnets, subnets


def vip_addresses(m, state):
    # Virtual addresses this machine may hold (issue #96): only .251 to .254
    # of its own tenant network, so no grant can claim another machine's.
    n = m["tenant_n"]
    out = []
    for vip in state.get("vips", []):
        if m["vmid"] not in vip["vmids"]:
            continue
        address = ipaddress.IPv4Address(vip["address"])
        if vip["tenant_n"] != n or address not in ipaddress.IPv4Network(f"10.200.{n}.0/24") or not 251 <= int(address) % 256 <= 254:
            raise ValueError("invalid virtual address")
        out.append(str(address))
    return sorted(out)


def targets(grant, m, state):
    """Whether a public port or domain reaches this machine: it names the
    machine, or a virtual address this machine may hold (issue #146), so
    every holder admits it at the address that moves."""
    if grant.get("vip"):
        return any(
            v["id"] == grant["vip"] and v["tenant_n"] == m["tenant_n"] == grant["tenant_n"] and m["vmid"] in v["vmids"]
            for v in state.get("vips", [])
        )
    return grant["vmid"] == m["vmid"]


def guest_firewall(m, state, config):
    # These rules cover net0 only: experiment NICs run with firewall=0, so a
    # restricted machine's private NICs stay unfiltered (issue #75).
    machine(m)
    n = m["tenant_n"]
    rules = [
        "[OPTIONS]",
        "enable: 1",
        "ipfilter: 1",
        "macfilter: 1",
        # Guests use static addresses from cloud-init or pct; no DHCP server answers.
        "dhcp: 0",
        "ndp: 0",
        "radv: 0",
        "policy_in: DROP",
        "policy_out: ACCEPT",
        "",
        "[IPSET ipfilter-net0]",
        m["ip"],
        *vip_addresses(m, state),
        "0.0.0.0",
        "",
    ]
    binding = next((b for b in public_bindings(state, config.get("protected_addresses", [])) if b[1]["vmid"] == m["vmid"]), None)
    if binding:
        rules += ["[IPSET internet]", *INTERNET_IPSET, ""]
    rules += [
        "[RULES]",
        "OUT DROP -dest ::/0",
        "IN DROP -source ::/0",
        "OUT DROP -source 0.0.0.0",
        "OUT ACCEPT -dest 10.200.0.2 -p udp -dport 53",
        "OUT ACCEPT -dest 10.200.0.2 -p tcp -dport 53",
        "OUT ACCEPT -dest 10.200.0.3 -p tcp -dport 8080",
    ]
    for peer in state["peers"]:
        # Peering is a grant by the destination owner, scoped to one port.
        src = str(ipaddress.IPv4Network(peer["source"], strict=False))
        dst = str(ipaddress.IPv4Address(peer["target"]))
        port = integer(peer["port"], 1, 65535)
        proto = peer.get("proto", "tcp")
        if proto not in ("tcp", "udp"):
            raise ValueError("invalid peer protocol")
        if ipaddress.ip_address(m["ip"]) in ipaddress.ip_network(src):
            rules.append(f"OUT ACCEPT -dest {dst} -p {proto} -dport {port}")
        if dst == m["ip"]:
            rules.append(f"IN ACCEPT -source {src} -p {proto} -dport {port}")
    rules += [
        f"OUT DROP -dest 10.200.{n}.1",
        f"OUT ACCEPT -dest 10.200.{n}.0/24",
    ]
    if m.get("network_access", "tenant") == "tenant":
        rules.append(f"IN ACCEPT -source 10.200.{n}.0/24")
        # The tenant's VPN clients count as its network (PLAN 6.11).
        rules.append(f"IN ACCEPT -source 10.201.{n}.0/24")
    # Public entry points on protected hosts (the public HTTPS gateway): the internet can
    # already reach them, so tenants may too. Management ports on the same host stay dropped.
    for entry in config.get("public_entries", []):
        dest = ipaddress.ip_network(entry["address"], strict=False)
        # Only a protected public host (issue #28): an entry for a private
        # range would open it above the drops below.
        protected = [ipaddress.ip_network(a, strict=False) for a in config["protected_addresses"]]
        if dest.version != 4 or dest.prefixlen != 32 or not dest.network_address.is_global or not any(p.version == 4 and dest.subnet_of(p) for p in protected):
            raise ValueError(f"public entry {entry['address']} is not a protected public address")
        port = integer(entry["port"], 1, 65535)
        rules.append(f"OUT ACCEPT -dest {dest} -p tcp -dport {port}")
    for dest in sorted({str(ipaddress.ip_network(e["address"], strict=False)) for e in config.get("public_entries", [])}):
        # Every tenant's public ports are public (issue #28): tenants reach
        # them by the public address too, like anyone on the internet.
        for proto in ("tcp", "udp"):
            rules.append(f"OUT ACCEPT -dest {dest} -p {proto} -dport {TENANT_PORTS}")
        # Special ports are public too (PLAN 6.10).
        for g in state["ports"]:
            public = integer(g["public_port"], 1, 65535)
            if g.get("special") and grantable(public) and g["proto"] in ("tcp", "udp"):
                rules.append(f"OUT ACCEPT -dest {dest} -p {g['proto']} -dport {public}")
    for block in [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "127.0.0.0/8",
        "224.0.0.0/4",
        *config["protected_addresses"],
    ]:
        rules.append(f"OUT DROP -dest {ipaddress.ip_network(block, strict=False)}")
    rules += ["OUT DROP -p tcp -dport 25"]
    for grant in state["ports"]:
        if targets(grant, m, state):
            port = integer(grant["port"], 1, 65535)
            proto = grant["proto"]
            if proto not in ("tcp", "udp"):
                raise ValueError("invalid protocol")
            # The exit node DNATs only, so the client's address arrives.
            rules.append(f"IN ACCEPT -p {proto} -dport {port}")
    if binding:
        # The internet reaches a machine with a public address on the ports
        # its owner chose, or on all of them (issue #91).
        if binding[2] == ["all"]:
            rules.append("IN ACCEPT -source +internet")
        else:
            rules += [f"IN ACCEPT -source +internet -p {proto} -dport {port}" for proto, port in binding[2]]
    for domain in state.get("domains", []):
        if targets(domain, m, state):
            port = integer(domain["target_port"], 1, 65535)
            rules.append(f"IN ACCEPT -source 10.200.0.2 -p tcp -dport {port}")
            if domain.get("delegated"):
                # The control plane asks the target before the gateway
                # obtains a certificate for a delegated name (PLAN 6.10).
                rules.append(f"IN ACCEPT -source 10.200.0.3 -p tcp -dport {port}")
    # Reachability probes only, from the authenticated control plane, and
    # the jump host forwarding members to their machines (issue #98): SSH,
    # or the declared ports of a machine without it (issue #94).
    for port in [integer(p, 1, 65535) for p in m.get("service_ports") or []] or [22]:
        rules.append(f"IN ACCEPT -source 10.200.0.3 -p tcp -dport {port}")
        rules.append(f"IN ACCEPT -source 10.200.0.4 -p tcp -dport {port}")
    return "\n".join(rules) + "\n"


class CommandFailure(RuntimeError):
    pass


def run(*args, timeout=180, input=None):
    p = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=timeout, input=input)
    if p.returncode:
        raise CommandFailure(f"{args[0]} {args[1]} failed: {p.stderr[-1200:]}")
    return p.stdout.strip()


def api(method, path, **kwargs):
    # Writes only; reads use pve_get.
    args = ["pvesh", method, path, "--output-format", "json"]
    for key, value in kwargs.items():
        args += ["--" + key.replace("_", "-"), str(value)]
    # Below the control plane's 300 s bound on a reconcile, so the node never
    # outlives the request that holds its lock.
    text = run(*args, timeout=240)
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # SDN reload emits progress before its final JSON task id.
        if path == "/cluster/sdn" and method == "set":
            return json.loads(text.splitlines()[-1])
        raise


def write(path, data, mode=0o640):
    p = Path(path)
    if p.exists() and p.read_text() == data:
        return False
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(data)
    tmp.chmod(mode)
    os.replace(tmp, p)
    return True


def integer(value, lo, hi):
    if type(value) is not int or not lo <= value <= hi:
        raise ValueError(f"integer must be between {lo} and {hi}")
    return value


def label(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", value):
        raise ValueError("invalid label")
    return value


def machine(m):
    n = integer(m["tenant_n"], 1, 254)
    vmid = integer(m["vmid"], 10000 + n * 100, 10099 + n * 100)
    integer(m["host"], 10, 109)
    label(m["name"])
    if m["kind"] not in ("vm", "ct"):
        raise ValueError("invalid machine kind")
    expected = f"10.200.{n}.{m['host']}"
    if m["ip"] != expected:
        raise ValueError("address does not match tenant")
    if not re.fullmatch(r"02:ca:[0-9a-f:]{11}", m["mac"]):
        raise ValueError("invalid MAC")
    return vmid


def disk_volume(m, allow_provisioning=False):
    """The root disk's Proxmox volume, `<storage>:<volume>`, for NetBox (issue #175)."""
    cfg = owned(m, allow_provisioning)
    volume = cfg.get("scsi0" if m["kind"] == "vm" else "rootfs", "").split(",")[0]
    return {"disk_volume": volume} if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]*:[a-zA-Z0-9_./-]+", volume) else {}


def provision_marker(m):
    return "carrel-provision-" + hashlib.sha256(str(m.get("readiness_token", m["name"])).encode()).hexdigest()


def owned(m, allow_provisioning=False, node=None):
    vmid = machine(m)
    kind = "qemu" if m["kind"] == "vm" else "lxc"
    cfg = pve_get(f"/nodes/{node or NODE}/{kind}/{vmid}/config")
    tags = cfg.get("tags", "").split(";")
    if "carrel" not in tags or f"tenant-{m['tenant_n']}" not in tags:
        manifest = STATE / f"create-{vmid}.json"
        if allow_provisioning and kind == "qemu" and manifest.exists():
            saved = json.loads(manifest.read_text())
            marker = provision_marker(m)
            if saved.get("marker") == marker and cfg.get("description") == marker:
                return cfg
        raise ValueError("refusing unowned VMID")
    return cfg


def tenant_config(t):
    n = integer(t["n"], 1, 254)
    label(t["slug"])
    return n, f"t{n:03d}"


def ensure(path, key, value, *, existing, **params):
    if any(x[key] == value for x in existing):
        return False
    api("create", path, **{key: value}, **params)
    existing.append({key: value, **params})
    return True



def site():
    return json.loads(SITE.read_text())


def mirror_url(distro):
    mirrors = site().get("apt_mirrors", {}) if SITE.exists() else {}
    url = mirrors.get(distro) if distro in ("debian", "ubuntu") else None
    if url and not re.fullmatch(r"https?://[A-Za-z0-9.-]+(/[A-Za-z0-9._/-]*)?", url):
        raise ValueError("invalid apt mirror")
    return url.rstrip("/") if url else None


def mirror_command(image):
    """The shell command that points a new guest's package sources at the
    site's mirror (apt_mirrors in the site file), or None. Debian's
    security archive stays upstream: the NYCU mirror does not carry it."""
    distro = str(image).split("-", 1)[0]
    url = mirror_url(distro)
    if not url:
        return None
    if distro == "debian":
        pattern = r"s#https?://deb\.debian\.org/debian(/?)([[:space:]]|$)#" + url + r"\1\2#g"
        files = "/etc/apt/mirrors/debian.list /etc/apt/sources.list.d/debian.sources"
    else:
        pattern = r"s#https?://(archive|security)\.ubuntu\.com/ubuntu(/?)([[:space:]]|$)#" + url + r"\2\3#g"
        files = "/etc/apt/sources.list.d/ubuntu.sources"
    return f"for f in {files}; do [ -f \"$f\" ] && sed -i -E '{pattern}' \"$f\"; done; true"


def public_ingress():
    # The first exit node holds the public address and terminates ingress (PLAN 15.15).
    s = site()
    if s["exit_nodes"][0] != NODE:
        return None
    return str(ipaddress.IPv4Interface(s["public"]["address"]).ip)


def public_interface():
    """The exit node's public VLAN interface, as install-network.py names it."""
    s = site()
    return f'{s["underlay_interface"]}.{int(s["public"]["vlan"])}'


# Public IP bindings (issue #91, PLAN 6.12): the exit node holds each bound
# address, DNATs it to its machine and SNATs the machine's egress to it. The
# addresses it added are kept here, so it removes only its own.
PUBLIC_IPS = Path("/etc/carrel/public-ips.json")

# Internet sources: what reaches a bound address. Private ranges never come in
# from the uplink (carrel_public drops them), and they must not open a
# restricted machine to other tenants. An ipset holds no /0, so two halves.
INTERNET_IPSET = ["0.0.0.0/1", "128.0.0.0/1", "!10.0.0.0/8", "!172.16.0.0/12", "!192.168.0.0/16", "!100.64.0.0/10"]


def public_bindings(state, protected=()):
    """The checked bindings of active tenants: [(public address, machine, ports)]."""
    if not state.get("public_ips"):
        return []
    s = site()
    shared = ipaddress.IPv4Interface(s["public"]["address"])
    gateway = ipaddress.IPv4Address(s["public"]["gateway"])
    active = {t["n"] for t in state["tenants"] if t.get("status", "active") == "active"}
    machines = {m["vmid"]: m for m in state["machines"]}
    blocked = [ipaddress.ip_network(p, strict=False) for p in protected]
    out, seen, held = [], set(), set()
    for b in state["public_ips"]:
        n = integer(b["tenant_n"], 1, 254)
        public = ipaddress.IPv4Address(b["address"])
        network = shared.network
        if public in seen:
            raise ValueError("invalid public address binding")
        seen.add(public)
        if (public not in network or public in (network.network_address, network.broadcast_address, gateway, shared.ip)
                or any(public in p for p in blocked)):
            # A NetBox range that strays outside the public network: that
            # binding is not applied, and every other machine keeps working.
            print(f"public address {public} is not usable here; binding skipped", file=sys.stderr)
            continue
        m = machines.get(b["vmid"])
        if m is None or n not in active:
            continue
        machine(m)
        if m["tenant_n"] != n or m["vmid"] in held:
            raise ValueError("invalid public address binding")
        held.add(m["vmid"])
        out.append((str(public), m, public_ports(b["ports"])))
    return sorted(out, key=lambda x: ipaddress.IPv4Address(x[0]))


def public_ports(ports):
    """["all"] or protocol/port pairs, each once."""
    if ports == ["all"]:
        return ["all"]
    out = []
    if not isinstance(ports, list) or not 1 <= len(ports) <= 32:
        raise ValueError("invalid public address ports")
    for p in ports:
        proto, _, port = str(p).partition("/")
        if proto not in ("tcp", "udp"):
            raise ValueError("invalid public address ports")
        if not port.isdigit():
            raise ValueError("invalid public address ports")
        out.append((proto, integer(int(port), 1, 65535)))
    if len(set(out)) != len(out):
        raise ValueError("invalid public address ports")
    return out


def public_addresses(bindings):
    """Hold the bound addresses on the public interface, deprecated so the node
    never picks one as the source of its own connections, and scope link so an
    ifreload keeps them. bindings maps each
    address to its machine's address. An address that leaves, or moves to
    another machine, loses its tracked connections too: a NAT mapping outlives
    the rules that made it."""
    iface = public_interface()
    old = json.loads(PUBLIC_IPS.read_text()) if PUBLIC_IPS.exists() else {}
    if isinstance(old, list):
        old = dict.fromkeys(old, "")
    # Tracked before they are added, so an address added before a failure
    # is still removed later.
    write(PUBLIC_IPS, json.dumps(dict(sorted({**old, **bindings}.items()))))
    for a in sorted(bindings):
        # scope link: ifupdown2 purges global addresses its files do not
        # list on every ifreload, which each SDN apply runs.
        run("ip", "address", "replace", f"{ipaddress.IPv4Address(a)}/32", "dev", iface, "preferred_lft", "0", "scope", "link")
    for a in sorted(set(old) - set(bindings)):
        if a in held_addresses(iface):
            run("ip", "address", "del", f"{ipaddress.IPv4Address(a)}/32", "dev", iface)
    for a in sorted(old):
        if bindings.get(a) != old[a]:
            conntrack_flush(a)
    write(PUBLIC_IPS, json.dumps(dict(sorted(bindings.items()))))


def held_addresses(iface):
    return {i["local"] for x in json.loads(run("ip", "-4", "-j", "address", "show", "dev", iface)) for i in x.get("addr_info", [])}


def conntrack_flush(address):
    """Forget the connections of a public address in every zone: those that
    arrived for it (DNAT) and those that left from it (SNAT)."""
    ipaddress.IPv4Address(address)
    for selector in ("--orig-dst", "--reply-dst"):
        p = subprocess.run(["conntrack", "-D", selector, address], capture_output=True, text=True, timeout=60)
        # conntrack exits 1 when nothing matched.
        if p.returncode and "flow entries have been deleted" not in p.stderr:
            raise CommandFailure(f"conntrack -D failed: {p.stderr[-300:]}")


# The public port blocks of tenants 1 to 254 (20000 + 10n to 20009 + 10n).
TENANT_PORTS = "20010:22549"

# Public ports never granted to a tenant as a special port (PLAN 6.10);
# internal/carrel/special_ports.go keeps the same list.
NEVER_PORTS = {22, 25, 53, 80, 111, 443, 3128, 8006}


def grantable(public):
    """A special public port: none of the site's own, no tenant block, no client VPN port."""
    return public not in NEVER_PORTS and not 20000 <= public <= 22549 and not VPN_PORT_BASE <= public <= VPN_PORT_BASE + 254


def ports_nft(state, address, bindings=()):
    """DNAT the public address: HTTP(S) to the infra gateway, granted ports to
    machines; and each bound public address to its machine, 1:1 (issue #91)."""
    iface = public_interface() if bindings else ""
    bound = [f'iifname "{iface}" ip daddr {public} dnat to {m["ip"]}' for public, m, _ in bindings]
    rules = [f"ip daddr {address} tcp dport {{ 80, 443 }} dnat to 10.200.0.2"]
    if SITE.exists() and site().get("ssh_jump"):
        # The platform SSH jump host (issue #98) in CT 102.
        rules.append(f"ip daddr {address} tcp dport 22 dnat to 10.200.0.4")
    seen = set()
    for g in state["ports"]:
        n = integer(g["tenant_n"], 1, 254)
        if g.get("special"):
            # A port granted through port_request, outside every block.
            public = integer(g["public_port"], 1, 65535)
            if not grantable(public):
                raise ValueError("special port grant on a reserved port")
        else:
            public = integer(g["public_port"], 20000 + n * 10, 20009 + n * 10)
        port = integer(g["port"], 1, 65535)
        if g["proto"] not in ("tcp", "udp") or (g["proto"], public) in seen:
            raise ValueError("invalid port grant")
        ip = ipaddress.IPv4Address(g["ip"])
        # A machine address, or a virtual address of the tenant (issue #146).
        hosts = range(251, 255) if g.get("vip") else range(10, 110)
        if ip not in ipaddress.IPv4Network(f"10.200.{n}.0/24") or int(str(ip).rsplit(".", 1)[1]) not in hosts:
            raise ValueError("port grant outside tenant network")
        seen.add((g["proto"], public))
        rules.append(f"ip daddr {address} {g['proto']} dport {public} dnat to {ip}:{port}")
    body = "\n".join("  " + r for r in bound + rules)
    egress = "".join(f'\n  oifname "{iface}" ip saddr {m["ip"]} snat to {public}' for public, m, _ in bindings)
    # The node itself reaches its public address too (issue #48): its own
    # packets take the output hook, not prerouting.
    local = "\n".join("  " + r for r in rules if "dport 22 dnat to 10.200.0.4" not in r)
    return f"""add table ip carrel_ports
flush table ip carrel_ports
table ip carrel_ports {{
 chain prerouting {{
  type nat hook prerouting priority dstnat - 5; policy accept;
{body}
 }}
 chain output {{
  type nat hook output priority dstnat - 5; policy accept;
{local}
 }}
 chain postrouting {{
  type nat hook postrouting priority srcnat - 5; policy accept;
  # A tenant reaching another tenant's public port (issue #28): the answer
  # must come back through here, so the source becomes the public address.
  ip saddr 10.200.0.0/16 ip daddr 10.200.0.0/16 ip daddr != 10.200.0.0/24 ct status dnat ct original ip daddr {address} snat to {address}
  # A machine with a public address leaves from it; this chain runs before
  # carrel_public, whose rule SNATs every other tenant to the shared address.{egress}
 }}
}}
"""


# Client VPN (issue #103, PLAN 6.11): one WireGuard interface per tenant on the
# first exit node, in the tenants' VRF. Tenant N listens on 31000 + N, below the
# ephemeral port range, and its clients take addresses from 10.201.N.0/24.
VPN_PORT_BASE = 31000
VPN_KEYS = Path("/etc/carrel/wg")
VPN_MTU = 1420
WG_KEY = re.compile(r"[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=")


def vpn_clients(state):
    """The checked client peers of each active tenant: {n: [(public key, address)]}."""
    active = {t["n"] for t in state["tenants"] if t.get("status", "active") == "active"}
    out = {}
    for c in state.get("vpn_clients", []):
        n = integer(c["tenant_n"], 1, 254)
        address = ipaddress.IPv4Address(c["address"])
        if address not in ipaddress.IPv4Network(f"10.201.{n}.0/24") or not 2 <= int(address) % 256 <= 254:
            raise ValueError("VPN client address outside its tenant's range")
        if not WG_KEY.fullmatch(str(c["public_key"])):
            raise ValueError("invalid VPN client public key")
        if n in active:
            out.setdefault(n, []).append((c["public_key"], str(address)))
    return out


def vpn_nft(tenants):
    """A client reaches its own tenant's network and nothing else: not another
    tenant, not the infra or fetch network, not the node, not the internet.

    Inbound is filtered in prerouting: once a packet enters the VRF, the
    forward and input hooks see vrf_tenants as its interface, not wg-tNNN.
    Outbound, the forward hook does see the wg-tNNN it leaves through."""
    ingress, egress = [], []
    for n in sorted(tenants):
        dev = f"wg-t{n:03d}"
        # The node's own gateway address is in that /24 too: not for clients.
        ingress.append(f'iifname "{dev}" ip daddr 10.200.{n}.1 counter drop')
        ingress.append(f'iifname "{dev}" ip saddr 10.201.{n}.0/24 ip daddr 10.200.{n}.0/24 accept')
        egress.append(f'oifname "{dev}" ip saddr 10.200.{n}.0/24 ip daddr 10.201.{n}.0/24 accept')
    return f"""add table inet carrel_vpn
flush table inet carrel_vpn
table inet carrel_vpn {{
 chain prerouting {{
  type filter hook prerouting priority -150; policy accept;
{chr(10).join("  " + r for r in ingress)}
  iifname "wg-t*" counter drop
 }}
 chain forward {{
  type filter hook forward priority -25; policy accept;
{chr(10).join("  " + r for r in egress)}
  oifname "wg-t*" counter drop
 }}
}}
"""


def vpn(state):
    """Bring each tenant's WireGuard interface to the desired peers; returns
    the public key and port of each, which the control plane hands to clients.
    The private keys stay in VPN_KEYS on this node. A failure here stays here:
    the rest of the reconciliation, every other tenant's included, goes on."""
    if not public_ingress():
        return {}
    try:
        return vpn_apply(vpn_clients(state))
    except Exception as e:  # noqa: BLE001 - reported to the control plane
        return {"error": f"{type(e).__name__}: {e}"[:300]}


def vpn_apply(tenants):
    # The filter goes first, so no interface is ever up without it.
    rules = vpn_nft(tenants)
    write("/etc/carrel/vpn.nft", rules)
    run("nft", "-c", "-f", "/etc/carrel/vpn.nft")
    run("nft", "-f", "/etc/carrel/vpn.nft")
    if tenants and not shutil.which("wg"):
        raise CommandFailure("wireguard-tools is not installed on the exit node")
    out = {}
    for n, peers in sorted(tenants.items()):
        dev = f"wg-t{n:03d}"
        key = VPN_KEYS / f"t{n:03d}.key"
        if not key.exists():
            VPN_KEYS.mkdir(mode=0o700, parents=True, exist_ok=True)
            # The key first, then a file created 0600: a failed genkey leaves
            # no empty key behind, and the file is never readable in between.
            private = run("wg", "genkey")
            with os.fdopen(os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
                f.write(private + "\n")
        private = key.read_text().strip()
        if not Path(f"/sys/class/net/{dev}").exists():
            run("ip", "link", "add", dev, "type", "wireguard")
        run("ip", "link", "set", dev, "master", "vrf_tenants", "mtu", str(VPN_MTU))
        run("ip", "address", "replace", f"10.201.{n}.1/24", "dev", dev)
        conf = f"[Interface]\nListenPort = {VPN_PORT_BASE + n}\nPrivateKey = {private}\n"
        conf += "".join(f"\n[Peer]\nPublicKey = {k}\nAllowedIPs = {a}/32\n" for k, a in sorted(peers))
        path = VPN_KEYS / f"{dev}.conf"
        write(path, conf, 0o600)
        run("wg", "syncconf", dev, path)
        run("ip", "link", "set", dev, "up")
        out[str(n)] = {"public_key": run("wg", "pubkey", input=private), "port": VPN_PORT_BASE + n}
    # A tenant without clients, or suspended, keeps no interface.
    for link in Path("/sys/class/net").glob("wg-t*"):
        if re.fullmatch(r"wg-t\d{3}", link.name) and int(link.name[4:]) not in tenants:
            run("ip", "link", "del", link.name)
            (VPN_KEYS / f"{link.name}.conf").unlink(missing_ok=True)
    return out


def first_exit_node():
    # The first exit node reconciles before the others. It alone serves
    # private DHCP (a private network is one layer 2 segment across the
    # nodes: one DHCP server and one .1) and writes cluster-wide files.
    return site()["exit_nodes"][0] == NODE


def private_dhcp(state, serve=True):
    """Each DHCP server lives in its own unrouted namespace, never on the host LAN."""
    infra_path = Path("/etc/carrel/infra.nft")
    if infra_path.exists():
        infra = infra_path.read_text()
        reporter_rule = '  oifname "vmbr98" ip saddr 10.200.0.0/16 ip daddr 10.200.0.3 tcp dport 8080 accept\n'
        if reporter_rule not in infra:
            anchor = '  oifname "vmbr98" counter drop\n'
            if anchor not in infra:
                raise RuntimeError("unrecognized infrastructure firewall; reporter rule not installed")
            proposed = infra.replace(anchor, reporter_rule + anchor)
            write("/etc/carrel/infra.nft.next", proposed)
            run("nft", "-c", "-f", "/etc/carrel/infra.nft.next")
            write(infra_path, proposed)
            run("nft", "-f", str(infra_path))
    unit = """[Unit]
Description=Carrel isolated DHCP %i
After=network.target
[Service]
ExecStart=/usr/sbin/ip netns exec carrel-%i /usr/sbin/dnsmasq --keep-in-foreground --conf-file=/etc/carrel/private-%i.conf --user=root
Restart=on-failure
RestartSec=3
"""
    if write("/etc/systemd/system/carrel-private-dhcp@.service", unit):
        run("systemctl", "daemon-reload")
    wanted = {net["id"] for net in state["networks"] if net.get("mode") == "managed"} if serve else set()
    existing = {path.stem.removeprefix("private-") for path in Path("/etc/carrel").glob("private-p*.conf")}
    existing.update(path.name.removeprefix("carrel-") for path in Path("/run/netns").glob("carrel-p*"))
    existing.update(path.name.removeprefix("d") for path in Path("/sys/class/net").glob("dp*"))
    for id in sorted(existing):
        if not re.fullmatch(r"p[0-9]{5}", id) or id in wanted:
            continue
        run("systemctl", "stop", f"carrel-private-dhcp@{id}")
        # Removing a namespace also asynchronously removes its veth peer. Delete
        # the host end first to avoid racing that removal on a subsequent command.
        if Path("/sys/class/net/d" + id).exists():
            run("ip", "link", "delete", "d" + id)
        if Path("/run/netns/carrel-" + id).exists():
            run("ip", "netns", "delete", "carrel-" + id)
        Path(f"/etc/carrel/private-{id}.conf").unlink(missing_ok=True)
        (STATE / f"{id}.leases").unlink(missing_ok=True)
    for net in state["networks"]:
        n, serial = integer(net["tenant_n"], 1, 254), integer(net["serial"], 1, 99)
        id = f"p{n:03d}{serial:02d}"
        # Private bridges carry guest traffic only; the host has no IP on them.
        ipv6 = Path(f"/proc/sys/net/ipv6/conf/{id}/disable_ipv6")
        if ipv6.exists():
            ipv6.write_text("1")
        if net.get("mode") != "managed" or not serve:
            continue
        subnet = ipaddress.IPv4Network(net["cidr"])
        if subnet.prefixlen not in (24, 25) or not subnet.is_private:
            raise ValueError("invalid managed subnet")
        ns, uplink, interface = "carrel-" + id, "d" + id, "h" + id
        if not Path("/run/netns/" + ns).exists():
            run("ip", "netns", "add", ns)
        if not Path("/sys/class/net/" + uplink).exists():
            run("ip", "link", "add", uplink, "type", "veth", "peer", "name", interface)
            run("ip", "link", "set", interface, "netns", ns)
        run("ip", "link", "set", uplink, "master", id)
        run("ip", "link", "set", uplink, "mtu", 1450, "up")
        run("ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
        run("ip", "netns", "exec", ns, "ip", "link", "set", interface, "mtu", 1450, "up")
        address = str(subnet.network_address + 1)
        run("ip", "netns", "exec", ns, "ip", "address", "replace", f"{address}/{subnet.prefixlen}", "dev", interface)
        conf = ["port=0", "bind-interfaces", "dhcp-authoritative", "log-dhcp", f"interface={interface}",
                f"dhcp-leasefile=/var/lib/carrel/{id}.leases", f"dhcp-range={subnet.network_address},static,{subnet.netmask},12h",
                "dhcp-option=option:router", "dhcp-option=option:dns-server", "dhcp-option=option:mtu,1450"]
        for m in state["machines"]:
            for nic in m["nics"]:
                if nic["network"] == id and nic.get("ip"):
                    ip = ipaddress.IPv4Address(nic["ip"])
                    if ip not in subnet or not re.fullmatch(r"02:cb:[0-9a-f:]{11}", nic["mac"]):
                        raise ValueError("invalid private lease")
                    conf.append(f"dhcp-host={nic['mac']},{ip},12h")
        changed = write(f"/etc/carrel/private-{id}.conf", "\n".join(conf) + "\n")
        run("dnsmasq", "--test", "--conf-file=" + f"/etc/carrel/private-{id}.conf")
        run("systemctl", "restart" if changed else "start", f"carrel-private-dhcp@{id}")
    bridges = [f'"p{integer(n["tenant_n"], 1, 254):03d}{integer(n["serial"], 1, 99):02d}"' for n in state["networks"]]
    rule = "meta ibrname { " + ", ".join(bridges) + " } drop" if bridges else ""
    nft = "add table bridge carrel_private_host\nflush table bridge carrel_private_host\n"
    nft += "table bridge carrel_private_host {\n chain input {\n type filter hook input priority -200; policy accept;\n " + rule + "\n }\n}\n"
    write("/etc/carrel/private-host.nft", nft)
    run("nft", "-c", "-f", "/etc/carrel/private-host.nft")
    run("nft", "-f", "/etc/carrel/private-host.nft")
    firewall_unit = """[Unit]
Description=Carrel private bridges cannot reach the host
After=network.target
Before=pve-guests.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/carrel/private-host.nft
[Install]
WantedBy=multi-user.target
"""
    if write("/etc/systemd/system/carrel-private-host.service", firewall_unit):
        run("systemctl", "daemon-reload")
        run("systemctl", "enable", "carrel-private-host")


def nic_value(m, nic):
    index = integer(nic["index"], 1, 7)
    network = nic["network"]
    if not re.fullmatch(f"p{m['tenant_n']:03d}[0-9]{{2}}", network):
        raise ValueError("invalid private network")
    mac = nic["mac"]
    if not re.fullmatch(r"02:c[bc]:[0-9a-f:]{11}", mac):
        raise ValueError("invalid private MAC")
    base = f"bridge={network},firewall=0,rate=100"
    if m["kind"] == "vm":
        return f"virtio={mac},{base},mtu=1"
    address = f"{ipaddress.IPv4Address(nic['ip'])}/{integer(nic['prefix'], 24, 25)}" if nic.get("ip") else "manual"
    return f"name=eth{index},type=veth,hwaddr={mac},mtu=1450,ip={address},{base}"


def sdn_owed(links_missing, first, wait=30):
    """Whether this node must reload SDN for tenant links it lacks. The first
    node applies new VNets for the whole cluster, and that reload usually
    brings the links to the others too (issue #48): they wait for it and
    reload only if the links are still missing, not once per node."""
    if not links_missing():
        return False
    if first:
        return True
    for _ in range(wait):
        time.sleep(1)
        if not links_missing():
            return False
    return True


def reconcile(state, first=True):
    config = json.loads(CONFIG.read_text())
    changed = []
    # One fresh observation per reconciliation. Mutations remain serialized
    # by the node adapter's infrastructure lock.
    vnets, subnets_by_vnet = topology_read()
    for t in state["tenants"]:
        n, vnet = tenant_config(t)
        if ensure(
            "/cluster/sdn/vnets", "vnet", vnet, existing=vnets, zone="tenants", tag=100000 + n, alias="carrel-" + t["slug"]
        ):
            changed.append(vnet)
        subnets = subnets_by_vnet.get(vnet, [])
        if not subnets:
            api(
                "create",
                f"/cluster/sdn/vnets/{vnet}/subnets",
                subnet=f"10.200.{n}.0/24",
                type="subnet",
                gateway=f"10.200.{n}.1",
                snat=1,
            )
            changed.append(f"subnet-{n}")
    if state.get("fetch"):
        # The fetch network (PLAN 6.1, N = 255): only the fetch container.
        if ensure("/cluster/sdn/vnets", "vnet", "t255", existing=vnets, zone="tenants", tag=100255, alias="carrel-fetch"):
            changed.append("t255")
        if not subnets_by_vnet.get("t255"):
            api("create", "/cluster/sdn/vnets/t255/subnets", subnet="10.200.255.0/24", type="subnet", gateway="10.200.255.1", snat=1)
            changed.append("subnet-255")
    for net in state["networks"]:
        n = integer(net["tenant_n"], 1, 254)
        k = integer(net["serial"], 1, 99)
        name = f"p{n:03d}{k:02d}"
        if ensure(
            "/cluster/sdn/vnets",
            "vnet",
            name,
            existing=vnets,
            zone="private",
            tag=200000 + n * 100 + k,
            vlanaware=1,
            alias="carrel-" + label(net["name"]),
        ):
            changed.append(name)
    # Delete only owned private networks absent from the desired database.
    wanted = {f"p{x['tenant_n']:03d}{x['serial']:02d}" for x in state["networks"]}
    for v in vnets:
        if v["zone"] == "private" and v.get("alias", "").startswith("carrel-") and v["vnet"] not in wanted:
            api("delete", f"/cluster/sdn/vnets/{v['vnet']}")
            changed.append("removed-" + v["vnet"])
    def links_missing():
        return any(not Path("/sys/class/net/" + f"t{t['n']:03d}").exists() for t in state["tenants"])

    if changed or sdn_owed(links_missing, first):
        task = api("set", "/cluster/sdn")
        if isinstance(task, str) and task.startswith("UPID:"):
            for _ in range(60):
                status = pve_get(f"/nodes/{NODE}/tasks/{urllib.parse.quote(task, safe='')}/status")
                if status["status"] == "stopped":
                    if status.get("exitstatus") != "OK":
                        raise RuntimeError("SDN reload failed")
                    break
                time.sleep(1)
            else:
                raise TimeoutError("SDN reload")
        for t in state["tenants"]:
            if not Path("/sys/class/net/" + f"t{t['n']:03d}").exists():
                raise RuntimeError(
                    "SDN reload left a missing tenant bridge; inspect the node networking task"
                )
    # Only exit nodes have the cross-VRF pair; other nodes route to them over EVPN.
    if state["tenants"] and Path("/sys/class/net/xvrfp_tenants").exists():
        # Route through the cross-VRF pair in both directions. Separate tracking
        # zones keep the outer SNAT tuple distinct from the tenant-side tuple.
        # Otherwise a SYN-ACK re-entering the VRF is INVALID in PVE's nft firewall.
        run(
            "ip",
            "route",
            "replace",
            "vrf",
            "vrf_tenants",
            "default",
            "via",
            "10.255.255.1",
            "dev",
            "xvrfp_tenants",
        )
    for t in state["tenants"]:
        n, vnet = tenant_config(t)
        if "clsact" not in run("tc", "qdisc", "show", "dev", vnet):
            run("tc", "qdisc", "add", "dev", vnet, "clsact")
        run(
            "tc",
            "filter",
            "replace",
            "dev",
            vnet,
            "ingress",
            "protocol",
            "ip",
            "pref",
            "49152",
            "handle",
            "1",
            "flower",
            "src_ip",
            f"10.200.{n}.0/24",
            "action",
            "police",
            "rate",
            "100mbit",
            "burst",
            "1mb",
            "conform-exceed",
            "drop/ok",
        )
    interfaces = [f"{'tap' if m['kind'] == 'vm' else 'veth'}{machine(m)}i0" for m in state["machines"]]
    # Same-tenant traffic between nodes enters through the VNet's VXLAN port;
    # it must share the guests' zone, or the reply of a cross-node connection
    # finds no entry and is dropped as invalid.
    interfaces += [f"vxlan_{tenant_config(t)[1]}" for t in state["tenants"]]
    if state.get("fetch"):
        # The fetch container and its network cross the VRF like a tenant's.
        interfaces += [f"veth{FETCH_CT}i0", "vxlan_t255"]
    # Routed tenant traffic between nodes (egress to the exit node, replies of
    # public DNAT) crosses the zone's L3VNI port; it needs the same zone.
    interfaces.append("vrfvx_tenants")
    interface_rule = (
        "iifname { " + ", ".join('"' + i + '"' for i in interfaces) + " } ct zone set 1" if interfaces else ""
    )
    tracking = f"""add table bridge carrel_conntrack
flush table bridge carrel_conntrack
table bridge carrel_conntrack {{
 chain prerouting {{ type filter hook prerouting priority -300; policy accept;
  {interface_rule}
 }}
}}
add table inet carrel_conntrack
flush table inet carrel_conntrack
table inet carrel_conntrack {{
 chain prerouting {{ type filter hook prerouting priority -300; policy accept;
  iifname {{ "xvrfp_tenants", "vrf_tenants", "vrfbr_tenants" }} ct zone set 1
  iifname "wg-t*" ct zone set 1
 }}
}}
"""
    write("/etc/carrel/conntrack.nft", tracking)
    run("nft", "-c", "-f", "/etc/carrel/conntrack.nft")
    run("nft", "-f", "/etc/carrel/conntrack.nft")
    run("systemctl", "start", "carrel-conntrack")
    # Per-guest filtering protects routed and same-node bridged paths. Private
    # experiment NICs deliberately have firewall=0; primary NIC is mandatory.
    # The files are cluster-wide: one node writes them.
    if first_exit_node():
        for m in state["machines"]:
            write(f"/etc/pve/firewall/{m['vmid']}.fw", guest_firewall(m, state, config))
        if state.get("fetch"):
            write(f"/etc/pve/firewall/{FETCH_CT}.fw", fetch_firewall(config))
    private_dhcp(state, serve=first_exit_node())
    address = public_ingress()
    if address:
        bindings = public_bindings(state, config.get("protected_addresses", []))
        rules = ports_nft(state, address, bindings)
        write("/etc/carrel/ports.nft.next", rules)
        run("nft", "-c", "-f", "/etc/carrel/ports.nft.next")
        write("/etc/carrel/ports.nft", rules)
        run("nft", "-f", "/etc/carrel/ports.nft")
        # The rules first: an address held without them reaches only the
        # node, whose public input drops it.
        public_addresses({public: m["ip"] for public, m, _ in bindings})
        unit = """[Unit]
Description=Carrel public port forwarding
After=carrel-public.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/carrel/ports.nft
ExecStartPost=/usr/local/lib/carrel/node-agent.py public-ips
[Install]
WantedBy=multi-user.target
"""
        if write("/etc/systemd/system/carrel-ports.service", unit):
            run("systemctl", "daemon-reload")
            run("systemctl", "enable", "carrel-ports")
    tunnels = vpn(state)
    write(STATE / "vips.json", json.dumps(vip_targets(state)))
    if write("/etc/systemd/system/carrel-vip-probe.service", VIP_PROBE_UNIT):
        run("systemctl", "daemon-reload")
    # Every time, so an enable that failed once is retried.
    run("systemctl", "enable", "--now", "carrel-vip-probe")
    write(STATE / "desired.json", json.dumps(state, sort_keys=True))
    if tunnels:
        return {"changed": changed, "vpn": tunnels}
    return {"changed": changed}


# Virtual addresses across nodes (issue #96). A remote EVPN neighbour entry is
# NOARP, so the kernel ignores the new holder's gratuitous ARP and FRR never
# learns the move while the old node still advertises its own entry. That
# entry stays STALE as long as nothing uses it. Probing it every second lets it
# fail within seconds of the address leaving; FRR withdraws the route and the
# new holder's next gratuitous ARP is learned (measured on B09, 2026-10-21).
VIP_PROBE_UNIT = """[Unit]
Description=Carrel virtual address probe
After=frr.service
[Service]
ExecStart=/usr/local/lib/carrel/node-agent.py vip-probe
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
"""


def vip_targets(state):
    out = []
    for vip in state.get("vips", []):
        n = integer(vip["tenant_n"], 1, 254)
        address = ipaddress.IPv4Address(vip["address"])
        if address not in ipaddress.IPv4Network(f"10.200.{n}.0/24") or not 251 <= int(address) % 256 <= 254:
            raise ValueError("invalid virtual address")
        out.append({"address": str(address), "dev": f"t{n:03d}"})
    return sorted(out, key=lambda v: v["address"])


def vip_probe_once(targets, run=run):
    probed = []
    for v in targets:
        try:
            entries = json.loads(run("ip", "-j", "neigh", "show", v["address"], "dev", v["dev"]) or "[]")
        except CommandFailure:
            # One missing bridge must not stop the others.
            print(f"vip-probe: cannot read {v['dev']}", file=sys.stderr)
            continue
        for entry in entries:
            # Only this node's own entry: remote ones are FRR's.
            if "extern_learn" in entry.get("flags", []) or "lladdr" not in entry:
                continue
            if set(entry.get("state", [])) & {"REACHABLE", "STALE", "DELAY"}:
                run("ip", "neigh", "change", v["address"], "dev", v["dev"], "lladdr", entry["lladdr"], "nud", "probe")
                probed.append(v["address"])
    return probed


def vip_probe():
    started = Path(__file__).stat().st_mtime
    while True:
        # A deploy replaces this file: run the new code.
        if Path(__file__).stat().st_mtime != started:
            os.execv(sys.executable, [sys.executable, __file__, "vip-probe"])
        try:
            path = STATE / "vips.json"
            vip_probe_once(json.loads(path.read_text()) if path.exists() else [])
        except Exception as e:  # noqa: BLE001 - the loop outlives one bad round
            print(f"vip-probe: {type(e).__name__}", file=sys.stderr)
        time.sleep(1)


def keys(values):
    if not 1 <= len(values) <= 20:
        raise ValueError("1 to 20 public keys required")
    for key in values:
        if (
            len(key) > 16000
            or "\n" in key
            or not re.fullmatch(
                r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+) [A-Za-z0-9+/=]+(?: [^\r\n]*)?", key
            )
        ):
            raise ValueError("invalid SSH public key")
    return "\n".join(values) + "\n"


def cloud_init(m, *, prepared=False, environment="development"):
    name = f"carrel-{m['vmid']}-user.json"
    if m.get("service_ports"):
        # An image without SSH (issue #94): the member's own document, which
        # Talos reads as its machine config. Without one, an empty
        # cloud-config, which Talos skips and boots into maintenance mode.
        user = m.get("user_data") or "#cloud-config\n{}\n"
        if not isinstance(user, str) or len(user.encode()) > 65536:
            raise ValueError("user_data is a string of at most 64 KiB")
        write("/var/lib/vz/snippets/" + name, user, 0o600)
        return "user=local:snippets/" + name + ",network=local:snippets/" + network_file(m)
    keys(m["ssh_keys"])
    blocked = "guest-exec,guest-exec-status,guest-file-open,guest-file-close,guest-file-read,guest-file-write,guest-file-seek,guest-file-flush,guest-set-user-password"
    data = {
        "hostname": m["name"],
        "manage_etc_hosts": True,
        "users": [
            {
                "name": "user",
                "lock_passwd": True,
                "shell": "/bin/bash",
                "sudo": "ALL=(ALL) NOPASSWD:ALL",
                "ssh_authorized_keys": m["ssh_keys"],
                **({"groups": ["docker"]} if prepared and environment == "development" else {}),
            }
        ],
        "disable_root": True,
        "ssh_pwauth": False,
        "timezone": "Asia/Taipei",
        "package_update": bool(m.get("packages")) or not prepared,
        "packages": ([] if prepared else ["qemu-guest-agent", "unattended-upgrades"]) + m.get("packages", []),
        "write_files": [
            {"path": "/etc/qemu/qemu-ga.conf", "content": "[general]\nblock-rpcs=" + blocked + "\n"},
            {"path": "/etc/sysctl.d/90-carrel.conf", "content": "vm.swappiness=10\n"},
        ],
        "runcmd": [
            ["systemctl", "enable", "--now", "qemu-guest-agent", "fstrim.timer"],
            ["sysctl", "--system"],
            *m.get("runcmd", []),
        ],
    }
    if not data["packages"]:
        del data["packages"]
    distro = str(m.get("image", "")).split("-", 1)[0]
    if url := mirror_url(distro):
        # cloud-init writes the sources (Debian: its mirror lists) from this on
        # first boot. Debian's security archive stays upstream.
        security = url if distro == "ubuntu" else "https://deb.debian.org/debian-security"
        data["apt"] = {"generate_mirrorlists": True,
                       "primary": [{"arches": ["default"], "uri": url}],
                       "security": [{"arches": ["default"], "uri": security}]}
    if m.get("readiness_token"):
        private_macs = " ".join(f"02:cb:{m['tenant_n']:02x}:{m['host']-10:02x}:{i:02x}:01" for i in range(1, 8))
        reporter = Path("/usr/local/lib/carrel/guest-report.py").read_text()
        commands = "import json,subprocess\nfrom pathlib import Path\np=Path('/var/lib/carrel-bootstrap.json')\n"
        commands += "subprocess.run(['networkctl','reload'],check=True)\n"
        commands += "for interface in json.loads(subprocess.check_output(['ip','-j','link'])):\n"
        commands += " if interface.get('address','').startswith('02:cb:'):\n  subprocess.run(['networkctl','reconfigure',interface['ifname']],check=True)\n"
        commands += "for i,command in enumerate(json.loads(" + repr(json.dumps(m.get("runcmd", []))) + ")):\n"
        commands += " p.write_text(json.dumps({'state':'running','step':i}))\n result=subprocess.run(command,check=False)\n"
        commands += " if result.returncode:\n  p.write_text(json.dumps({'state':'failed','step':i}))\n  raise SystemExit(result.returncode)\n"
        commands += "p.write_text(json.dumps({'state':'complete'}))\n"
        data["write_files"] += [
            {"path": "/usr/local/lib/carrel/guest-report.py", "content": reporter, "permissions": "0755"},
            {"path": "/etc/carrel/guest.json", "content": json.dumps({"vmid": m["vmid"], "token": m["readiness_token"], "health_checks": m.get("health_checks", [])}), "permissions": "0600"},
            {"path": "/usr/local/lib/carrel/bootstrap.py", "content": commands, "permissions": "0700"},
            {"path": "/etc/systemd/system/carrel-guest-report.service", "content": "[Unit]\nAfter=cloud-final.service\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 /usr/local/lib/carrel/guest-report.py\n"},
            {"path": "/etc/systemd/system/carrel-guest-report.timer", "content": "[Unit]\nDescription=Carrel boot and application status\n[Timer]\nOnBootSec=1s\nOnUnitActiveSec=15s\n[Install]\nWantedBy=timers.target\n"},
            {"path": "/etc/systemd/network/20-carrel-private.network", "content": "[Match]\nMACAddress=" + private_macs + "\n[Link]\nMTUBytes=1450\n[Network]\nDHCP=ipv4\nLinkLocalAddressing=no\nIPv6AcceptRA=no\n[DHCPv4]\nUseRoutes=no\nUseDNS=no\nUseNTP=no\nUseHostname=no\n"},
        ]
        data["runcmd"] = [
            ["systemctl", "daemon-reload"],
            ["systemctl", "enable", "--now", "systemd-networkd", "carrel-guest-report.timer", "qemu-guest-agent", "fstrim.timer"],
            ["sysctl", "--system"],
            ["python3", "/usr/local/lib/carrel/bootstrap.py"],
        ]
    if m.get("swap_mb", 1024):
        data["swap"] = {
            "filename": "/swapfile",
            "size": str(integer(m.get("swap_mb", 1024), 0, 65536)) + "M",
            "maxsize": str(m.get("swap_mb", 1024)) + "M",
        }
    write("/var/lib/vz/snippets/" + name, "#cloud-config\n" + json.dumps(data), 0o600)
    return "user=local:snippets/" + name + ",network=local:snippets/" + network_file(m)


def network_file(m):
    network_name = f"carrel-{m['vmid']}-network.json"
    network = {"version": 2, "ethernets": {"primary": {
        "match": {"macaddress": m["mac"]}, "addresses": [m["ip"] + "/24"],
        "routes": [{"to": "0.0.0.0/0", "via": f"10.200.{m['tenant_n']}.1"}],
        "nameservers": {"addresses": ["10.200.0.2"]}, "mtu": 1450,
    }}}
    write("/var/lib/vz/snippets/" + network_name, json.dumps(network), 0o600)
    return network_name


def zfs_usage(machines, pool):
    # ZFS accounts blocks per dataset: a linked clone's usedbydataset excludes
    # the template's blocks, and usedbysnapshots counts what only snapshots hold.
    owners = {m["vmid"]: m["tenant_n"] for m in machines}
    totals = {n: {"live": 0, "snapshots": 0} for n in set(owners.values())}
    rows = run("zfs", "list", "-H", "-p", "-d", "1", "-t", "filesystem,volume",
               "-o", "name,usedbydataset,usedbysnapshots", pool)
    for row in rows.splitlines():
        name, live, snapshots = row.split("\t")
        match = re.fullmatch(r"(?:vm|subvol)-(\d+)-(?:disk-\d+|cloudinit)", name.rsplit("/", 1)[-1])
        if match and int(match[1]) in owners:
            usage = totals[owners[int(match[1])]]
            usage["live"] += int(live)
            usage["snapshots"] += int(snapshots)
    now = time.time()
    return [{"tenant_n": n, "sampled_at": now, "available": True,
             "retained_snapshot_bytes": v["snapshots"],
             "unique_total_bytes": v["live"] + v["snapshots"],
             "accounting": "zfs_usedbydataset_plus_usedbysnapshots"} for n, v in totals.items()]


def vm_template(image):
    defaults = {"debian-13-minimal": None, "debian-13": 9000, "ubuntu-24.04": 9001}
    if image not in defaults:
        raise ValueError("image not installed")
    path = Path("/etc/carrel/templates.json")
    configured = json.loads(path.read_text()) if path.exists() else {}
    value = configured.get(image, {"vmid": defaults[image], "prepared": False})
    environment = value.get("environment", "development")
    if image == "debian-13-minimal" and (not value.get("prepared") or environment != "minimal"):
        raise ValueError("prepared Debian minimal template is not installed")
    return {"vmid": integer(value["vmid"], 9000, 9999), "prepared": value.get("prepared") is True,
            "environment": environment}


def first_firewall(m):
    """Write the guest firewall before the guest first starts.

    qm clone drops an existing <vmid>.fw (PVE copies the template's, which has
    none), so the file the reconcile before creation wrote is gone. The grants
    come from the state that reconcile saved here.
    """
    saved = STATE / "desired.json"
    state = json.loads(saved.read_text()) if saved.exists() else {}
    grants = {k: state.get(k, []) for k in ("peers", "ports", "domains", "vips")}
    write(f"/etc/pve/firewall/{m['vmid']}.fw", guest_firewall(m, grants, json.loads(CONFIG.read_text())))


def tenant_route():
    """Whether this node routes tenant traffic out: the VRF needs a default
    route through a gateway (one, or several with ECMP), not only PVE's
    unreachable placeholder. None before the first tenant creates the VRF."""
    if not Path("/sys/class/net/vrf_tenants").exists():
        return None
    try:
        routes = json.loads(run("ip", "-j", "route", "show", "vrf", "vrf_tenants", "default") or "[]")
    except CommandFailure:
        return False
    return any(r.get("gateway") or any(h.get("gateway") for h in r.get("nexthops", [])) for r in routes)


SNIPPETS = Path("/var/lib/vz/snippets")


def cloud_init_files(m):
    """The exact cloud-init files of a VM, for the control plane to keep (issue #93).

    Proxmox makes the instance id the SHA-1 of these bytes, so a copy written
    on another node must be these bytes, never a regenerated file.
    """
    vmid = machine(m)
    paths = {kind: SNIPPETS / f"carrel-{vmid}-{kind}.json" for kind in ("user", "network")}
    if m.get("kind") != "vm" or not all(p.exists() for p in paths.values()):
        return {}
    return {"cloud_init": {kind: p.read_text() for kind, p in paths.items()}}


def restore_cloud_init(m, files):
    # Only a missing file is written back: one that exists is what this VM
    # booted with, and replacing it would change its instance id.
    vmid = machine(m)
    for kind in ("user", "network"):
        path = SNIPPETS / f"carrel-{vmid}-{kind}.json"
        if path.exists():
            continue
        data = files[kind]
        if not isinstance(data, str) or len(data) > 4_000_000:
            raise ValueError("invalid cloud-init file")
        write(path, data, 0o600)


def located(m):
    """The node whose configuration holds this machine, or None."""
    vmid = machine(m)
    kind = "qemu-server" if m["kind"] == "vm" else "lxc"
    found = [p.parts[-3] for p in PVE_NODES.glob(f"*/{kind}/{vmid}.conf")]
    return found[0] if len(found) == 1 else None


def migration_bwlimit(req):
    return integer(req.get("bwlimit", 51200), 1024, 1048576)


def migrate_prepare(req):
    # On the target, before the machine arrives (PLAN 7.10): its exact
    # cloud-init files, so the first boot here keeps its instance id.
    m = req["machine"]
    where = located(m)
    if where is None:
        raise ValueError("machine not found in the cluster")
    owned(m, node=where)
    # Every VM with cloud-init: managed, or without SSH (issue #94).
    if m["kind"] == "vm" and (m.get("guest_management", 1) or m.get("service_ports")):
        if not req.get("cloud_init"):
            raise ValueError("cloud-init files required to move a VM")
        if where == NODE:
            return {"state": "ready"}
        # The VM has never booted here: a file left by an earlier VM with
        # this VMID, or an older copy of this one, gives way to the stored bytes.
        vmid = machine(m)
        for kind in ("user", "network"):
            (SNIPPETS / f"carrel-{vmid}-{kind}.json").unlink(missing_ok=True)
        restore_cloud_init(m, req["cloud_init"])
    return {"state": "ready"}


def migrate(req):
    # Runs where the machine is. A retry after it already moved is done.
    m, target = req["machine"], req["target"]
    vmid = machine(m)
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", target) or not (PVE_NODES / target).is_dir() or target == NODE:
        raise ValueError("invalid target node")
    where = located(m)
    if where == target:
        return {"state": "moved"}
    if where != NODE:
        raise ValueError("machine is not on this node")
    cfg = owned(m)
    bw = migration_bwlimit(req)
    if m["kind"] == "vm":
        running = "running" in run("qm", "status", vmid)
        storage, _, name = cfg["scsi0"].split(",")[0].partition(":")
        if storage == storage_id() and name.startswith("base-"):
            # Proxmox refuses to migrate a linked clone on local storage: its
            # disk goes to the shared storage first, which also unlinks it.
            # A retry finds it there already and goes straight to migrating.
            transit = content_storage("images")
            entry = storage_entry(transit)
            if entry is None or entry["type"] not in ("nfs", "cifs") or "images" not in entry.get("content", ""):
                raise ValueError("moving a linked clone needs the site's shared images storage")
            run("qm", "disk", "move", vmid, "scsi0", transit, "--format", "qcow2", "--delete", "1", "--bwlimit", bw, timeout=4 * 3600)
        run("qm", "migrate", vmid, target, "--with-local-disks", "--bwlimit", bw, *(["--online"] if running else []), timeout=4 * 3600)
    else:
        running = "running" in run("pct", "status", vmid)
        run("pct", "migrate", vmid, target, "--bwlimit", bw, *(["--restart"] if running else []), timeout=4 * 3600)
    if located(m) != target:
        raise CommandFailure("migration did not reach the target")
    return {"state": "moved"}


def migrate_finish(req):
    # On the target: a disk that arrived on the shared storage goes back to
    # this node's guest storage, still online.
    m = req["machine"]
    vmid = machine(m)
    if located(m) != NODE:
        raise ValueError("machine is not on this node")
    cfg = owned(m)
    if m["kind"] == "vm":
        storage = storage_id()
        if cfg["scsi0"].split(",")[0].partition(":")[0] != storage:
            run("qm", "disk", "move", vmid, "scsi0", storage, "--delete", "1", "--bwlimit", migration_bwlimit(req), timeout=4 * 3600)
    return {"state": "done"}


def cloud_init_remove(req):
    # On the node a VM left: its files must not outlive it here.
    m = req["machine"]
    vmid = machine(m)
    if located(m) == NODE:
        raise ValueError("machine is still on this node")
    for kind in ("user", "network"):
        (SNIPPETS / f"carrel-{vmid}-{kind}.json").unlink(missing_ok=True)
    return {"state": "removed"}


# The fetch container (PLAN 7.8): unprivileged, on the fetch network, with
# no view of the shared storage. Downloads land in its own disk; a root step
# here pulls them out through the container, so a symlink it plants
# resolves inside the container, never on this host.
FETCH_CT = 103
FETCH_DIR = "/var/lib/carrel-fetch"
JOB = re.compile(r"[a-f0-9]{32}")
VOLUME = re.compile(r"carrel-t(\d{3})-[a-z][a-z0-9-]{0,31}-[a-f0-9]{12}\.(iso|qcow2|raw)")


def bounded(args, out, limit, timeout):
    """Run a command whose output is untrusted: at most limit bytes into out,
    and at the deadline the whole process group dies (pct forks a worker),
    even while a read is blocked."""
    with subprocess.Popen([str(a) for a in args], stdout=subprocess.PIPE, start_new_session=True) as p:
        expired = threading.Event()

        def kill():
            # The group may be gone already; that must not hide the error.
            with contextlib.suppress(ProcessLookupError):
                os.killpg(p.pid, 9)

        def expire():
            expired.set()
            kill()

        timer = threading.Timer(timeout, expire)
        timer.start()
        total = 0
        try:
            while chunk := p.stdout.read(1 << 20):
                total += len(chunk)
                if total > limit:
                    raise ValueError("output over its limit")
                out.write(chunk)
            p.wait()
        except BaseException:
            kill()
            raise
        finally:
            timer.cancel()
        if expired.is_set():
            raise subprocess.TimeoutExpired(args, timeout)
        if p.returncode:
            raise CommandFailure(f"{args[0]} failed")
    return total


def in_fetch(job, name, limit):
    # Read inside the container as its root, so its paths resolve there; a
    # regular file only, never more than limit bytes.
    path = f"{FETCH_DIR}/{job}.{name}"
    return ["pct", "exec", FETCH_CT, "--", "sh", "-c",
            f'test -f "{path}" && test ! -L "{path}" && exec head -c {limit + 1} "{path}"']


def fetch_firewall(config):
    rules = [
        "[OPTIONS]", "enable: 1", "ipfilter: 1", "macfilter: 1", "dhcp: 0", "ndp: 0", "radv: 0",
        "policy_in: DROP", "policy_out: DROP", "",
        "[IPSET ipfilter-net0]", "10.200.255.10", "",
        "[RULES]",
        "OUT ACCEPT -dest 10.200.0.2 -p udp -dport 53",
        "OUT ACCEPT -dest 10.200.0.2 -p tcp -dport 53",
    ]
    for block in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
                  "127.0.0.0/8", "224.0.0.0/4", *config["protected_addresses"]]:
        rules.append(f"OUT DROP -dest {ipaddress.ip_network(block, strict=False)}")
    rules += ["OUT ACCEPT -p tcp -dport 80", "OUT ACCEPT -p tcp -dport 443"]
    return "\n".join(rules) + "\n"


def fetch_job(req):
    job = req["job"]
    if not isinstance(job, str) or not JOB.fullmatch(job):
        raise ValueError("invalid job")
    return job


def fetch_start(req):
    job = fetch_job(req)
    spec = {
        "url": req["url"], "sha256": req["sha256"], "max_bytes": integer(req["max_bytes"], 1, 20 * 1024**3),
        "format": req["format"], "out": f"{FETCH_DIR}/{job}.data",
        "refused": [str(ipaddress.ip_network(r, strict=False)) for r in req.get("refused", [])],
    }
    if not isinstance(spec["url"], str) or len(spec["url"]) > 4096 or not re.fullmatch(r"[a-f0-9]{64}", spec["sha256"]):
        raise ValueError("invalid fetch")
    if spec["format"] not in ("iso", "qcow2", "raw"):
        raise ValueError("invalid format")
    staged = STATE / f"fetch-{job}.json"
    write(staged, json.dumps(spec), 0o644)
    try:
        run("pct", "push", FETCH_CT, staged, f"{FETCH_DIR}/{job}.json", "--user", "carrel-fetch", "--group", "carrel-fetch")
    finally:
        staged.unlink(missing_ok=True)
    run("pct", "exec", FETCH_CT, "--", "systemd-run", "--collect", f"--unit=carrel-fetch-{job}", "--uid=carrel-fetch", "--gid=carrel-fetch",
        f"--property=StandardInput=file:{FETCH_DIR}/{job}.json", f"--property=StandardOutput=file:{FETCH_DIR}/{job}.result",
        "--property=RuntimeMaxSec=11000", "--property=MemoryMax=512M", "--property=NoNewPrivileges=yes",
        "/usr/local/bin/carrel-fetch")
    return {"state": "running"}


def fetch_status(req):
    job = fetch_job(req)
    out = run("pct", "exec", FETCH_CT, "--", "sh", "-c",
              f"head -c 4096 {FETCH_DIR}/{job}.result 2>/dev/null; echo; stat -c %s {FETCH_DIR}/{job}.data 2>/dev/null; "
              f"systemctl is-active carrel-fetch-{job} 2>/dev/null; true", timeout=30)
    lines = out.splitlines()
    result = {}
    if lines and lines[0].startswith("{"):
        result = json.loads(lines[0])
    received = next((int(x) for x in lines[1:] if x.isdigit()), 0)
    active = "active" in lines[-1:] or "activating" in lines[-1:]
    if result:
        return {"state": "done" if result.get("ok") else "failed", "result": result, "received": received}
    return {"state": "running" if active else "failed", "received": received,
            **({} if active else {"result": {"code": "fetch_failed", "error": "the download stopped"}})}


def fetch_store(req):
    # Root step: the checksum from the database, never the fetcher's word.
    job = fetch_job(req)
    name, kind = req["volume"], req["kind"]
    match = VOLUME.fullmatch(name) if isinstance(name, str) else None
    if not match or kind not in ("iso", "import"):
        raise ValueError("invalid volume")
    if (kind == "iso") != name.endswith(".iso"):
        raise ValueError("volume kind does not match its file")
    digest = req["sha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("invalid checksum")
    # The name carries its tenant and the start of its checksum.
    if int(match[1]) != integer(req["tenant_n"], 1, 254) or name.rsplit("-", 1)[1][:12] != digest[:12]:
        raise ValueError("volume name does not match its tenant or checksum")
    limit = integer(req["max_bytes"], 1, 20 * 1024**3)
    storage = content_storage(kind)
    entry = storage_entry(storage)
    if entry is None or "path" not in entry:
        raise ValueError("the image storage is not a directory storage")
    folder = Path(entry["path"]) / ("template/iso" if kind == "iso" else "import")
    final = folder / name
    lock_path = STATE / f"fetch-{job}.lock"
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not final.exists():
            partial = folder / f".carrel-{job}.partial"
            try:
                with partial.open("wb") as out:
                    bounded(in_fetch(job, "data", limit), out, limit, 4 * 3600)
                if sha256_limited(partial) != digest:
                    raise ValueError("stored file does not match its checksum")
                partial.chmod(0o444)
                os.replace(partial, final)
            except subprocess.TimeoutExpired as e:
                raise StorageUnavailable("the image storage did not answer") from e
            finally:
                partial.unlink(missing_ok=True)
        fetch_clean(req)
    lock_path.unlink(missing_ok=True)
    return {"state": "stored", "volume": f"{storage}:{kind}/{name}", "size": final.stat().st_size}


def image_delete(req):
    # A tenant's stored image (PLAN 7.8); the name must carry that tenant.
    name, kind = req["volume"], req["kind"]
    match = VOLUME.fullmatch(name) if isinstance(name, str) else None
    if not match or kind not in ("iso", "import") or int(match[1]) != integer(req["tenant_n"], 1, 254):
        raise ValueError("invalid volume")
    entry = storage_entry(content_storage(kind))
    if entry is None or "path" not in entry:
        raise ValueError("the image storage is not a directory storage")
    (Path(entry["path"]) / ("template/iso" if kind == "iso" else "import") / name).unlink(missing_ok=True)
    return {"state": "deleted"}


def fetch_clean(req):
    job = fetch_job(req)
    run("pct", "exec", FETCH_CT, "--", "sh", "-c",
        f"systemctl stop carrel-fetch-{job} 2>/dev/null; rm -f {FETCH_DIR}/{job}.json {FETCH_DIR}/{job}.data {FETCH_DIR}/{job}.result")
    return {"state": "cleaned"}


def iso_volume(m, volume):
    # Only this tenant's ISOs, on the site's ISO storage (PLAN 7.8).
    storage, _, rest = str(volume).partition(":iso/")
    match = VOLUME.fullmatch(rest)
    if storage != content_storage("iso") or not match or int(match[1]) != m["tenant_n"] or not rest.endswith(".iso"):
        raise ValueError("invalid ISO volume")
    entry = storage_entry(storage)
    if entry is None or "path" not in entry:
        raise ValueError("the ISO storage is not a directory storage")
    probe(Path(entry["path"]) / "template" / "iso" / rest)
    return f"{storage}:iso/{rest}"


def probe(path):
    # A hard NFS mount waits forever: look in a child with a deadline.
    try:
        run("test", "-f", path, timeout=10)
    except (CommandFailure, subprocess.TimeoutExpired) as e:
        raise StorageUnavailable(f"{path.name} missing or its storage unreachable") from e


def create_from_iso(m, exists, manifest, saved, marker):
    """An empty VM with an installer ISO (PLAN 7.8): no template, no
    cloud-init. The disk boots first, so a finished install never loops back
    into the installer."""
    vmid = machine(m)
    integer(m["cpu"], 1, 64)
    integer(m["memory_mb"], 512, 131072)
    integer(m["disk_gb"], 10, 1000)
    n = m["tenant_n"]
    iso = iso_volume(m, m["iso_volume"])
    storage = storage_id()
    if not exists:
        args = ["qm", "create", vmid, "--name", m["name"], "--description", marker, "--tags", f"carrel;tenant-{n}",
                "--cores", m["cpu"], "--memory", m["memory_mb"], "--balloon", "0", "--cpu", "x86-64-v2-AES",
                "--net0", f"virtio={m['mac']},bridge=t{n:03d},firewall=1,mtu=1,rate=12.5",
                "--scsihw", "virtio-scsi-single", "--scsi0", f"{storage}:{m['disk_gb']},iothread=1,discard=on,ssd=1",
                "--ide2", f"{iso},media=cdrom", "--boot", "order=scsi0;ide2", "--ostype", "l26",
                "--vga", "std", "--onboot", "1", "--startup", "order=20,up=3"]
        if m.get("firmware") == "uefi":
            args += ["--bios", "ovmf", "--machine", "q35", "--efidisk0", f"{storage}:1,efitype=4m,pre-enrolled-keys=1"]
            if m.get("tpm"):
                args += ["--tpmstate0", f"{storage}:1,version=v2.0"]
        elif m.get("tpm"):
            raise ValueError("a TPM needs UEFI firmware")
        run(*args, timeout=600)
    for nic in m["nics"]:
        run("qm", "set", vmid, f"--net{integer(nic['index'], 1, 7)}", nic_value(m, nic))
    first_firewall(m)
    if "running" not in run("qm", "status", vmid):
        run("qm", "start", vmid)
    write(manifest, json.dumps({**saved, "marker": marker, "complete": True}), 0o600)
    return {"state": "running", "vmid": vmid}


# Reads of shared storage share the nodes' one link with corosync (PLAN
# 7.8): checksums run at the migration limit, 50 MiB/s.
HASH_RATE = 50 * 1024 * 1024
HASH_CODE = """import hashlib, sys, time
h, rate, start, done = hashlib.sha256(), int(sys.argv[2]), time.monotonic(), 0
with open(sys.argv[1], "rb") as f:
    while block := f.read(1 << 20):
        h.update(block)
        done += len(block)
        ahead = done / rate - (time.monotonic() - start)
        if ahead > 0:
            time.sleep(ahead)
print(h.hexdigest())
"""


def sha256_limited(path):
    # In a child with a deadline: a hard NFS mount can block a read forever.
    return run(sys.executable, "-I", "-c", HASH_CODE, str(path), str(HASH_RATE), timeout=3600).strip()


def import_volume(m, volume, digest):
    # Only this tenant's images on the site's import storage, and only the
    # bytes the fetcher's checks accepted (the database's checksum).
    storage, _, rest = str(volume).partition(":import/")
    match = VOLUME.fullmatch(rest)
    if storage != content_storage("import") or not match or int(match[1]) != m["tenant_n"] or rest.endswith(".iso"):
        raise ValueError("invalid image volume")
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest) or rest.rsplit("-", 1)[1][:12] != digest[:12]:
        raise ValueError("invalid image checksum")
    entry = storage_entry(storage)
    if entry is None or "path" not in entry:
        raise ValueError("the image storage is not a directory storage")
    try:
        found = sha256_limited(Path(entry["path"]) / "import" / rest)
    except (CommandFailure, subprocess.TimeoutExpired) as e:
        raise StorageUnavailable(f"{rest} missing or its storage unreachable") from e
    if found != digest:
        raise ValueError("image does not match its checksum")
    # The fetcher's virtual size is not trusted (PLAN 7.8): read it here,
    # before the import, and keep it within the disk the quota counted.
    try:
        info = json.loads(run("qemu-img", "info", "-f", rest.rsplit(".", 1)[1], "--output=json", Path(entry["path"]) / "import" / rest, timeout=60))
    except (CommandFailure, subprocess.TimeoutExpired, ValueError) as e:
        raise ValueError("image is not a readable disk image") from e
    size = info.get("virtual-size")
    if not isinstance(size, int) or size <= 0 or size > integer(m["disk_gb"], 1, 1000) * 1024**3:
        raise ValueError("the image's virtual size exceeds the machine's disk")
    return f"{storage}:import/{rest}"


def set_media(m, cfg, req):
    vmid = machine(m)
    # A managed or Talos VM's ide2 is its cloud-init drive: never touched here.
    if m["kind"] != "vm" or m.get("guest_management", 1) or m.get("service_ports"):
        raise ValueError("only VMs installed from an ISO take media")
    if req.get("iso_volume"):
        run("qm", "set", vmid, "--ide2", f"{iso_volume(m, req['iso_volume'])},media=cdrom")
    else:
        run("qm", "set", vmid, "--ide2", "none,media=cdrom")
    return {"state": "done"}


def console(m, mode, ticket):
    """The VM's console on stdin and stdout (PLAN 7.8): its screen over VNC
    (VMs installed from an ISO) or its serial port (cloud images, whose VGA
    is serial0). The control plane sends nothing more until it reads the
    reply line, so no console bytes sit in this process's input buffer when
    qm or socat takes over."""
    vmid = machine(m)
    if m["kind"] != "vm":
        raise ValueError("only VMs have a console")
    cfg = owned(m)
    if power_status(m) != "running":
        raise ValueError("start the machine first")
    if mode == "vnc":
        if str(cfg.get("vga", "")).startswith("serial") or not isinstance(ticket, str) or not re.fullmatch(r"[A-Za-z0-9]{8}", ticket):
            raise ValueError("this machine has no screen, or the ticket is invalid")
        # qm sets this as the VNC password, valid for 30 seconds.
        os.environ["LC_PVE_TICKET"] = ticket
        command = ["qm", "vncproxy", str(vmid)]
    elif mode == "serial":
        socket_path = Path(f"/var/run/qemu-server/{vmid}.serial0")
        if not socket_path.exists():
            raise ValueError("this machine has no serial console")
        command = ["socat", "-", f"UNIX-CONNECT:{socket_path}"]
    else:
        raise ValueError("invalid console mode")
    sys.stdout.write(json.dumps({"ok": True, "result": {"state": "streaming", "mode": mode}}) + "\n")
    sys.stdout.flush()
    os.execvp(command[0], command)


def create(m):
    vmid = machine(m)
    manifest = STATE / f"create-{vmid}.json"
    marker = provision_marker(m)
    exists = any(Path(f"/etc/pve/{kind}/{vmid}.conf").exists() for kind in ("qemu-server", "lxc"))
    # /etc/pve/qemu-server is this node only; VMIDs are unique across the cluster.
    if not exists and any(path for kind in ("qemu-server", "lxc") for path in PVE_NODES.glob(f"*/{kind}/{vmid}.conf")):
        raise ValueError("VMID exists on another node")
    saved = json.loads(manifest.read_text()) if manifest.exists() else {}
    if exists:
        try:
            owned(m)
        except ValueError:
            cfg = pve_get(f"/nodes/{NODE}/qemu/{vmid}/config")
            if saved.get("marker") != marker or cfg.get("description") != marker:
                raise
        if saved.get("complete") and saved.get("marker") == marker:
            return {"state": "exists", "vmid": vmid, **cloud_init_files(m)}
        if saved.get("marker") != marker:
            # Older, already handed-over guests are never reconfigured by retry.
            return {"state": "exists", "vmid": vmid, **cloud_init_files(m)}
    else:
        saved = {"marker": marker, "complete": False}
        if m["kind"] == "vm" and not m.get("iso_volume") and not m.get("import_volume"):
            saved["template"] = vm_template(m["image"])
        write(manifest, json.dumps(saved), 0o600)
    if m.get("iso_volume"):
        return create_from_iso(m, exists, manifest, saved, marker)
    integer(m["cpu"], 1, 64)
    integer(m["memory_mb"], 512, 131072)
    integer(m["disk_gb"], 10, 1000)
    n = m["tenant_n"]
    tags = f"carrel;tenant-{n}"
    keyfile = STATE / f"{vmid}.pub"
    if not m.get("service_ports"):
        write(keyfile, keys(m["ssh_keys"]), 0o600)
    net = f"bridge=t{n:03d},firewall=1,hwaddr={m['mac']},mtu=1450,rate=12.5"
    if m["kind"] == "vm" and m.get("import_volume") and not exists:
        # A tenant's cloud image (PLAN 7.8): checked against its checksum,
        # then imported as the boot disk; the rest is an ordinary VM.
        volume = import_volume(m, m["import_volume"], m.get("import_sha256"))
        run("qm", "create", vmid, "--name", m["name"], "--description", marker, "--scsihw", "virtio-scsi-single",
            "--scsi0", f"{storage_id()}:0,import-from={volume},iothread=1,discard=on,ssd=1",
            "--ide2", f"{storage_id()}:cloudinit", "--boot", "order=scsi0", "--serial0", "socket", "--agent", "1",
            "--ostype", "l26", timeout=3600)
        exists = True
    if m["kind"] == "vm":
        template = saved.get("template", {"prepared": False})
        if not exists:
            cfg = pve_get(f"/nodes/{NODE}/qemu/{template['vmid']}/config")
            if not cfg.get("template") or not cfg.get("scsi0", "").startswith(storage_id() + ":base-"):
                raise ValueError("expected an immutable template on this node's guest storage")
            run("qm", "clone", template["vmid"], vmid, "--full", "0", "--name", m["name"], "--description", marker, timeout=600)
        run(
            "qm",
            "set",
            vmid,
            "--tags",
            tags,
            "--cores",
            m["cpu"],
            "--memory",
            m["memory_mb"],
            "--balloon",
            "0",
            "--cpu",
            "host" if m.get("nested_virt") else "x86-64-v2-AES",
            "--net0",
            f"virtio={m['mac']},bridge=t{n:03d},firewall=1,mtu=1,rate=12.5",
            "--ipconfig0",
            f"ip={m['ip']}/24,gw=10.200.{n}.1",
            "--nameserver",
            "10.200.0.2",
            "--cicustom",
            cloud_init(m, prepared=template["prepared"], environment=template.get("environment", "development")),
            *([] if m.get("service_ports") else ["--ciuser", "user", "--sshkeys", keyfile]),
            "--onboot",
            "1",
            "--startup",
            "order=20,up=3",
        )
        run("qm", "resize", vmid, "scsi0", f"{m['disk_gb']}G")
        for nic in m["nics"]:
            run("qm", "set", vmid, f"--net{integer(nic['index'], 1, 7)}", nic_value(m, nic))
        first_firewall(m)
        if "running" not in run("qm", "status", vmid):
            run("qm", "start", vmid)
    else:
        if not exists:
            run(
                "pct",
                "create",
                vmid,
                ct_template(m["image"]),
                "--hostname",
                m["name"],
                "--unprivileged",
                "1",
                "--features",
                "nesting=1",
                "--cores",
                m["cpu"],
                "--memory",
                m["memory_mb"],
                "--swap",
                m.get("swap_mb", 0),
                "--rootfs",
                f"{storage_id()}:{m['disk_gb']}",
                "--net0",
                net + f",name=eth0,ip={m['ip']}/24,gw=10.200.{n}.1,type=veth",
                "--nameserver",
                "10.200.0.2",
                "--ssh-public-keys",
                keyfile,
                "--tags",
                tags,
                "--onboot",
                "1",
                "--startup",
                "order=20,up=3",
                timeout=600,
            )
        # Bootstrap hardening before handover, never a general guest execution API.
        for nic in m["nics"]:
            run("pct", "set", vmid, f"--net{integer(nic['index'], 1, 7)}", nic_value(m, nic))
        first_firewall(m)
        if "running" not in run("pct", "status", vmid):
            run("pct", "start", vmid)
        run("pct", "exec", vmid, "--", "mkdir", "-p", "/etc/systemd/system/systemd-journald.service.d")
        fix = STATE / "journald.conf"
        write(fix, "[Service]\nImportCredential=\n")
        run("pct", "push", vmid, fix, "/etc/systemd/system/systemd-journald.service.d/carrel.conf")
        run("pct", "exec", vmid, "--", "systemctl", "daemon-reload")
        run("pct", "exec", vmid, "--", "systemctl", "reset-failed", "systemd-journald")
        run("pct", "exec", vmid, "--", "systemctl", "restart", "systemd-journald")
        if command := mirror_command(m["image"]):
            run("pct", "exec", vmid, "--", "sh", "-c", command)
    write(manifest, json.dumps({**saved, "marker": marker, "complete": True}), 0o600)
    keyfile.unlink(missing_ok=True)
    return {"state": "running", "vmid": vmid, **cloud_init_files(m)}


def power_status(m):
    kind = "qemu" if m["kind"] == "vm" else "lxc"
    status = pve_get(f"/nodes/{NODE}/{kind}/{m['vmid']}/status/current")
    if status.get("qmpstatus") in ("paused", "suspended", "prelaunch"):
        return "paused"
    return status.get("status", "unknown")


def power_action(m, cfg, op):
    # CT suspend uses experimental disk checkpoints, not an in-memory pause.
    if op in ("pause", "resume") and m["kind"] != "vm":
        raise ValueError("pause/resume require a VM; CT checkpoint is unsupported")
    cmd = "qm" if m["kind"] == "vm" else "pct"
    vmid = m["vmid"]
    before = power_status(m)
    if before not in ("running", "stopped", "paused"):
        raise ValueError("cannot confirm current power state")
    if op in ("pause", "resume", "reboot") and before == "stopped":
        raise ValueError("start the stopped machine first")
    desired = "stopped" if op in ("stop", "shutdown") else "paused" if op == "pause" else "running"
    transition = before != desired or op == "reboot"
    if transition:
        if op in ("shutdown", "reboot") and before == "paused":
            # Graceful guest actions need its CPUs running. This intermediate
            # resume is part of the requested shutdown/reboot, not a new intent.
            run(cmd, "resume", vmid, timeout=180)
        actual = "resume" if op == "start" and before == "paused" else "suspend" if op == "pause" else op
        args = [cmd, actual, vmid]
        if op == "pause":
            args += ["--todisk", "0"]
        if op == "shutdown":
            # Never fall back to forced power-off on a graceful shutdown timeout.
            args += ["--timeout", "150", "--forceStop", "0"]
        run(*args, timeout=180)
    after = power_status(m) if transition else before
    # qm reboot finishes before its separate qmstart worker has completed.
    # Observe the bounded transition instead of treating that stopped gap as failure.
    deadline = time.monotonic() + 30
    while transition and after != desired and time.monotonic() < deadline:
        time.sleep(0.5)
        after = power_status(m)
    if after != desired:
        raise ValueError(f"power transition not confirmed: expected {desired}, observed {after}")
    onboot = 1 if desired == "running" else 0
    config_changed = int(cfg.get("onboot", 0)) != onboot
    if config_changed:
        run(cmd, "set", vmid, "--onboot", onboot)
    return {
        "power_state": after,
        "changed": transition or config_changed,
        "boot_changed": op == "reboot" or (op == "start" and before == "stopped"),
    }


def action(req):
    m = req["machine"]
    if req["action"] == "delete" and not any(Path(f"/etc/pve/{kind}/{machine(m)}.conf").exists() for kind in ("qemu-server", "lxc")):
        # Absent here is not absent: a move may have left it on another node.
        if any(PVE_NODES.glob(f"*/*/{machine(m)}.conf")):
            raise ValueError("machine is on another node")
        return {"state": "absent"}
    cfg = owned(m, allow_provisioning=req["action"] == "delete")
    cmd = "qm" if m["kind"] == "vm" else "pct"
    vmid = m["vmid"]
    op = req["action"]
    if op in ["start", "shutdown", "stop", "reboot", "pause", "resume"]:
        if op in ("start", "reboot") and req.get("cloud_init"):
            restore_cloud_init(m, req["cloud_init"])
        return power_action(m, cfg, op)
    elif op == "delete":
        if req.get("confirm") != m["name"]:
            raise ValueError("confirmation mismatch")
        if "running" in run(cmd, "status", vmid):
            run(cmd, "stop", vmid)
        run(cmd, "destroy", vmid, "--purge", "1")
        Path(f"/etc/pve/firewall/{vmid}.fw").unlink(missing_ok=True)
        Path(f"/var/lib/vz/snippets/carrel-{vmid}-user.json").unlink(missing_ok=True)
        Path(f"/var/lib/vz/snippets/carrel-{vmid}-network.json").unlink(missing_ok=True)
        (STATE / f"create-{vmid}.json").unlink(missing_ok=True)
    elif op == "rename":
        # The VM's name, or the CT's hostname, follows the record. Ownership
        # rests on the tags, not the name.
        name = label(req["name"])
        if cmd == "qm":
            run("qm", "set", vmid, "--name", name)
        else:
            run("pct", "set", vmid, "--hostname", name)
    elif op == "resize":
        cpu = integer(req["cpu"], 1, 64)
        mem = integer(req["memory_mb"], 512, 131072)
        disk = integer(req["disk_gb"], m["disk_gb"], 1000)
        if (cpu < int(cfg.get("cores", 1)) or mem < int(cfg["memory"])) and "running" in run(cmd, "status", vmid):
            raise ValueError("CPU/RAM shrink requires a stopped machine")
        volume = "scsi0" if cmd == "qm" else "rootfs"
        size = re.search(r"(?:^|,)size=(\d+(?:\.\d+)?)([KMGT])(?:,|$)", cfg[volume])
        if not size:
            raise ValueError("cannot verify current disk size")
        actual = float(size[1]) * 1024 ** {"K": 1, "M": 2, "G": 3, "T": 4}[size[2]]
        if disk * 1024**3 < actual:
            raise ValueError("disk cannot shrink")
        run(cmd, "set", vmid, "--cores", cpu, "--memory", mem)
        if disk * 1024**3 > actual:
            run(cmd, "resize", vmid, volume, f"{disk}G")
    elif op in ["snapshot", "delsnapshot", "rollback"]:
        name = label(req["name"])
        if op in ("snapshot", "delsnapshot"):
            kind = "qemu" if cmd == "qm" else "lxc"
            snapshots = pve_get(f"/nodes/{NODE}/{kind}/{vmid}/snapshot")
            exists = any(s["name"] == name for s in snapshots)
            if (op == "delsnapshot" and not exists) or (op == "snapshot" and exists):
                return {"state": "exists" if exists else "absent"}
        if op == "rollback" and "running" in run(cmd, "status", vmid):
            run(cmd, "stop", vmid)
        run(cmd, op, vmid, name, timeout=600)
        if op == "rollback":
            return {"state": "running" if "running" in run(cmd, "status", vmid) else "stopped"}
    elif op == "media":
        return set_media(m, cfg, req)
    elif op in ["nic_attach", "nic_detach"]:
        index = integer(req["index"], 1, 7)
        if op == "nic_detach":
            if cmd == "qm" and power_status(m) == "paused":
                raise ValueError("resume or shut down before NIC hot unplug")
            if f"net{index}" in cfg:
                run(cmd, "set", vmid, "--delete", f"net{index}")
        else:
            serial = integer(req["serial"], 1, 99)
            net = f"bridge=p{m['tenant_n']:03d}{serial:02d},firewall=0,rate=100"
            net = "virtio," + net + ",mtu=1" if cmd == "qm" else f"name=eth{index},type=veth,mtu=1450," + net
            run(cmd, "set", vmid, f"--net{index}", nic_value(m, req["nic"]) if req.get("nic") else net)
    else:
        raise ValueError("unsupported machine operation")
    return {"state": "done"}


# Freezing a machine (issue #190): vzdump to the PVE storage of the Proxmox
# Backup Server, then the control plane deletes the machine. The backup is
# protected, so a prune job on the datastore cannot take it. The cluster may
# run its own scheduled backups of the same machine into the same storage:
# the ones this agent made are told apart by their notes alone, and it never
# reads, reuses or removes any other.
BACKUP_VOLUME = re.compile(r"[a-z][a-z0-9_.-]*:backup/[A-Za-z0-9_./:+-]+")
FREEZE_NOTE = "carrel-freeze "
# vzdump and the wait for a verification must end inside the control plane's
# 4 hour bound on one request.
VZDUMP_SECONDS = 3 * 3600
VERIFY_POLL_SECONDS = 20


def backup_storage(storage):
    entry = storage_entry(storage) if isinstance(storage, str) and re.fullmatch(r"[a-z][a-z0-9_.-]{0,62}", storage) else None
    if entry is None or entry["type"] != "pbs":
        raise ValueError("backup storage must be a Proxmox Backup Server storage")
    return storage


def backups(storage, vmid):
    # As root: the reader token has no view of the backup storage.
    out = run("pvesh", "get", f"/nodes/{NODE}/storage/{storage}/content", "--content", "backup", "--vmid", vmid, "--output-format", "json")
    return json.loads(out) if out else []


def freeze_note(freeze_id):
    if not isinstance(freeze_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", freeze_id):
        raise ValueError("invalid freeze id")
    return FREEZE_NOTE + freeze_id


def carrel_backups(storage, vmid):
    return [b for b in backups(storage, vmid) if str(b.get("notes", "")).strip().startswith(FREEZE_NOTE)]


def backup_free(storage, backup):
    if backup.get("protected"):
        run("pvesh", "set", f"/nodes/{NODE}/storage/{storage}/content/{backup['volid']}", "--protected", 0)
    run("pvesm", "free", backup["volid"], timeout=600)


def freeze_stamp(m):
    return STATE / f"freeze-{machine(m)}.json"


def config_digest(m):
    kind = "qemu" if m["kind"] == "vm" else "lxc"
    return pve_get(f"/nodes/{NODE}/{kind}/{machine(m)}/config").get("digest")


def last_start(m):
    """The newest start of the machine that PVE recorded, whoever asked for it."""
    task = "qmstart" if m["kind"] == "vm" else "vzstart"
    out = run("pvesh", "get", f"/nodes/{NODE}/tasks", "--vmid", machine(m), "--typefilter", task, "--limit", 5, "--output-format", "json")
    return max((int(t.get("starttime", 0)) for t in (json.loads(out) if out else [])), default=0)


def freeze_stamp_valid(m, note):
    """True when the machine is provably as it was when this backup was made.

    The agent's own requests remove the stamp (main). A start by anything else
    (the node's boot, HA, an admin in the PVE interface) is a task PVE logs,
    which changes last_start; the configuration digest covers the rest.
    """
    path = freeze_stamp(m)
    try:
        stamp = json.loads(path.read_text())
    except (OSError, ValueError):
        return False
    return (
        stamp.get("note") == note
        and stamp.get("digest") is not None
        and stamp.get("digest") == config_digest(m)
        and stamp.get("started") == last_start(m)
    )


def freeze(req):
    m = req["machine"]
    vmid = machine(m)
    storage = backup_storage(req["storage"])
    note = freeze_note(req["freeze_id"])
    wait = integer(req.get("verify_wait", 1800), 0, 3600)
    owned(m)
    if power_status(m) != "stopped":
        raise ValueError("a machine freezes only when stopped")
    kind = "qemu" if m["kind"] == "vm" else "lxc"
    if any(s["name"] != "current" for s in pve_get(f"/nodes/{NODE}/{kind}/{vmid}/snapshot")):
        raise ValueError("a machine with snapshots does not freeze")

    def mine():
        return [b for b in backups(storage, vmid) if str(b.get("notes", "")).strip() == note]

    found = mine()
    if found and not freeze_stamp_valid(m, note):
        # A backup of an earlier attempt: the machine may have run since, so
        # what it holds is not what a freeze must keep.
        for b in found:
            backup_free(storage, b)
        found = []
    if not found:
        freeze_stamp(m).unlink(missing_ok=True)
        # A machine that boots with the node would run again before the retry.
        if str(pve_get(f"/nodes/{NODE}/{kind}/{vmid}/config").get("onboot", 0)) not in ("0", ""):
            run("qm" if kind == "qemu" else "pct", "set", vmid, "--onboot", 0)
        # Taken before the backup: a start after this point differs from it.
        proof = {"note": note, "digest": config_digest(m), "started": last_start(m)}
        try:
            run("vzdump", vmid, "--storage", storage, "--mode", "stop", "--protected", 1, "--notes-template", note, timeout=VZDUMP_SECONDS)
        except CommandFailure as e:
            # Another backup job of the cluster holds the guest.
            if "lock" in str(e):
                raise CommandFailure("the machine is being backed up by another job; freeze it again later") from e
            raise
        write(freeze_stamp(m), json.dumps(proof), 0o600)
        found = mine()
    if len(found) != 1:
        raise CommandFailure("the backup is not on the storage")
    deadline = time.monotonic() + wait
    while True:
        backup = (mine() or [None])[0]
        if backup is None:
            raise CommandFailure("the backup is not on the storage")
        verification = (backup.get("verification") or {}).get("state")
        if verification in ("ok", "failed") or time.monotonic() >= deadline:
            break
        time.sleep(VERIFY_POLL_SECONDS)
    if verification == "failed":
        backup_free(storage, backup)
        freeze_stamp(m).unlink(missing_ok=True)
        raise CommandFailure("the backup failed its verification and was removed")
    # The wait above can take minutes: the machine must be what the backup holds.
    if power_status(m) != "stopped" or not freeze_stamp_valid(m, note):
        backup_free(storage, backup)
        freeze_stamp(m).unlink(missing_ok=True)
        raise CommandFailure("the machine changed while it was backed up; the backup was removed")
    if verification != "ok":
        # Kept for the next attempt, which reuses it while the machine is unchanged.
        raise CommandFailure("the backup was not verified in time; the Proxmox Backup Server must verify new snapshots")
    if not backup.get("protected") or int(backup.get("size", 0)) <= 0 or not BACKUP_VOLUME.fullmatch(str(backup.get("volid"))):
        raise CommandFailure("the backup could not be verified")
    # Earlier attempts' leftovers: the machine is live, so no other freeze backup of it is wanted.
    for other in carrel_backups(storage, vmid):
        if other["volid"] != backup["volid"]:
            backup_free(storage, other)
    return {"volid": backup["volid"], "size": int(backup["size"]), "verification": "ok", "note": note}


def discard_restore(m, where):
    """Remove what a restore left on this node: a finished machine or a cut-off half."""
    vmid = machine(m)
    kind = "qemu" if m["kind"] == "vm" else "lxc"
    cmd = "qm" if m["kind"] == "vm" else "pct"
    cfg = pve_get(f"/nodes/{where}/{kind}/{vmid}/config")
    if where != NODE:
        raise ValueError("machine is on another node")
    if cfg.get("lock") == "create":
        run(cmd, "unlock", vmid)
    else:
        owned(m, node=where)
        if cfg.get("name", cfg.get("hostname")) != m["name"]:
            raise ValueError("VMID is in use")
        if "running" in run(cmd, "status", vmid):
            run(cmd, "stop", vmid)
    run(cmd, "destroy", vmid, "--purge", "1")


def thaw(req):
    m = req["machine"]
    vmid = machine(m)
    volid = req["volid"]
    if not isinstance(volid, str) or not BACKUP_VOLUME.fullmatch(volid):
        raise ValueError("invalid backup volume")
    backup_storage(volid.split(":")[0])
    guest = storage_id()
    where = located(m)
    if req.get("discard"):
        # Deleting a machine whose thaw was cut off: drop what it restored.
        if where is None:
            return {"state": "absent"}
        discard_restore(m, where)
        return {"state": "discarded"}
    if where is not None:
        kind = "qemu" if m["kind"] == "vm" else "lxc"
        if where == NODE and pve_get(f"/nodes/{where}/{kind}/{vmid}/config").get("lock") == "create":
            # A restore that was cut off: PVE leaves its half behind, locked.
            discard_restore(m, where)
        else:
            # A retry after the restore finished; anything else holds the VMID.
            cfg = owned(m, node=where)
            if where != NODE or cfg.get("lock") or cfg.get("name", cfg.get("hostname")) != m["name"]:
                raise ValueError("VMID is in use")
            return {"state": "restored"}
    if any(PVE_NODES.glob(f"*/*/{vmid}.conf")):
        raise ValueError("VMID is in use")
    if m["kind"] == "vm":
        run("qmrestore", volid, vmid, "--storage", guest, timeout=VZDUMP_SECONDS)
    else:
        run("pct", "restore", vmid, volid, "--storage", guest, timeout=VZDUMP_SECONDS)
    owned(m)
    return {"state": "restored"}


def backup_remove(req):
    m = req["machine"]
    vmid = machine(m)
    volid = req["volid"]
    if not isinstance(volid, str) or not BACKUP_VOLUME.fullmatch(volid):
        raise ValueError("invalid backup volume")
    storage = backup_storage(volid.split(":")[0])
    found = [b for b in backups(storage, vmid) if b.get("volid") == volid]
    if not found:
        return {"state": "absent"}
    notes = str(found[0].get("notes", "")).strip()
    # Never a scheduled or manual backup of the cluster, and never the backup
    # of another freeze.
    if not notes.startswith(FREEZE_NOTE) or (req.get("note") and notes != req["note"]):
        raise ValueError("not the backup of a frozen machine")
    backup_free(storage, found[0])
    return {"state": "removed"}


def main():
    STATE.mkdir(parents=True, exist_ok=True)
    # A start may carry a VM's cloud-init files: user-data with large runcmd
    # arguments reaches about 1 MB, twice that once JSON-escaped again.
    # One request per line: a console streams the rest of stdin after it.
    data = sys.stdin.buffer.readline(8_000_001)
    if len(data) > 8_000_000:
        raise ValueError("request too large")
    req = json.loads(data)
    op = req["op"]
    if op == "console":
        console(req["machine"], req.get("mode"), req.get("ticket"))
    # A migration copies disks for minutes: it takes a lock of its machine
    # only, so reconciles and other machines on this node go on.
    long = op in ("migrate", "migrate_finish", "freeze", "thaw", "backup_remove")
    lock_path = STATE / (f"vm-{machine(req['machine'])}.lock" if long else "node.lock")
    with lock_path.open("w") as lock:
        if op not in ("inventory", "status", "metrics", "node_files", "cloud_init_read", "disk_volume", "fetch_status", "fetch_store"):
            fcntl.flock(lock, fcntl.LOCK_EX)
        journal = None
        # Anything that may change or start a machine ends the proof that a
        # freeze backup still matches it (freeze_stamp_valid).
        if isinstance(req.get("machine"), dict) and op not in ("inventory", "status", "metrics", "node_files", "cloud_init_read", "disk_volume", "freeze", "thaw", "backup_remove"):
            freeze_stamp(req["machine"]).unlink(missing_ok=True)
        if req.get("request_id") and op in ("create", "action"):
            if not re.fullmatch(r"[a-f0-9]{64}", req["request_id"]):
                raise ValueError("invalid request ID")
            journal = STATE / "requests" / (req["request_id"] + ".json")
            if journal.exists():
                print(journal.read_text())
                return
        if op == "reconcile":
            out = reconcile(req["state"], first=req.get("first", True))
        elif op == "create":
            out = create(req["machine"])
            try:
                out = {**out, **disk_volume(req["machine"], allow_provisioning=True)}
            except Exception:
                # Only NetBox's disk name depends on it (issue #175): a
                # machine that was created must not fail here.
                pass
        elif op == "action":
            out = action(req)
        elif op == "inventory":
            # Guest maxdisk omits secondary disks. Count all volumes, including
            # templates and unused disks, for conservative admission.
            storage = storage_id()
            observed = inventory_read(storage)
            volumes = observed.pop("volumes")
            out = {
                "node": NODE,
                "tenant_route": tenant_route(),
                "storage_id": storage,
                **observed,
                "disk_committed_bytes": sum(v["size"] for v in volumes if v.get("content") in ("images", "rootdir")),
            }
        elif op == "storage_usage":
            for m in req["machines"]:
                machine(m)
            out = zfs_usage(req["machines"], storage_definition(storage_id())["pool"])
        elif op == "status":
            m = req["machine"]
            owned(m)
            kind = "qemu" if m["kind"] == "vm" else "lxc"
            out = pve_get(f"/nodes/{NODE}/{kind}/{m['vmid']}/status/current")
        elif op == "migrate_prepare":
            out = migrate_prepare(req)
        elif op == "migrate":
            out = migrate(req)
        elif op == "migrate_finish":
            out = migrate_finish(req)
        elif op == "cloud_init_remove":
            out = cloud_init_remove(req)
        elif op in ("freeze", "thaw", "backup_remove"):
            out = {"freeze": freeze, "thaw": thaw, "backup_remove": backup_remove}[op](req)
        elif op in ("fetch_start", "fetch_status", "fetch_store", "fetch_clean", "image_delete"):
            if not first_exit_node():
                raise ValueError("fetches run on the first exit node")
            out = {"fetch_start": fetch_start, "fetch_status": fetch_status, "fetch_store": fetch_store,
                   "fetch_clean": fetch_clean, "image_delete": image_delete}[op](req)
        elif op == "cloud_init_read":
            m = req["machine"]
            owned(m)
            out = cloud_init_files(m)
        elif op == "disk_volume":
            out = disk_volume(req["machine"])
        elif op == "node_files":
            # For the control plane's backup: only files without secrets
            # (the reader token is rebuilt by configure-reader.py).
            files = {}
            for name in ("node.json", "templates.json", "site.json"):
                path = Path("/etc/carrel") / name
                if path.exists():
                    files[name] = path.read_text()
            out = {"node": NODE, "files": files}
        elif op == "metrics":
            m = req["machine"]
            owned(m)
            kind = "qemu" if m["kind"] == "vm" else "lxc"
            out = pve_get(f"/nodes/{NODE}/{kind}/{m['vmid']}/rrddata", timeframe="hour")
        else:
            raise ValueError("unknown operation")
        response = json.dumps({"ok": True, "result": out})
        if journal:
            # The journal outlives the machine: no copy of its user-data.
            kept = {k: v for k, v in out.items() if k != "cloud_init"} if isinstance(out, dict) else out
            write(journal, json.dumps({"ok": True, "result": kept}), 0o600)
        print(response)


if __name__ == "__main__":
    # Only the systemd unit passes an argument; the SSH forced command cannot.
    if sys.argv[1:] == ["vip-probe"]:
        vip_probe()
    if sys.argv[1:] == ["public-ips"]:
        # At boot, after carrel-ports: the addresses the last reconcile held.
        public_addresses(json.loads(PUBLIC_IPS.read_text()) if PUBLIC_IPS.exists() else {})
        sys.exit(0)
    try:
        main()
    except Exception as e:
        code = "adapter_internal"
        if isinstance(e, ValueError):
            code = "invalid_request"
        elif isinstance(e, StorageUnavailable):
            code = "storage_unavailable"
        elif isinstance(e, subprocess.TimeoutExpired):
            code = "command_timeout"
        elif isinstance(e, (subprocess.CalledProcessError, CommandFailure)):
            code = "command_failed"
        print(json.dumps({"ok": False, "error_code": code, "error": "Node action failed"}))
        sys.exit(1)
