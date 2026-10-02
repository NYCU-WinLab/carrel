#!/usr/bin/env python3
"""Root node adapter, exposed only as an SSH forced command.

One bounded JSON request on stdin; no shell, arbitrary paths, guest exec or PVE
passthrough operations. Only tagged carrel tenant VMIDs may be changed. The
control plane owns authorization and quotas; this boundary owns host integrity.
"""

from concurrent.futures import ThreadPoolExecutor
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

STATE = Path("/var/lib/carrel")
NODE = socket.gethostname().split(".")[0]
CONFIG = Path("/etc/carrel/node.json")


def guest_firewall(m, state, config):
    machine(m)
    if m.get("network_access") == "restricted" and m.get("nics"):
        raise ValueError("restricted machines cannot have experiment NICs")
    n = m["tenant_n"]
    rules = [
        "[OPTIONS]",
        "enable: 1",
        "ipfilter: 1",
        "macfilter: 1",
        "dhcp: 1",
        "ndp: 0",
        "radv: 0",
        "policy_in: DROP",
        "policy_out: ACCEPT",
        "",
        "[IPSET ipfilter-net0]",
        m["ip"],
        "0.0.0.0",
        "",
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
        if grant["vmid"] == m["vmid"]:
            port = integer(grant["port"], 1, 65535)
            proto = grant["proto"]
            if proto not in ("tcp", "udp"):
                raise ValueError("invalid protocol")
            rules.append(f"IN ACCEPT -source 10.254.200.1 -p {proto} -dport {port}")
    for domain in state.get("domains", []):
        if domain["vmid"] == m["vmid"]:
            port = integer(domain["target_port"], 1, 65535)
            rules.append(f"IN ACCEPT -source 10.200.0.2 -p tcp -dport {port}")
    # Reachability probes only, from the authenticated control plane.
    rules.append("IN ACCEPT -source 10.200.0.3 -p tcp -dport 22")
    return "\n".join(rules) + "\n"


def run(*args, timeout=180):
    p = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError(f"{args[0]} {args[1]} failed: {p.stderr[-1200:]}")
    return p.stdout.strip()


def api(method, path, **kwargs):
    args = ["pvesh", method, path, "--output-format", "json"]
    for key, value in kwargs.items():
        args += ["--" + key.replace("_", "-"), str(value)]
    text = run(*args, timeout=600)
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


def provision_marker(m):
    return "carrel-provision-" + hashlib.sha256(str(m.get("readiness_token", m["name"])).encode()).hexdigest()


def owned(m, allow_provisioning=False):
    vmid = machine(m)
    kind = "qemu" if m["kind"] == "vm" else "lxc"
    cfg = api("get", f"/nodes/{NODE}/{kind}/{vmid}/config")
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


def ensure(path, key, value, *, existing=None, **params):
    if existing is None:
        existing = api("get", path)
    if any(x[key] == value for x in existing):
        return False
    api("create", path, **{key: value}, **params)
    existing.append({key: value, **params})
    return True



def private_dhcp(state):
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
    wanted = {net["id"] for net in state["networks"] if net.get("mode") == "managed"}
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
        if net.get("mode") != "managed":
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


def reconcile(state):
    config = json.loads(CONFIG.read_text())
    changed = []
    # Read topology once per reconciliation. Subnet reads are independent; all
    # mutations remain serialized by the node adapter's infrastructure lock.
    vnets = api("get", "/cluster/sdn/vnets")
    existing_tenants = [tenant_config(t)[1] for t in state["tenants"]
                        if any(v["vnet"] == tenant_config(t)[1] for v in vnets)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        subnets_by_vnet = dict(zip(existing_tenants, pool.map(
            lambda vnet: api("get", f"/cluster/sdn/vnets/{vnet}/subnets"), existing_tenants)))
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
    missing_links = any(not Path("/sys/class/net/" + f"t{t['n']:03d}").exists() for t in state["tenants"])
    if changed or missing_links:
        task = api("set", "/cluster/sdn")
        if isinstance(task, str) and task.startswith("UPID:"):
            for _ in range(60):
                status = api("get", f"/nodes/{NODE}/tasks/{task}/status")
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
    if state["tenants"]:
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
  iifname {{ "xvrfp_tenants", "vrf_tenants" }} ct zone set 1
 }}
}}
"""
    write("/etc/carrel/conntrack.nft", tracking)
    run("nft", "-c", "-f", "/etc/carrel/conntrack.nft")
    run("nft", "-f", "/etc/carrel/conntrack.nft")
    run("systemctl", "start", "carrel-conntrack")
    # Per-guest filtering protects routed and same-node bridged paths. Private
    # experiment NICs deliberately have firewall=0; primary NIC is mandatory.
    for m in state["machines"]:
        write(f"/etc/pve/firewall/{m['vmid']}.fw", guest_firewall(m, state, config))
    dhcp = [
        "port=0",
        "bind-dynamic",
        "log-dhcp",
        "dhcp-authoritative",
        "dhcp-leasefile=/var/lib/carrel/dhcp.leases",
    ]
    for t in state["tenants"]:
        n, vnet = tenant_config(t)
        dhcp += [
            f"interface={vnet}",
            f"dhcp-range=set:{vnet},10.200.{n}.0,static,255.255.255.0,12h",
            f"dhcp-option=tag:{vnet},option:router,10.200.{n}.1",
            f"dhcp-option=tag:{vnet},option:dns-server,10.200.0.2",
            f"dhcp-option=tag:{vnet},option:mtu,1450",
        ]
    for m in state["machines"]:
        dhcp.append(f"dhcp-host={m['mac']},{m['ip']},{m['name']},12h")
    if write("/etc/carrel/dhcp.conf", "\n".join(dhcp) + "\n"):
        run("dnsmasq", "--test", "--conf-file=/etc/carrel/dhcp.conf")
        run("systemctl", "restart", "carrel-dhcp")
    if NODE == "carrel01":
        slugs = {t["n"]: label(t["slug"]) for t in state["tenants"]}
        hosts = "".join(f"{m['ip']} {m['name']}.{slugs[m['tenant_n']]}.internal\n" for m in state["machines"])
        write(STATE / "dns.hosts", hosts)
        if run("pct", "exec", "101", "--", "cat", "/etc/carrel-hosts") != hosts.strip():
            run("pct", "push", "101", STATE / "dns.hosts", "/etc/carrel-hosts")
            run("pct", "exec", "101", "--", "systemctl", "restart", "carrel-dns")
        routes = ["{", " auto_https off", "}", ":80 {"]
        for domain in state.get("domains", []):
            if domain.get("state") != "ready":
                continue
            m = next(m for m in state["machines"] if m["vmid"] == domain["vmid"])
            expected = label(domain["sub"]) + "." + slugs[m["tenant_n"]] + ".winlab.tw"
            if domain["name"] != expected:
                raise ValueError("invalid tenant domain")
            port = integer(domain["target_port"], 1, 65535)
            routes += [
                f" @d{domain['id']} host {expected}",
                f" handle @d{domain['id']} {{",
                f"  reverse_proxy {m['ip']}:{port}",
                " }",
            ]
        routes += [" handle {", "  respond 404", " }", "}"]
        caddy = "\n".join(routes) + "\n"
        if run("pct", "exec", "101", "--", "cat", "/etc/caddy/Caddyfile") != caddy.strip():
            write(STATE / "gateway.Caddyfile", caddy)
            run("pct", "push", "101", STATE / "gateway.Caddyfile", "/etc/caddy/Caddyfile", "--perms", "644")
            run(
                "pct",
                "exec",
                "101",
                "--",
                "/usr/local/bin/caddy",
                "validate",
                "--config",
                "/etc/caddy/Caddyfile",
            )
            run("pct", "exec", "101", "--", "systemctl", "reload", "caddy")
    private_dhcp(state)
    write(STATE / "desired.json", json.dumps(state, sort_keys=True))
    return {"changed": changed}


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


def cloud_init(m, *, prepared=False):
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
                **({"groups": ["docker"]} if prepared else {}),
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
    if m.get("swap_mb", 4096):
        data["swap"] = {
            "filename": "/swapfile",
            "size": str(integer(m.get("swap_mb", 4096), 0, 65536)) + "M",
            "maxsize": str(m.get("swap_mb", 4096)) + "M",
        }
    name = f"carrel-{m['vmid']}-user.json"
    write("/var/lib/vz/snippets/" + name, "#cloud-config\n" + json.dumps(data), 0o600)
    network_name = f"carrel-{m['vmid']}-network.json"
    network = {"version": 2, "ethernets": {"primary": {
        "match": {"macaddress": m["mac"]}, "addresses": [m["ip"] + "/24"],
        "routes": [{"to": "0.0.0.0/0", "via": f"10.200.{m['tenant_n']}.1"}],
        "nameservers": {"addresses": ["10.200.0.2"]}, "mtu": 1450,
    }}}
    write("/var/lib/vz/snippets/" + network_name, json.dumps(network), 0o600)
    return "user=local:snippets/" + name + ",network=local:snippets/" + network_name


def vm_template(image):
    defaults = {"debian-13": 9000, "ubuntu-24.04": 9001}
    if image not in defaults:
        raise ValueError("image not installed")
    path = Path("/etc/carrel/templates.json")
    configured = json.loads(path.read_text()) if path.exists() else {}
    value = configured.get(image, {"vmid": defaults[image], "prepared": False})
    return {"vmid": integer(value["vmid"], 9000, 9999), "prepared": value.get("prepared") is True}


def create(m):
    vmid = machine(m)
    manifest = STATE / f"create-{vmid}.json"
    marker = provision_marker(m)
    exists = any(Path(f"/etc/pve/{kind}/{vmid}.conf").exists() for kind in ("qemu-server", "lxc"))
    saved = json.loads(manifest.read_text()) if manifest.exists() else {}
    if exists:
        try:
            owned(m)
        except ValueError:
            cfg = api("get", f"/nodes/{NODE}/qemu/{vmid}/config")
            if saved.get("marker") != marker or cfg.get("description") != marker:
                raise
        if saved.get("complete") and saved.get("marker") == marker:
            return {"state": "exists", "vmid": vmid}
        if saved.get("marker") != marker:
            # Older, already handed-over guests are never reconfigured by retry.
            return {"state": "exists", "vmid": vmid}
    else:
        saved = {"marker": marker, "complete": False}
        if m["kind"] == "vm":
            saved["template"] = vm_template(m["image"])
        write(manifest, json.dumps(saved), 0o600)
    integer(m["cpu"], 1, 64)
    integer(m["memory_mb"], 512, 131072)
    integer(m["disk_gb"], 10, 1000)
    n = m["tenant_n"]
    tags = f"carrel;tenant-{n}"
    keyfile = STATE / f"{vmid}.pub"
    write(keyfile, keys(m["ssh_keys"]), 0o600)
    net = f"bridge=t{n:03d},firewall=1,hwaddr={m['mac']},mtu=1450,rate=12.5"
    if m["kind"] == "vm":
        template = saved.get("template", {"prepared": False})
        if not exists:
            cfg = api("get", f"/nodes/{NODE}/qemu/{template['vmid']}/config")
            if not cfg.get("template") or not cfg.get("scsi0", "").startswith("local-lvm:base-"):
                raise ValueError("expected an immutable LVM-thin template")
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
            cloud_init(m, prepared=template["prepared"]),
            "--ciuser",
            "user",
            "--sshkeys",
            keyfile,
            "--onboot",
            "1",
            "--startup",
            "order=20,up=3",
        )
        run("qm", "resize", vmid, "scsi0", f"{m['disk_gb']}G")
        for nic in m["nics"]:
            run("qm", "set", vmid, f"--net{integer(nic['index'], 1, 7)}", nic_value(m, nic))
        if "running" not in run("qm", "status", vmid):
            run("qm", "start", vmid)
    else:
        images = {
            "debian-13": "debian-13-standard_13.1-2_amd64.tar.zst",
            "ubuntu-24.04": "ubuntu-24.04-standard_24.04-2_amd64.tar.zst",
        }
        template = images[m["image"]]
        if not exists:
            run(
                "pct",
                "create",
                vmid,
                "local:vztmpl/" + template,
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
                f"local-lvm:{m['disk_gb']}",
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
        if "running" not in run("pct", "status", vmid):
            run("pct", "start", vmid)
        run("pct", "exec", vmid, "--", "mkdir", "-p", "/etc/systemd/system/systemd-journald.service.d")
        fix = STATE / "journald.conf"
        write(fix, "[Service]\nImportCredential=\n")
        run("pct", "push", vmid, fix, "/etc/systemd/system/systemd-journald.service.d/carrel.conf")
        run("pct", "exec", vmid, "--", "systemctl", "daemon-reload")
        run("pct", "exec", vmid, "--", "systemctl", "reset-failed", "systemd-journald")
        run("pct", "exec", vmid, "--", "systemctl", "restart", "systemd-journald")
    write(manifest, json.dumps({**saved, "marker": marker, "complete": True}), 0o600)
    keyfile.unlink(missing_ok=True)
    return {"state": "running", "vmid": vmid}


def action(req):
    m = req["machine"]
    if req["action"] == "delete" and not any(Path(f"/etc/pve/{kind}/{machine(m)}.conf").exists() for kind in ("qemu-server", "lxc")):
        return {"state": "absent"}
    cfg = owned(m, allow_provisioning=req["action"] == "delete")
    cmd = "qm" if m["kind"] == "vm" else "pct"
    vmid = m["vmid"]
    op = req["action"]
    if op in ["start", "shutdown", "stop", "reboot"]:
        run(cmd, "set", vmid, "--onboot", "0" if op in ("stop", "shutdown") else "1")
        running = "running" in run(cmd, "status", vmid)
        if (op in ("stop", "shutdown") and running) or (op == "start" and not running) or op == "reboot":
            run(cmd, op, vmid, timeout=180)
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
            snapshots = api("get", f"/nodes/{NODE}/{kind}/{vmid}/snapshot")
            exists = any(s["name"] == name for s in snapshots)
            if (op == "delsnapshot" and not exists) or (op == "snapshot" and exists):
                return {"state": "exists" if exists else "absent"}
        if op == "rollback" and "running" in run(cmd, "status", vmid):
            run(cmd, "stop", vmid)
        run(cmd, op, vmid, name, timeout=600)
        if op == "rollback":
            return {"state": "running" if "running" in run(cmd, "status", vmid) else "stopped"}
    elif op in ["nic_attach", "nic_detach"]:
        index = integer(req["index"], 1, 7)
        if op == "nic_detach":
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


def main():
    STATE.mkdir(parents=True, exist_ok=True)
    data = sys.stdin.buffer.read(2_000_001)
    if len(data) > 2_000_000:
        raise ValueError("request too large")
    req = json.loads(data)
    op = req["op"]
    with (STATE / "node.lock").open("w") as lock:
        if op not in ("inventory", "status", "metrics"):
            fcntl.flock(lock, fcntl.LOCK_EX)
        journal = None
        if req.get("request_id") and op in ("create", "action"):
            if not re.fullmatch(r"[a-f0-9]{64}", req["request_id"]):
                raise ValueError("invalid request ID")
            journal = STATE / "requests" / (req["request_id"] + ".json")
            if journal.exists():
                print(journal.read_text())
                return
        if op == "reconcile":
            out = reconcile(req["state"])
        elif op == "create":
            out = create(req["machine"])
        elif op == "action":
            out = action(req)
        elif op == "inventory":
            # Guest maxdisk omits secondary disks. Count all thin volumes,
            # including templates and unused disks, for conservative admission.
            volumes = api("get", f"/nodes/{NODE}/storage/local-lvm/content")
            pools = json.loads(run("lvs", "--reportformat", "json", "--units", "b", "--nosuffix", "-o", "lv_name,data_percent,metadata_percent", "pve/data"))["report"][0]["lv"]
            pool = pools[0]
            out = {
                "thin_pool": {"data_fraction": float(pool["data_percent"] or 0) / 100,
                              "metadata_fraction": float(pool["metadata_percent"] or 0) / 100},
                "node": NODE,
                "resources": api("get", "/cluster/resources"),
                "storage": api("get", f"/nodes/{NODE}/storage/local-lvm/status"),
                "status": api("get", f"/nodes/{NODE}/status"),
                "disk_committed_bytes": sum(v["size"] for v in volumes if v.get("content") in ("images", "rootdir")),
            }
        elif op == "storage_usage":
            for m in req["machines"]:
                machine(m)
            spec = importlib.util.spec_from_file_location("thin_usage", "/usr/local/lib/carrel/thin-usage.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            out = module.collect(req["machines"])
        elif op == "status":
            m = req["machine"]
            owned(m)
            kind = "qemu" if m["kind"] == "vm" else "lxc"
            out = api("get", f"/nodes/{NODE}/{kind}/{m['vmid']}/status/current")
        elif op == "metrics":
            m = req["machine"]
            owned(m)
            kind = "qemu" if m["kind"] == "vm" else "lxc"
            out = api("get", f"/nodes/{NODE}/{kind}/{m['vmid']}/rrddata", timeframe="hour")
        else:
            raise ValueError("unknown operation")
        response = json.dumps({"ok": True, "result": out})
        if journal:
            write(journal, response, 0o600)
        print(response)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        sys.exit(1)
