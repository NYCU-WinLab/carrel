#!/usr/bin/env python3
"""Root node adapter, exposed only as an SSH forced command.

One bounded JSON request on stdin; no shell, arbitrary paths, guest exec or PVE
passthrough operations. Only tagged carrel tenant VMIDs may be changed. The
control plane owns authorization and quotas; this boundary owns host integrity.
"""

import fcntl
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


def owned(m):
    vmid = machine(m)
    kind = "qemu" if m["kind"] == "vm" else "lxc"
    cfg = api("get", f"/nodes/{NODE}/{kind}/{vmid}/config")
    tags = cfg.get("tags", "").split(";")
    if "carrel" not in tags or f"tenant-{m['tenant_n']}" not in tags:
        raise ValueError("refusing unowned VMID")
    return cfg


def tenant_config(t):
    n = integer(t["n"], 1, 254)
    label(t["slug"])
    return n, f"t{n:03d}"


def ensure(path, key, value, **params):
    existing = api("get", path)
    if any(x[key] == value for x in existing):
        return False
    api("create", path, **{key: value}, **params)
    return True


def reconcile(state):
    config = json.loads(CONFIG.read_text())
    changed = []
    for t in state["tenants"]:
        n, vnet = tenant_config(t)
        if ensure(
            "/cluster/sdn/vnets", "vnet", vnet, zone="tenants", tag=100000 + n, alias="carrel-" + t["slug"]
        ):
            changed.append(vnet)
        subnets = api("get", f"/cluster/sdn/vnets/{vnet}/subnets")
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
            zone="private",
            tag=200000 + n * 100 + k,
            vlanaware=1,
            alias="carrel-" + label(net["name"]),
        ):
            changed.append(name)
    # Delete only owned private networks absent from the desired database.
    wanted = {f"p{x['tenant_n']:03d}{x['serial']:02d}" for x in state["networks"]}
    for v in api("get", "/cluster/sdn/vnets"):
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
        machine(m)
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
        ]
        for peer in state["peers"]:
            # Peering is a grant by the destination owner, scoped to one port.
            src = str(ipaddress.IPv4Network(peer["source"], strict=False))
            dst = str(ipaddress.IPv4Address(peer["target"]))
            port = integer(peer["port"], 1, 65535)
            if ipaddress.ip_address(m["ip"]) in ipaddress.ip_network(src):
                rules.append(f"OUT ACCEPT -dest {dst} -p tcp -dport {port}")
            if dst == m["ip"]:
                rules.append(f"IN ACCEPT -source {src} -p tcp -dport {port}")
        rules += [
            f"OUT DROP -dest 10.200.{n}.1",
            f"OUT ACCEPT -dest 10.200.{n}.0/24",
            f"IN ACCEPT -source 10.200.{n}.0/24",
        ]
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
        write(f"/etc/pve/firewall/{m['vmid']}.fw", "\n".join(rules) + "\n")
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


def cloud_init(m):
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
            }
        ],
        "disable_root": True,
        "ssh_pwauth": False,
        "timezone": "Asia/Taipei",
        "package_update": True,
        "packages": ["qemu-guest-agent", "unattended-upgrades", *m.get("packages", [])],
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
    if m.get("swap_mb", 4096):
        data["swap"] = {
            "filename": "/swapfile",
            "size": str(integer(m.get("swap_mb", 4096), 0, 65536)) + "M",
            "maxsize": str(m.get("swap_mb", 4096)) + "M",
        }
    name = f"carrel-{m['vmid']}-user.json"
    write("/var/lib/vz/snippets/" + name, "#cloud-config\n" + json.dumps(data), 0o600)
    return "user=local:snippets/" + name


def create(m):
    vmid = machine(m)
    for kind in ["qemu-server", "lxc"]:
        if Path(f"/etc/pve/{kind}/{vmid}.conf").exists():
            owned(m)
            return {"state": "exists", "vmid": vmid}
    integer(m["cpu"], 1, 64)
    integer(m["memory_mb"], 512, 131072)
    integer(m["disk_gb"], 10, 1000)
    n = m["tenant_n"]
    tags = f"carrel;tenant-{n}"
    keyfile = STATE / f"{vmid}.pub"
    write(keyfile, keys(m["ssh_keys"]), 0o600)
    net = f"bridge=t{n:03d},firewall=1,hwaddr={m['mac']},mtu=1450,rate=12.5"
    if m["kind"] == "vm":
        templates = {"debian-13": 9000, "ubuntu-24.04": 9001}
        if m["image"] not in templates:
            raise ValueError("image not installed")
        run("qm", "clone", templates[m["image"]], vmid, "--full", "1", "--name", m["name"], timeout=600)
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
            cloud_init(m),
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
        run("qm", "start", vmid)
    else:
        images = {
            "debian-13": "debian-13-standard_13.1-2_amd64.tar.zst",
            "ubuntu-24.04": "ubuntu-24.04-standard_24.04-2_amd64.tar.zst",
        }
        template = images[m["image"]]
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
        run("pct", "start", vmid)
        run("pct", "exec", vmid, "--", "mkdir", "-p", "/etc/systemd/system/systemd-journald.service.d")
        fix = STATE / "journald.conf"
        write(fix, "[Service]\nImportCredential=\n")
        run("pct", "push", vmid, fix, "/etc/systemd/system/systemd-journald.service.d/carrel.conf")
        run("pct", "exec", vmid, "--", "systemctl", "daemon-reload")
        run("pct", "exec", vmid, "--", "systemctl", "reset-failed", "systemd-journald")
        run("pct", "exec", vmid, "--", "systemctl", "restart", "systemd-journald")
    keyfile.unlink(missing_ok=True)
    return {"state": "running", "vmid": vmid}


def action(req):
    m = req["machine"]
    cfg = owned(m)
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
    elif op == "resize":
        cpu = integer(req["cpu"], int(cfg.get("cores", 1)), 64)
        mem = integer(req["memory_mb"], int(cfg["memory"]), 131072)
        disk = integer(req["disk_gb"], m["disk_gb"], 1000)
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
        if op == "delsnapshot":
            kind = "qemu" if cmd == "qm" else "lxc"
            snapshots = api("get", f"/nodes/{NODE}/{kind}/{vmid}/snapshot")
            if not any(s["name"] == name for s in snapshots):
                return {"state": "absent"}
        run(cmd, op, vmid, name, timeout=600)
    elif op in ["nic_attach", "nic_detach"]:
        index = integer(req["index"], 1, 7)
        if op == "nic_detach":
            run(cmd, "set", vmid, "--delete", f"net{index}")
        else:
            serial = integer(req["serial"], 1, 99)
            net = f"bridge=p{m['tenant_n']:03d}{serial:02d},firewall=0,rate=100"
            net = "virtio," + net + ",mtu=1" if cmd == "qm" else f"name=eth{index},type=veth,mtu=1450," + net
            run(cmd, "set", vmid, f"--net{index}", net)
    else:
        raise ValueError("unsupported machine operation")
    return {"state": "done"}


def main():
    STATE.mkdir(parents=True, exist_ok=True)
    with (STATE / "node.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        data = sys.stdin.buffer.read(2_000_001)
        if len(data) > 2_000_000:
            raise ValueError("request too large")
        req = json.loads(data)
        op = req["op"]
        if op == "reconcile":
            out = reconcile(req["state"])
        elif op == "create":
            out = create(req["machine"])
        elif op == "action":
            out = action(req)
        elif op == "inventory":
            out = {
                "node": NODE,
                "resources": api("get", "/cluster/resources"),
                "storage": api("get", f"/nodes/{NODE}/storage/local-lvm/status"),
                "status": api("get", f"/nodes/{NODE}/status"),
            }
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
        print(json.dumps({"ok": True, "result": out}))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        sys.exit(1)
