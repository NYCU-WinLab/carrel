#!/usr/bin/env python3
"""Forced-command adapter on the old PVE. Owns only carrel's NAT table."""

import fcntl
import base64
from datetime import datetime, timezone
import ipaddress
import json
import re
from pathlib import Path
import subprocess
import sys


def run(*args):
    p = subprocess.run(args, text=True, capture_output=True, check=True)
    return p.stdout


def label(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", value):
        raise ValueError("invalid DNS label")
    return value


def push(vmid, local, remote):
    run("pct", "push", str(vmid), str(local), remote, "--perms", "600")


def proxy(state, base):
    domains = [d for d in state.get("domains", []) if d["state"] == "ready"]
    wanted = {label(d["slug"]) for d in domains}
    for d in domains:
        if d["name"] != label(d["sub"]) + "." + d["slug"] + ".winlab.tw":
            raise ValueError("domain outside tenant subtree")
    certificates_changed = False
    for cert in state.get("certificates", []):
        slug = label(cert["slug"])
        if slug not in wanted or max(len(cert["fullchain"]), len(cert["privkey"])) > 65536:
            raise ValueError("invalid certificate bundle")
        pending = base / (slug + "-pending")
        pending.mkdir(mode=0o700, exist_ok=True)
        crt, key = pending / "fullchain.pem", pending / "privkey.pem"
        for path, value in [(crt, cert["fullchain"]), (key, cert["privkey"])]:
            path.write_text(value)
            path.chmod(0o600)
        run("openssl", "x509", "-in", str(crt), "-noout", "-checkhost", "probe." + slug + ".winlab.tw")
        run("openssl", "x509", "-in", str(crt), "-noout", "-checkend", "0")
        if run("openssl", "x509", "-in", str(crt), "-pubkey", "-noout") != run(
            "openssl", "pkey", "-in", str(key), "-pubout"
        ):
            raise ValueError("certificate key mismatch")
        remote = "/etc/caddy/carrel-certs/" + slug
        run("pct", "exec", "200", "--", "mkdir", "-p", remote)
        old = subprocess.run(
            ["pct", "exec", "200", "--", "cat", remote + "/fullchain.pem"], text=True, capture_output=True
        )
        if old.returncode or old.stdout != cert["fullchain"]:
            push(200, crt, remote + "/fullchain.pem")
            push(200, key, remote + "/privkey.pem")
            certificates_changed = True
        key.unlink()
        crt.unlink()
        pending.rmdir()
    if wanted != {c["slug"] for c in state.get("certificates", [])}:
        raise ValueError("missing domain certificate")
    frontend = [
        "# Managed by carrel",
        "carrel.winlab.tw {",
        " reverse_proxy 10.10.10.207:80 {",
        "  flush_interval -1",
        "  stream_close_delay 5m",
        " }",
        "}",
    ]
    for slug in sorted(wanted):
        prefix = "/etc/caddy/carrel-certs/" + slug
        frontend += [
            f"*.{slug}.winlab.tw {{",
            f" tls {prefix}/fullchain.pem {prefix}/privkey.pem",
            " reverse_proxy 10.10.10.207:80",
            "}",
        ]
    front = "\n".join(frontend) + "\n"
    path = "/home/user/gateway/carrel.Caddyfile"
    old = run("pct", "exec", "200", "--", "cat", path)
    if old != front or certificates_changed:
        local = base / "frontend.Caddyfile"
        local.write_text(front)
        push(200, local, path)
        run("pct", "exec", "200", "--", "caddy", "validate", "--config", "/home/user/gateway/Caddyfile")
        run("pct", "exec", "200", "--", "systemctl", "reload", "caddy")
    routes = [
        "{",
        " admin localhost:2019",
        " auto_https off",
        "}",
        ":80 {",
        " @carrel host carrel.winlab.tw",
        " handle @carrel {",
        "  reverse_proxy 10.200.0.3:8080 {",
        "   flush_interval -1",
        "   stream_close_delay 5m",
        "  }",
        " }",
    ]
    if domains:
        routes += [
            " @tenants host " + " ".join(d["name"] for d in domains),
            " handle @tenants {",
            "  reverse_proxy 10.200.0.2:80",
            " }",
        ]
    routes += [" handle {", "  respond 404", " }", "}"]
    proxy_conf = "\n".join(routes) + "\n"
    if run("pct", "exec", "207", "--", "cat", "/etc/caddy/Caddyfile") != proxy_conf:
        local = base / "proxy.Caddyfile"
        local.write_text(proxy_conf)
        # Debian's Caddy runs unprivileged and needs read permission on its config.
        run("pct", "push", "207", str(local), "/etc/caddy/Caddyfile", "--perms", "644")
        run(
            "pct", "exec", "207", "--", "/usr/local/bin/caddy", "validate", "--config", "/etc/caddy/Caddyfile"
        )
        run("pct", "exec", "207", "--", "systemctl", "reload", "caddy")


def main():
    base = Path("/var/lib/carrel-edge")
    base.mkdir(exist_ok=True)
    with (base / "lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        raw = sys.stdin.buffer.read(14_000_001)
        if len(raw) > 14_000_000:
            raise ValueError("oversized request")
        req = json.loads(raw)
        if req["op"] == "backup":
            archive = base64.b64decode(req["archive"], validate=True)
            if not 1 <= len(archive) <= 10_000_000 or not archive.startswith(b"\x1f\x8b"):
                raise ValueError("Invalid backup archive")
            folder = base / "backups"
            folder.mkdir(mode=0o700, exist_ok=True)
            name = datetime.now(timezone.utc).strftime("control-%Y-%m-%d.tar.gz")
            pending = folder / "pending"
            pending.write_bytes(archive)
            pending.chmod(0o600)
            pending.replace(folder / name)
            for old in sorted(folder.glob("control-*.tar.gz"))[:-14]:
                old.unlink()
            print(json.dumps({"ok": True, "result": {"file": name, "bytes": len(archive)}}))
            return
        if req["op"] != "reconcile":
            raise ValueError("unknown operation")
        state = req["state"]
        rules = [
            "add table ip carrel_ports",
            "flush table ip carrel_ports",
            "table ip carrel_ports {",
            "chain prerouting { type nat hook prerouting priority dstnat - 5; policy accept;",
        ]
        seen = set()
        for p in state["ports"]:
            n, public, private, proto = p["tenant_n"], p["public_port"], p["port"], p["proto"]
            if not (
                type(n) is int
                and 1 <= n <= 254
                and type(public) is int
                and 20000 + n * 10 <= public < 20010 + n * 10
                and type(private) is int
                and 1 <= private <= 65535
                and proto in ("tcp", "udp")
            ):
                raise ValueError("invalid port grant")
            address = ipaddress.IPv4Address(p["ip"])
            if (
                address not in ipaddress.IPv4Network(f"10.200.{n}.0/24")
                or not 10 <= int(str(address).split(".")[-1]) <= 109
            ):
                raise ValueError("invalid target")
            if (proto, public) in seen:
                raise ValueError("duplicate public port")
            seen.add((proto, public))
            rules.append(
                f'ip daddr 140.113.194.229 iifname {{ "vmbr0", "tailscale0", "vnet10" }} {proto} dport {public} counter dnat to {address}:{private}'
            )
        rules += [
            "}",
            "chain postrouting { type nat hook postrouting priority srcnat - 5; policy accept;",
            'oifname "wg-carrel" ct status dnat ip daddr 10.200.0.0/16 snat to 10.254.200.1',
            "}",
            "}",
        ]
        content = "\n".join(rules) + "\n"
        path = base / "ports.nft"
        old = path.read_text() if path.exists() else ""
        pending = base / "ports.pending.nft"
        pending.write_text(content)
        run("nft", "-c", "-f", str(pending))
        run("nft", "-f", str(pending))
        pending.replace(path)
        proxy(state, base)
        (base / "desired.json").write_text(
            json.dumps({k: v for k, v in state.items() if k != "certificates"})
        )
        print(json.dumps({"ok": True, "result": {"ports": len(seen), "changed": old != content}}))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        sys.exit(1)
