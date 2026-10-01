#!/usr/bin/env python3
"""Install a pinned official Caddy on the two Carrel-owned proxy containers."""

import hashlib
import importlib.util
from pathlib import Path
import tarfile
import tempfile
import urllib.request

spec = importlib.util.spec_from_file_location("deploy", Path(__file__).with_name("deploy-control.py"))
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)
VERSION = "2.11.4"
SHA512 = "8220d1f013b6f27510247b2360c9e0ca9f018feebd82515f07635318b34ff9777ccc8fd0b6e6f2486ce3a33fe389fbb7db12d05baa474f4587509fb4f5ebf1c9"


def main():
    with tempfile.TemporaryDirectory() as temp:
        archive = Path(temp) / "caddy.tar.gz"
        url = f"https://github.com/caddyserver/caddy/releases/download/v{VERSION}/caddy_{VERSION}_linux_amd64.tar.gz"
        archive.write_bytes(urllib.request.urlopen(url, timeout=60).read())
        if hashlib.sha512(archive.read_bytes()).hexdigest() != SHA512:
            raise ValueError("Caddy checksum mismatch")
        with tarfile.open(archive) as tar:
            binary = Path(temp) / "caddy"
            binary.write_bytes(tar.extractfile("caddy").read())
        for host, ct in [("pve", 207), ("carrel01", 101)]:
            deploy.run(["scp", str(binary), host + ":/var/lib/carrel-caddy"])
            deploy.ssh(
                host,
                f"pct push {ct} /var/lib/carrel-caddy /usr/local/bin/caddy --perms 755 && rm /var/lib/carrel-caddy && pct exec {ct} -- mkdir -p /etc/systemd/system/caddy.service.d",
            )
            deploy.push_ct(
                host,
                ct,
                "/etc/systemd/system/caddy.service.d/carrel.conf",
                """[Service]
ExecStart=
ExecStart=/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --force
Restart=on-failure
RestartSec=3
""",
            )
            deploy.ssh(
                host,
                f"pct exec {ct} -- chmod 644 /etc/caddy/Caddyfile && pct exec {ct} -- /usr/local/bin/caddy validate --config /etc/caddy/Caddyfile && pct exec {ct} -- systemctl daemon-reload && pct exec {ct} -- systemctl restart caddy && pct exec {ct} -- /usr/local/bin/caddy version",
            )


if __name__ == "__main__":
    main()
