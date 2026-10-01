#!/usr/bin/env python3
"""Publish only carrel.winlab.tw through the existing gateway and new CT 207."""

import importlib.util
import json
from pathlib import Path
import urllib.request

spec = importlib.util.spec_from_file_location("deploy", Path(__file__).with_name("deploy-control.py"))
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


def main():
    env = deploy.ssh("pve", "pct exec 200 -- cat /home/user/gateway/.env", capture=True)
    token = next(
        line.split("=", 1)[1].strip().strip('"').strip("'")
        for line in env.splitlines()
        if line.startswith("CF_API_TOKEN=")
    )

    def cf(path, data=None):
        request = urllib.request.Request(
            "https://api.cloudflare.com/client/v4/" + path,
            data=json.dumps(data).encode() if data is not None else None,
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        )
        result = json.load(urllib.request.urlopen(request))
        assert result["success"]
        return result["result"]

    zone = cf("zones?name=winlab.tw")[0]["id"]
    records = cf(f"zones/{zone}/dns_records?name=carrel.winlab.tw")
    if records:
        assert (
            len(records) == 1 and records[0]["type"] == "A" and records[0]["content"] == "140.113.194.229"
        ), "refusing to adopt another record"
    else:
        cf(
            f"zones/{zone}/dns_records",
            {
                "type": "A",
                "name": "carrel.winlab.tw",
                "content": "140.113.194.229",
                "ttl": 120,
                "proxied": False,
                "comment": "Owned by carrel B09 external edge",
            },
        )
    current = deploy.ssh("pve", "pct exec 200 -- cat /home/user/gateway/Caddyfile", capture=True)
    include = "import /home/user/gateway/carrel.Caddyfile"
    ready = deploy.ssh(
        "pve", "test ! -f /var/lib/carrel-edge/desired.json || echo ready", capture=True
    ).strip()
    if not ready:
        deploy.push_ct(
            "pve",
            200,
            "/home/user/gateway/carrel.Caddyfile",
            """# Managed carrel external entry. Existing sites stay in the original Caddyfile.
carrel.winlab.tw {
 reverse_proxy 10.10.10.207:80 {
  flush_interval -1
 }
}
""",
        )
    if include not in current:
        deploy.push_ct("pve", 200, "/home/user/gateway/Caddyfile.carrel-backup", current)
        deploy.push_ct(
            "pve",
            200,
            "/home/user/gateway/Caddyfile",
            current.rstrip() + "\n\n# Carrel B09 ingress\n" + include + "\n",
        )
    deploy.ssh(
        "pve",
        "pct exec 200 -- caddy validate --config /home/user/gateway/Caddyfile && pct exec 200 -- systemctl reload caddy",
    )
    service = """[Unit]
Description=Carrel public tenant port mappings
After=network.target wg-quick@wg-carrel.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /var/lib/carrel-edge/ports.nft
ExecReload=/usr/sbin/nft -f /var/lib/carrel-edge/ports.nft
[Install]
WantedBy=multi-user.target
"""
    import shlex

    code = "from pathlib import Path; import sys; Path('/etc/systemd/system/carrel-ports.service').write_text(sys.stdin.read())"
    deploy.ssh("pve", "python3 -c " + shlex.quote(code), service)
    if not ready:
        deploy.ssh(
            "pve",
            "/usr/local/lib/carrel/edge-agent.py",
            json.dumps({"op": "reconcile", "state": {"ports": []}}),
        )
    deploy.ssh("pve", "systemctl daemon-reload && systemctl enable --now carrel-ports")
    print("Published https://carrel.winlab.tw/mcp through CT 200 -> CT 207 -> WireGuard -> B09 control plane")


if __name__ == "__main__":
    main()
