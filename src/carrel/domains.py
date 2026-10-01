"""DNS-01 and certificates stay in the control plane, outside the ingress proxy."""

import asyncio
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx


class Domains:
    def __init__(self, store, config):
        self.store, self.config = store, config
        self.base = Path(config.get("certificate_dir", "/var/lib/carrel/certificates"))

    async def record(self, t, remove=False):
        base = f"https://api.cloudflare.com/client/v4/zones/{self.config['cloudflare_zone']}/dns_records"
        name = "*." + t["slug"] + ".winlab.tw"
        owner = f"carrel:b09:tenant:{t['n']}"
        async with httpx.AsyncClient(timeout=20) as http:
            headers = {"Authorization": "Bearer " + self.config["cloudflare_token"]}
            r = await http.get(base, params={"name": name}, headers=headers)
            r.raise_for_status()
            result = r.json()
            if not result.get("success"):
                raise RuntimeError("Cloudflare DNS lookup failed")
            records = result["result"]
            if records and (len(records) != 1 or records[0].get("comment") != owner):
                raise RuntimeError("Refusing DNS record owned outside carrel")
            if remove and records:
                r = await http.delete(base + "/" + records[0]["id"], headers=headers)
                r.raise_for_status()
            elif not remove and not records:
                r = await http.post(
                    base,
                    headers=headers,
                    json={
                        "type": "A",
                        "name": name,
                        "content": "140.113.194.229",
                        "ttl": 120,
                        "proxied": False,
                        "comment": owner,
                    },
                )
                r.raise_for_status()
                if not r.json().get("success"):
                    raise RuntimeError("DNS record creation failed")

    async def ensure(self, t):
        now = int(time.time())
        cert = next((c for c in self.store.objects("certificates", t["n"]) if c["slug"] == t["slug"]), None)
        # Only first issuance consumes the shared registered-domain budget.
        if not cert:
            issued = [c for c in self.store.objects("certificates") if c["issued_at"] > now - 7 * 86400]
            if len(issued) >= 30:
                return {"state": "queued", "ready_at": min(c["issued_at"] for c in issued) + 7 * 86400}
        await self.record(t)
        self.base.mkdir(parents=True, exist_ok=True)
        credentials = self.base / "cloudflare.ini"
        credentials.write_text("dns_cloudflare_api_token = " + self.config["cloudflare_token"] + "\n")
        credentials.chmod(0o600)
        process = await asyncio.create_subprocess_exec(
            str(Path(sys.executable).with_name("certbot")),
            "certonly",
            "--non-interactive",
            "--agree-tos",
            "--email",
            self.config.get("acme_email", "yongxiang.zhan@outlook.com"),
            "--dns-cloudflare",
            "--dns-cloudflare-credentials",
            str(credentials),
            "--dns-cloudflare-propagation-seconds",
            "30",
            "--cert-name",
            t["slug"],
            "--config-dir",
            str(self.base / "config"),
            "--work-dir",
            str(self.base / "work"),
            "--logs-dir",
            str(self.base / "logs"),
            "--keep-until-expiring",
            "-d",
            "*." + t["slug"] + ".winlab.tw",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _out, err = await asyncio.wait_for(process.communicate(), 300)
        except TimeoutError:
            process.kill()
            await process.wait()
            raise RuntimeError("Certificate issuance timed out")
        if process.returncode:
            print(
                json.dumps(
                    {"event": "certificate_failed", "tenant": t["n"], "diagnostic": err.decode()[-1200:]}
                )
            )
            raise RuntimeError("Certificate issuance failed; inspect control-plane ACME logs")
        if not cert:
            cert = {"id": str(t["n"]), "tenant_n": t["n"], "slug": t["slug"], "issued_at": now}
            self.store.put("certificates", str(t["n"]), t["n"], cert)
        return {"state": "ready"}

    def bundles(self, domains):
        wanted = {d["tenant_n"] for d in domains if d["state"] == "ready"}
        bundles = []
        for cert in self.store.objects("certificates"):
            if cert["tenant_n"] not in wanted:
                continue
            path = self.base / "config" / "live" / cert["slug"]
            bundles.append(
                {
                    "slug": cert["slug"],
                    "fullchain": (path / "fullchain.pem").read_text(),
                    "privkey": (path / "privkey.pem").read_text(),
                }
            )
        return bundles

    async def renew(self, tenant=None):
        from cryptography import x509

        wanted = {d["tenant_n"] for d in self.store.objects("domains")}
        for t in [tenant] if tenant else self.store.tenants():
            path = self.base / "config" / "live" / t["slug"] / "fullchain.pem"
            if t["n"] in wanted and path.exists():
                cert = x509.load_pem_x509_certificate(path.read_bytes())
                if (cert.not_valid_after_utc - datetime.now(UTC)).days < 30:
                    await self.ensure(t)
