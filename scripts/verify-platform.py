#!/usr/bin/env python3
"""Live acceptance on disposable Keycloak tenants. Saves non-secret test facts."""

import argparse
import json
from pathlib import Path

import httpx


class Client:
    def __init__(self, tokens, index, origin="https://carrel.winlab.tw"):
        self.file, self.index, self.origin = tokens, index, origin

    def call(self, name, args=None):
        values = json.loads(self.file.read_text())
        token = values[self.index]
        with httpx.Client(timeout=600) as c:
            r = c.post(
                self.origin + "/oauth/token",
                data={
                    "client_id": token["client_id"],
                    "grant_type": "refresh_token",
                    "refresh_token": token["refresh_token"],
                    "resource": self.origin + "/mcp",
                },
            )
            r.raise_for_status()
            token.update(r.json())
            self.file.write_text(json.dumps(values))
            self.file.chmod(0o600)
            r = c.post(
                self.origin + "/mcp",
                headers={
                    "Authorization": "Bearer " + token["access_token"],
                    "Accept": "application/json, text/event-stream",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": args or {}},
                },
            )
            r.raise_for_status()
            result = r.json()["result"]["structuredContent"]
            print(name, json.dumps(result), flush=True)
            return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--tokens", type=Path, required=True)
    p.add_argument("--key", type=Path, required=True)
    p.add_argument("--phase", choices=["create", "delete"], required=True)
    a = p.parse_args()
    clients = [Client(a.tokens, i) for i in range(2)]
    if a.phase == "create":
        for c in clients:
            assert c.call("whoami")["ok"]
        forbidden = clients[0].call("quota_get", {"tenant": "carrel-test-b-0930"})
        assert forbidden["error"]["code"] == "forbidden"
        key = a.key.with_suffix(".pub").read_text().strip()
        for c, kind in zip(clients, ["vm", "ct"]):
            spec = {
                "name": "acceptance",
                "kind": kind,
                "image": "debian-13",
                "cpu": 1,
                "memory_mb": 1024,
                "disk_gb": 12,
                "ssh_keys": [key],
                "swap_mb": 0,
            }
            assert c.call("machine_create", {**spec, "dry_run": True})["ok"]
            print("Creating", kind, "and waiting for SSH", flush=True)
            assert c.call("machine_create", spec)["ok"]
    else:
        for c in clients:
            assert c.call("machine_delete", {"machine": "acceptance", "confirm": "acceptance"})["ok"]


if __name__ == "__main__":
    main()
