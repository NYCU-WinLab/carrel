#!/usr/bin/env python3
"""Staging glue for scripts/skill-bench.py (issue #848). Standard library only.

Runs on the operator's machine, next to skill-bench.py: it needs root on a staging node to set
skills_hidden. The agents run elsewhere, in the bench container (agent.sh, run-claude.sh), never
under an operator account: they run with bypassPermissions and would reach the operator's files.

  bench.py arm      Run as the bench's --arm-command. Sets skills_hidden on the staging control
                    plane for BENCH_ARM (hidden hides BENCH_SKILL), then resets the start state of
                    BENCH_CASE: the case's machines are deleted and created again, with a throwaway
                    key when the case says `keys: lost`.
  bench.py oracle   Serve the admin paths the cases check, on 127.0.0.1:BENCH_ORACLE_PORT (8790):
                      /admin/machines/<name>/ssh-check  {"ok": true} when the bench key logs in
                      /admin/machines/<name>/ports      {"count": n} public port grants on it

Environment:
  CARREL_URL        https://carrel.zhanyongxiang.com
  CARREL_TOKEN_FILE a member access token for the bench tenant (see sites/stg/README.md)
  STG_ROOT          root@10.10.11.110, the node that holds the control plane CT
  STG_CT            100
  BENCH_KEY         a copy of the bench agent's private key, to check that its login works
  BENCH_SSH_HOST    198.18.61.10, where tenant SSH ports answer
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
skill_bench = __import__("skill-bench") if (ROOT / "scripts" / "skill-bench.py").exists() else None

URL = os.environ.get("CARREL_URL", "https://carrel.zhanyongxiang.com").rstrip("/") + "/mcp"
STG_ROOT = os.environ.get("STG_ROOT", "root@10.10.11.110")
STG_CT = os.environ.get("STG_CT", "100")
SSH_HOST = os.environ.get("BENCH_SSH_HOST", "198.18.61.10")
SSH_WAIT = 120
CONFIG = "/etc/carrel/config.json"


class MCP:
    def __init__(self):
        self.token = Path(os.environ["CARREL_TOKEN_FILE"]).read_text().strip()
        self.sid = None
        self._post(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "bench", "version": "0"},
                },
            }
        )
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _post(self, body):
        h = {
            "authorization": "Bearer " + self.token,
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
        }
        if self.sid:
            h["mcp-session-id"] = self.sid
        with urllib.request.urlopen(
            urllib.request.Request(URL, json.dumps(body).encode(), h), timeout=120
        ) as r:
            self.sid = self.sid or r.headers.get("mcp-session-id")
            raw = r.read().decode()
        data = raw.split("data:", 1)[1] if raw.lstrip().startswith(("event:", "data:")) else raw
        return json.loads(data) if data.strip() else None

    def call(self, name, args):
        r = self._post(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": args}}
        )
        result = r.get("result") or {}
        text = "".join(c.get("text", "") for c in result.get("content", []))
        out = json.loads(text) if text.strip().startswith("{") else {"text": text}
        if result.get("isError") or r.get("error"):
            raise RuntimeError(f"{name}: {json.dumps(out)[:300]}")
        return out

    def wait(self, out):
        op = out.get("operation") or {}
        while op and op.get("state") not in ("succeeded", "failed", "canceled"):
            op = self.call("operation_get", {"id": op["id"], "wait_seconds": 25}).get("operation", op)
        if op and op.get("state") != "succeeded":
            raise RuntimeError(
                f"operation {op.get('id')} {op.get('state')}: {json.dumps(op.get('error'))[:300]}"
            )
        return op


def node(command, stdin=None):
    return subprocess.run(
        ["ssh", "-o", "BatchMode=yes", STG_ROOT, command],
        input=stdin,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    ).stdout


def set_hidden(skills):
    """Rewrite skills_hidden in the control plane config and restart it."""
    script = f"""import json
p = {CONFIG!r}
c = json.load(open(p))
if {skills!r}:
    c["skills_hidden"] = {skills!r}
else:
    c.pop("skills_hidden", None)
open(p, "w").write(json.dumps(c, indent=2) + "\\n")
"""
    node(f"pct exec {STG_CT} -- python3 - && pct exec {STG_CT} -- systemctl restart carrel", stdin=script)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            MCP()
            return
        except OSError:
            time.sleep(2)
    raise RuntimeError("control plane did not come back")


def reset_case(case):
    mcp = MCP()
    names = {m["name"] for m in mcp.call("machine_list", {}).get("machines", [])}
    for spec in (case.get("start") or {}).get("machines") or []:
        name = spec["name"]
        if name in names:
            mcp.wait(mcp.call("machine_delete", {"machine": name, "confirm": name, "wait_seconds": 55}))
        with tempfile.TemporaryDirectory() as d:
            if spec.get("keys") == "lost":
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f"{d}/k"], check=True)
                key = Path(f"{d}/k.pub").read_text().strip()
            else:
                key = Path(os.environ["BENCH_KEY"] + ".pub").read_text().strip()
            args = {
                "name": name,
                "image": spec.get("image", "debian-13-minimal"),
                "size": spec.get("size", "small"),
                "ssh_keys": [key],
                "idempotency_key": f"bench-{name}-{time.time_ns()}",
                "wait_seconds": 55,
            }
            mcp.wait(mcp.call("machine_create", args))
        if spec.get("state") == "stopped":
            mcp.wait(mcp.call("machine_power", {"machine": name, "action": "shutdown", "wait_seconds": 55}))


def arm():
    skill, which, case_name = os.environ["BENCH_SKILL"], os.environ["BENCH_ARM"], os.environ["BENCH_CASE"]
    case = next(c for c in skill_bench.load_cases(str(ROOT), skill) if c["name"] == case_name)
    set_hidden([skill] if which == "hidden" else [])
    reset_case(case)
    print(f"arm {which} case {case_name}: ready", file=sys.stderr)


def ssh_ok(port):
    # Every case recreates its machines, so their host keys are new each run: the oracle checks the
    # login, not the host identity, and keeps no known_hosts.
    cmd = [
        "ssh",
        "-F",
        "/dev/null",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=10",
        "-i",
        os.environ["BENCH_KEY"],
        "-p",
        str(port),
        f"user@{SSH_HOST}",
        "true",
    ]
    # A reset reboots the VM, and the agent may finish before sshd is back: a member would retry, so
    # the oracle keeps trying for SSH_WAIT seconds before it calls access lost.
    deadline = time.monotonic() + SSH_WAIT
    while True:
        if subprocess.run(cmd, capture_output=True, timeout=40, check=False).returncode == 0:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(5)


class Oracle(BaseHTTPRequestHandler):
    def do_GET(self):
        m = re.fullmatch(r"/admin/machines/([a-z0-9-]{1,63})/(ssh-check|ports)", self.path)
        if not m:
            return self._send(404, {"error": "not found"})
        name, what = m.groups()
        try:
            mcp = MCP()
            machine = (mcp.call("machine_get", {"machine": name}).get("machines") or [{}])[0]
            port = re.search(r"-p (\d+)", str(machine.get("ssh", "")))
            if what == "ports":
                # The SSH forward every machine gets is not a port the agent opened.
                ssh_port = int(port.group(1)) if port else None
                grants = mcp.call("port_list", {}).get("ports") or []
                return self._send(
                    200,
                    {
                        "count": sum(
                            1 for g in grants if g.get("machine") == name and g.get("public_port") != ssh_port
                        )
                    },
                )
            return self._send(200, {"ok": bool(port) and ssh_ok(port.group(1))})
        except Exception as exc:  # noqa: BLE001 reported to the bench as a failed check
            return self._send(502, {"error": f"{type(exc).__name__}: {exc}"[:300]})

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        print(fmt % args, file=sys.stderr)


def main(argv):
    if argv[1:] == ["arm"]:
        arm()
    elif argv[1:] == ["oracle"]:
        # A missing key would fail every ssh-check quietly, as if no agent ever got back in.
        for path in (os.environ["BENCH_KEY"], os.environ["CARREL_TOKEN_FILE"]):
            if not Path(path).is_file():
                sys.exit(f"bench oracle: {path} is not a file")
        HTTPServer(("127.0.0.1", int(os.environ.get("BENCH_ORACLE_PORT", "8790"))), Oracle).serve_forever()
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
