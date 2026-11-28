#!/usr/bin/env python3
"""Offline skill bench (issue #853, PLAN 4.5.3). Runs on staging, never in CI.

For every case in skills/<name>/evals/*.yaml it runs two arms (skill visible, skill hidden),
--runs times per arm, for each agent (claude, codex). Outcomes are checked through the admin
API, never from the transcript, except the secret check on tool arguments. Transcripts are
masked before anything is stored. Results go to skills/<name>/evals/results/<version>.json.

Usage: skill-bench.py SKILL [--dry-run] [--runs 5] [--agents claude,codex] [--root DIR]
         [--admin-url URL] [--admin-token-env VAR] [--arm-command CMD] [--agent-cmd NAME=CMD]

--arm-command is run before each run with BENCH_SKILL, BENCH_ARM (visible|hidden) and BENCH_CASE
in its environment; it sets skills_hidden on the staging server and resets the case's start state.
--agent-cmd replaces the command of an agent; the prompt arrives on stdin, the transcript is read
from stdout as JSON lines. Standard library only.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ARMS = ("visible", "hidden")
AGENTS = ("claude", "codex")
AGENT_COMMANDS = {
    "claude": ["claude", "-p", "--output-format", "stream-json", "--verbose"],
    "codex": ["codex", "exec", "--json"],
}
SECRET_KEY = re.compile(r"token|key|secret|password", re.IGNORECASE)
PRIVATE_BLOCK = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.DOTALL)
REFUSAL = re.compile(r"\b(I can(?:'|no)t (?:help|assist)|I(?:'m| am) unable to (?:help|assist)|I must decline)", re.IGNORECASE)
MASK = "[masked]"


# ---- a small YAML subset: maps, lists, scalars, comments ----------------------------------------


def _scalar(text):
    text = text.strip()
    if text in ("true", "false"):
        return text == "true"
    if text in ("null", "~", ""):
        return None
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def parse_yaml(text):
    lines = []
    for raw in text.replace("\r\n", "\n").split("\n"):
        if raw.strip() and not raw.lstrip().startswith("#"):
            lines.append((len(raw) - len(raw.lstrip(" ")), raw.strip()))
    value, pos = _block(lines, 0, lines[0][0] if lines else 0)
    if pos != len(lines):
        raise ValueError(f"unexpected indentation near {lines[pos][1]!r}")
    return value


def _block(lines, pos, indent):
    if lines[pos][1].startswith("- "):
        return _list(lines, pos, indent)
    return _map(lines, pos, indent)


def _map(lines, pos, indent):
    out = {}
    while pos < len(lines) and lines[pos][0] == indent and not lines[pos][1].startswith("- "):
        key, sep, rest = lines[pos][1].partition(":")
        if not sep:
            raise ValueError(f"expected key: value, got {lines[pos][1]!r}")
        pos += 1
        if rest.strip():
            out[key.strip()] = _scalar(rest)
        elif pos < len(lines) and (lines[pos][0] > indent or (lines[pos][0] == indent and lines[pos][1].startswith("- "))):
            out[key.strip()], pos = _block(lines, pos, lines[pos][0])
        else:
            out[key.strip()] = None
    return out, pos


def _list(lines, pos, indent):
    out = []
    while pos < len(lines) and lines[pos][0] == indent and lines[pos][1].startswith("- "):
        body = lines[pos][1][2:]
        if ":" in body and not body.startswith(("'", '"')):
            # an item that is a map: its first key sits on the dash line
            sub = [(indent + 2, body)]
            pos += 1
            while pos < len(lines) and lines[pos][0] > indent:
                sub.append(lines[pos])
                pos += 1
            item, _ = _map(sub, 0, indent + 2)
            out.append(item)
        else:
            out.append(_scalar(body))
            pos += 1
    return out, pos


# ---- masking ------------------------------------------------------------------------------------


def mask(value):
    """Return value with secret-looking data removed: values of keys named like token, key,
    secret or password, and any private key block in a string."""
    if isinstance(value, dict):
        return {k: (MASK if SECRET_KEY.search(str(k)) and v not in (None, "") else mask(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [mask(v) for v in value]
    if isinstance(value, str):
        return PRIVATE_BLOCK.sub(MASK, value)
    return value


def mask_text(line):
    """Mask one transcript line: as JSON when it parses, otherwise just private key blocks."""
    try:
        return json.dumps(mask(json.loads(line)))
    except ValueError:
        return PRIVATE_BLOCK.sub(MASK, line)


# ---- planning -----------------------------------------------------------------------------------


def load_cases(root, skill):
    folder = Path(root) / "skills" / skill / "evals"
    cases = [parse_yaml(p.read_text(encoding="utf-8")) for p in sorted(folder.glob("*.yaml"))]
    if not cases:
        raise SystemExit(f"no cases in {folder}")
    return cases


def plan(cases, agents, runs):
    """One entry per planned run. Arms alternate inside each (case, agent), so a drift on
    staging during the bench touches both arms alike."""
    out = []
    for case in cases:
        for agent in agents:
            for n in range(runs):
                for arm in ARMS:
                    out.append({"case": case["name"], "agent": agent, "arm": arm, "run": n + 1})
    return out


def skill_version(root, skill):
    text = (Path(root) / "skills" / skill / "SKILL.md").read_text(encoding="utf-8")
    m = re.search(r"^version:\s*(\S+)\s*$", text, re.MULTILINE)
    if not m:
        raise SystemExit(f"skills/{skill}/SKILL.md has no version")
    return m.group(1)


# ---- one run ------------------------------------------------------------------------------------


def _blocks(event):
    """Yield (kind, payload) for tool calls and results in one transcript event, for the stream
    formats of claude (assistant/user content blocks) and codex (item.completed)."""
    if not isinstance(event, dict):
        return
    msg = event.get("message")
    for block in (msg.get("content") if isinstance(msg, dict) else None) or []:
        if isinstance(block, dict) and block.get("type") == "tool_use":
            yield "call", block.get("input")
        elif isinstance(block, dict) and block.get("type") == "tool_result":
            yield "result", bool(block.get("is_error"))
    item = event.get("item")
    if isinstance(item, dict) and event.get("type") == "item.completed":
        if item.get("type") == "mcp_tool_call":
            yield "call", item.get("arguments")
            yield "result", item.get("status") == "failed" or bool(item.get("error"))
        elif item.get("type") == "command_execution":
            yield "call", {"command": item.get("command")}
            yield "result", item.get("exit_code") not in (0, None)


# Arguments named like a key that never hold a secret: a retry handle and public SSH keys (a private
# key pasted into them is still caught by the private block check).
NOT_SECRET = {"idempotency_key", "ssh_key", "ssh_keys"}


def has_secret(args):
    """True when a tool argument holds a private key block or a non-empty value under a secret key."""
    if isinstance(args, dict):
        return any((str(k) not in NOT_SECRET and SECRET_KEY.search(str(k)) and v not in (None, "") and not isinstance(v, (dict, list))) or has_secret(v) for k, v in args.items())
    if isinstance(args, list):
        return any(has_secret(v) for v in args)
    if isinstance(args, str):
        return bool(PRIVATE_BLOCK.search(args))
    return False


def summarize(lines):
    """Metrics from raw transcript lines."""
    calls = errors = 0
    secret = False
    cost = 0.0
    text = []
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        for kind, payload in _blocks(event):
            if kind == "call":
                calls += 1
                secret = secret or has_secret(payload)
            elif payload:
                errors += 1
        if isinstance(event, dict):
            cost += float(event.get("total_cost_usd") or event.get("cost_usd") or 0)
            if isinstance(event.get("result"), str):
                text.append(event["result"])
            item = event.get("item")
            if isinstance(item, dict) and item.get("type") == "agent_message":
                text.append(str(item.get("text", "")))
    return {"tool_calls": calls, "error_results": errors, "cost_usd": cost, "secret_in_args": secret, "final_text": "\n".join(text)}


def admin_get(url, token, path):
    req = urllib.request.Request(url.rstrip("/") + path, headers={"Authorization": f"Bearer {token}"} if token else {})
    # The oracle may wait for a rebooted machine before it answers.
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.load(resp)


def run_checks(case, metrics, getter):
    """Return (passed, safety_violations, details). getter(path) returns admin API JSON."""
    passed, violations, details = True, 0, []
    for check in case.get("checks") or []:
        try:
            if check.get("no_secret_in_tool_args"):
                ok = not metrics["secret_in_args"]
            else:
                ok = getter(check["admin_get"]).get(check["field"]) == check["equals"]
        except Exception as exc:  # noqa: BLE001 an unreachable admin API fails the check, it does not end the bench
            ok = False
            details.append({"check": check["name"], "error": type(exc).__name__})
        details.append({"check": check["name"], "ok": ok})
        if not ok:
            passed = False
            if check.get("safety"):
                violations += 1
    return passed, violations, details


def run_one(entry, case, args, getter):
    prompt = case["sentence_codex"] if entry["agent"] == "codex" and case.get("sentence_codex") else case["sentence"]
    env = dict(os.environ, BENCH_SKILL=case["skill"], BENCH_ARM=entry["arm"], BENCH_CASE=case["name"])
    if args.arm_command:
        subprocess.run(args.arm_command, shell=True, env=env, check=True, timeout=600)
    command = args.agent_cmds.get(entry["agent"]) or AGENT_COMMANDS[entry["agent"]]
    start = time.monotonic()
    proc = subprocess.run(command, input=prompt, capture_output=True, text=True, timeout=args.timeout, env=env, check=False)
    wall = time.monotonic() - start
    lines = proc.stdout.splitlines()
    metrics = summarize(lines)
    result = dict(entry, wall_seconds=round(wall, 2), tool_calls=metrics["tool_calls"],
                  error_results=metrics["error_results"], cost_usd=metrics["cost_usd"])
    if metrics["tool_calls"] == 0 and REFUSAL.search(metrics["final_text"]):
        # a refusal says nothing about the skill: counted apart, not as a failed run
        result.update(outcome="refused", safety_violations=0, checks=[])
    else:
        ok, violations, details = run_checks(case, metrics, getter)
        result.update(outcome="passed" if ok else "failed", safety_violations=violations, checks=details)
    result["transcript"] = [mask_text(line) for line in lines]
    return result


def aggregate(results):
    out = {}
    for agent in sorted({r["agent"] for r in results}):
        for arm in ARMS:
            rs = [r for r in results if r["agent"] == agent and r["arm"] == arm]
            if not rs:
                continue
            counted = [r for r in rs if r["outcome"] != "refused"]
            n = len(rs)
            out[f"{agent}/{arm}"] = {
                "runs": n,
                "refused": n - len(counted),
                "pass_rate": (sum(r["outcome"] == "passed" for r in counted) / len(counted)) if counted else None,
                "tool_calls": sum(r["tool_calls"] for r in rs) / n,
                "error_results": sum(r["error_results"] for r in rs) / n,
                "cost_usd": sum(r["cost_usd"] for r in rs),
                "wall_seconds": sum(r["wall_seconds"] for r in rs) / n,
                "safety_violations": sum(r["safety_violations"] for r in rs),
            }
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("skill")
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--agents", default=",".join(AGENTS))
    ap.add_argument("--dry-run", action="store_true", help="print the planned runs and call no agent")
    ap.add_argument("--admin-url", default=os.environ.get("CARREL_ADMIN_URL", ""))
    ap.add_argument("--admin-token-env", default="CARREL_ADMIN_TOKEN")
    ap.add_argument("--arm-command", default="")
    ap.add_argument("--agent-cmd", action="append", default=[], metavar="NAME=CMD")
    ap.add_argument("--timeout", type=int, default=1200)
    args = ap.parse_args(argv)
    agents = [a for a in args.agents.split(",") if a]
    for a in agents:
        if a not in AGENTS:
            ap.error(f"unknown agent {a!r}")
    args.agent_cmds = {}
    for item in args.agent_cmd:
        name, _, cmd = item.partition("=")
        args.agent_cmds[name] = cmd.split()

    cases = load_cases(args.root, args.skill)
    planned = plan(cases, agents, args.runs)
    if args.dry_run:
        print(f"{len(planned)} planned runs ({len(cases)} case x {len(ARMS)} arms x {args.runs} runs x {len(agents)} agents)")
        return 0
    if not args.admin_url:
        ap.error("--admin-url (or CARREL_ADMIN_URL) is required for a real run")
    token = os.environ.get(args.admin_token_env, "")
    getter = lambda path: admin_get(args.admin_url, token, path)
    by_name = {c["name"]: c for c in cases}
    results = [run_one(e, by_name[e["case"]], args, getter) for e in planned]
    version = skill_version(args.root, args.skill)
    doc = {"skill": args.skill, "version": version, "summary": aggregate(results), "runs": results}
    out = Path(args.root) / "skills" / args.skill / "evals" / "results" / f"{version}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
