#!/usr/bin/env python3
"""Check every skills/*/SKILL.md (issue #852).

Rules: valid frontmatter, every requires_tools name is a tool in
internal/carrel/contract.json, description at most 300 characters, and with
--base REF a SKILL.md that changed against REF has a higher version than on REF.

Usage: check-skills.py [--base origin/main] [--root DIR]
Standard library only. Exit 1 when any rule fails.
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

MAX_DESCRIPTION = 300
KEYS = {"name", "description", "version", "requires_tools", "verified"}
REQUIRED = ("name", "description", "version", "requires_tools")
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")


def parse(text):
    """Return (fields, error). requires_tools becomes a list."""
    text = text.replace("\r\n", "\n")
    if not text.startswith("---\n"):
        return None, "frontmatter must start with ---"
    rest = text[4:]
    if "\n---\n" in rest:
        head = rest.split("\n---\n", 1)[0]
    elif rest.endswith("\n---"):
        head = rest[:-4]
    else:
        return None, "frontmatter closing --- not found"
    fields = {}
    for line in head.split("\n"):
        if not line.strip():
            continue
        key, sep, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if not sep or key not in KEYS:
            return None, f"unknown or malformed frontmatter line {line!r}"
        if key in fields:
            return None, f"field {key} given twice"
        if key == "requires_tools":
            if not (value.startswith("[") and value.endswith("]")):
                return None, "field requires_tools must be a list like [a, b]"
            value = [i.strip().strip("\"'") for i in value[1:-1].split(",") if i.strip()]
        fields[key] = value
    for key in REQUIRED:
        if key not in fields:
            return None, f"field {key} missing"
    return fields, None


def version_key(version):
    core = version.split("+", 1)[0].split("-", 1)[0]
    return tuple(int(p) for p in core.split("."))


def check_file(path, tools):
    """Return (fields, errors) for one SKILL.md."""
    fields, err = parse(path.read_text(encoding="utf-8"))
    if err:
        return None, [err]
    errors = []
    if fields["name"] != path.parent.name:
        errors.append(f"name {fields['name']!r} must equal the directory {path.parent.name!r}")
    if len(fields["description"]) > MAX_DESCRIPTION:
        errors.append(f"description is {len(fields['description'])} characters, limit {MAX_DESCRIPTION}")
    if not SEMVER.match(fields["version"]):
        errors.append(f"version {fields['version']!r} is not semver")
    for tool in fields["requires_tools"]:
        if tool not in tools:
            errors.append(f"requires_tools names {tool!r}, which is not in contract.json")
    return fields, errors


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=False)


def check_bump(root, path, fields, base):
    rel = path.relative_to(root).as_posix()
    old = git(root, "show", f"{base}:{rel}")
    if old.returncode != 0:
        return []  # new on this branch
    if old.stdout.replace("\r\n", "\n") == path.read_text(encoding="utf-8").replace("\r\n", "\n"):
        return []
    old_fields, err = parse(old.stdout)
    if err or not SEMVER.match(old_fields["version"]) or not SEMVER.match(fields["version"]):
        return []  # the other rules report the broken side
    if version_key(fields["version"]) <= version_key(old_fields["version"]):
        return [f"changed since {base} but version {fields['version']} is not higher than {old_fields['version']}"]
    return []


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--base")
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    args = ap.parse_args(argv)
    root = Path(args.root)
    contract = json.loads((root / "internal" / "carrel" / "contract.json").read_text(encoding="utf-8"))
    tools = {t["name"] for t in contract["tools"]}
    failed = False
    for path in sorted((root / "skills").glob("*/SKILL.md")):
        fields, errors = check_file(path, tools)
        if fields and args.base:
            errors += check_bump(root, path, fields, args.base)
        for e in errors:
            failed = True
            print(f"{path.relative_to(root)}: {e}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
