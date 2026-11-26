#!/usr/bin/env python3
"""Install or upgrade the control plane from a published release, or from this
checkout and sandbox-built binaries.

Copies the release to a stage directory on the first exit node and runs
install-control.py there; nothing is built on the workstation or the node.
With --release the binaries and scripts come from the GitHub release archive,
checked against its SHA256SUMS; without it the deploy is a development build.
"""

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import tarfile
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = "NYCU-WinLab/carrel"
BINARIES = ("carrel", "carrel-deployd", "carrel-fetch")
# Shipped since the agent (PLAN 8.6); an older release has none.
OPTIONAL = ("carrel-agent",)
# install-control.py runs the release; the rest are the node programs it installs.
SCRIPTS = ("install-control.py", "node-agent.py", "configure-reader.py", "configure-nodes.py",
           "guest-report.py", "gateway-sync.py", "jump-sync.py", "jump-cert.py")


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def fetch_release(tag):
    """Download a release archive, check it against SHA256SUMS and unpack it.

    Returns the directory holding dist/, scripts/ and REVISION."""
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        raise SystemExit("A release is a tag such as v0.11.0")
    work = Path(tempfile.mkdtemp(prefix="carrel-" + tag + "-"))
    name = f"carrel-{tag}-linux-amd64"
    archive = work / (name + ".tar.gz")
    run(["gh", "release", "download", tag, "-R", REPO, "-p", archive.name, "-p", "SHA256SUMS", "-D", str(work)])
    sums = dict(reversed(line.split()) for line in (work / "SHA256SUMS").read_text().splitlines() if line.strip())
    if sums.get(archive.name) != hashlib.sha256(archive.read_bytes()).hexdigest():
        raise SystemExit("The release archive does not match SHA256SUMS")
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            parts = Path(member.name).parts
            if member.name.startswith("/") or ".." in parts or parts[:1] != (name,):
                raise SystemExit("Unexpected path in the release archive: " + member.name)
            if not (member.isfile() or member.isdir()):
                raise SystemExit("Unexpected entry in the release archive: " + member.name)
        # Every member was checked above; the data filter checks again where Python has it.
        tar.extractall(work, **({"filter": "data"} if hasattr(tarfile, "data_filter") else {}))
    return work / name


def fetch_plugins(host, scripts, into):
    """Download the plugins the site file lists, each checked against its sha256.

    The site file is read from the node; the release's own configure-nodes.py
    checks the list, so a release from before plugins (#662) fetches none."""
    spec = importlib.util.spec_from_file_location("configure_nodes", scripts / "configure-nodes.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "plugin_list"):
        return []
    site = json.loads(run(["ssh", host, "cat /etc/carrel/site.json"], capture_output=True).stdout or "{}")
    paths = []
    for p in module.plugin_list(site):
        path = into / module.plugin_artifact(p)
        with urllib.request.urlopen(p["url"], timeout=120) as response:
            path.write_bytes(response.read())
        if hashlib.sha256(path.read_bytes()).hexdigest() != p["sha256"]:
            raise SystemExit(f"plugin {p['name']} {p['version']}: {p['url']} does not match its sha256 in the site file")
        paths.append(path)
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True,
                        help="SSH target of the site's first exit node, which holds CT 100, e.g. root@192.168.19.101")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--release", help="Deploy this published release, e.g. v0.11.0")
    source.add_argument("--artifacts", type=Path,
                        help="Directory with sandbox-built binaries: a development build of this checkout")
    parser.add_argument("--templates", type=Path,
                        help="Optional candidate templates.json to merge after immutable-template validation")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.@][A-Za-z0-9_.@-]*", args.host):
        parser.error("invalid host")
    if args.release:
        unpacked = fetch_release(args.release)
        artifacts, scripts = unpacked / "dist", unpacked / "scripts"
        version, revision = args.release[1:], (unpacked / "REVISION").read_text().strip()
    else:
        # The health check expects the version this checkout builds.
        version = re.search(r'const Version = "([^"]+)"', (ROOT / "internal/carrel/value.go").read_text())[1]
        artifacts, scripts = args.artifacts.resolve(), ROOT / "scripts"
        revision = run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True).stdout.strip()
    sources = [artifacts / name for name in BINARIES] + [scripts / name for name in SCRIPTS]
    # A development build is this checkout, which has the agent.
    sources += [artifacts / name for name in OPTIONAL if args.artifacts or (artifacts / name).is_file()]
    for path in [p for p in sources if p.parent == artifacts]:
        if not path.is_file():
            raise SystemExit("Missing binary: " + path.name)
    if args.templates:
        if args.templates.name != "templates.json":
            parser.error("candidate manifest must be named templates.json")
        sources.append(args.templates.resolve())
    sources += fetch_plugins(args.host, scripts, artifacts)
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")  # noqa: UP017 (macOS Python 3.9)
    stage = "/var/lib/carrel/go-upgrade-" + stamp
    manifest = artifacts / "hashes.json"
    manifest.write_text(json.dumps(hashes) + "\n")
    run(["ssh", args.host, "install -d -m 700 " + stage])
    run(["scp", *map(str, sources), str(manifest), args.host + ":" + stage + "/"])
    run(["ssh", args.host, f"python3 {stage}/install-control.py host --stage {stage} --version {version}"])
    report = {"version": version, "revision": revision, "release": bool(args.release), "stamp": stamp, "sha256": hashes, "node_backup": stage,
              "control_backup": "/opt/carrel/rollback/go-" + stamp + ".tar.gz"}
    (artifacts / "deploy-go.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
