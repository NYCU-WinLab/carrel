#!/usr/bin/env python3
"""Install or upgrade the control plane from this checkout and sandbox-built binaries.

Copies the release to a stage directory on the first exit node and runs
install-control.py there; nothing is built on the workstation or the node.
"""

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARIES = ("carrel", "carrel-deployd")
# install-control.py runs the release; the rest are the node programs it installs.
SCRIPTS = ("install-control.py", "node-agent.py", "configure-reader.py", "configure-nodes.py",
           "guest-report.py", "gateway-sync.py")


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True,
                        help="SSH target of the site's first exit node, which holds CT 100, e.g. root@192.168.19.101")
    parser.add_argument("--artifacts", type=Path, required=True, help="Directory with the sandbox-built binaries")
    parser.add_argument("--templates", type=Path,
                        help="Optional candidate templates.json to merge after immutable-template validation")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.@][A-Za-z0-9_.@-]*", args.host):
        parser.error("invalid host")
    # The health check expects the version this checkout builds.
    version = re.search(r'const Version = "([^"]+)"', (ROOT / "internal/carrel/value.go").read_text())[1]
    artifacts = args.artifacts.resolve()
    sources = [artifacts / name for name in BINARIES] + [ROOT / "scripts" / name for name in SCRIPTS]
    for path in sources[: len(BINARIES)]:
        if not path.is_file():
            raise SystemExit("Missing sandbox-built binary: " + path.name)
    if args.templates:
        if args.templates.name != "templates.json":
            parser.error("candidate manifest must be named templates.json")
        sources.append(args.templates.resolve())
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")  # noqa: UP017 (macOS Python 3.9)
    stage = "/var/lib/carrel/go-upgrade-" + stamp
    manifest = artifacts / "hashes.json"
    manifest.write_text(json.dumps(hashes) + "\n")
    run(["ssh", args.host, "install -d -m 700 " + stage])
    run(["scp", *map(str, sources), str(manifest), args.host + ":" + stage + "/"])
    run(["ssh", args.host, f"python3 {stage}/install-control.py host --stage {stage} --version {version}"])
    revision = run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True).stdout.strip()
    report = {"version": version, "revision": revision, "stamp": stamp, "sha256": hashes, "node_backup": stage,
              "control_backup": "/opt/carrel/rollback/go-" + stamp + ".tar.gz"}
    (artifacts / "deploy-go.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
