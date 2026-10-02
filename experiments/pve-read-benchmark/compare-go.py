"""Compare installed legacy/Go readers on an idle PVE node without mutations.

Copy beside run.py and the sandbox-built carrel-pve-read binary. Requires the
root-only production reader configuration; emits only timings and stable hashes.
"""

import hashlib
import json
import random
import subprocess
import time
from pathlib import Path

from run import signature, stats

root = Path(__file__).resolve().parent
commands = {"current_perl": "/usr/local/lib/carrel/pve-read.pl", "go_https": str(root / "carrel-pve-read")}


def read(method, workload):
    start = time.perf_counter()
    value = json.loads(subprocess.check_output([commands[method], workload], timeout=40))
    return time.perf_counter() - start, value


expected, validation = {}, {}
for workload in ("inventory", "topology"):
    values = {name: read(name, workload)[1] for name in commands}
    signatures = {name: signature(workload, value) for name, value in values.items()}
    assert len(set(signatures.values())) == 1, (workload, signatures)
    expected[workload] = signatures["current_perl"]
    validation[workload] = {"same_data": True, "signature": expected[workload]}
    if workload == "inventory":
        validation[workload]["volumes"] = len(values["go_https"]["volumes"])
    print(json.dumps({"preflight": workload, **validation[workload]}), flush=True)
records = []
rng = random.Random(2026100206)
for trial in range(12):
    work = [(m, w) for m in commands for w in ("inventory", "topology")]
    rng.shuffle(work)
    for method, workload in work:
        seconds, value = read(method, workload)
        assert signature(workload, value) == expected[workload], "State changed during measurement"
        records.append({"trial": trial, "method": method, "workload": workload, "seconds": seconds})
    print(json.dumps({"round": trial + 1}), flush=True)
summary = {
    w: {
        m: stats([r["seconds"] for r in records if r["method"] == m and r["workload"] == w]) for m in commands
    }
    for w in ("inventory", "topology")
}
report = {
    "validation": validation,
    "records": records,
    "summary": summary,
    "go_binary_sha256": hashlib.sha256((root / "carrel-pve-read").read_bytes()).hexdigest(),
}
(root / "read-benchmark.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(summary), flush=True)
