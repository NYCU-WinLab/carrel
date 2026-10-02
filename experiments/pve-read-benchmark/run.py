"""Interleave bounded read-only probes on the PVE node; publish timings, not payloads."""

import hashlib
import json
import platform
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
METHODS = ["python-pvesh", "rust-pvesh", "python-batch", "python-http", "rust-http"]


def stable_view(workload, value):
    if workload == "topology":
        # Config is stable; array order is not part of the API contract.
        return {
            "vnets": sorted(value["vnets"], key=lambda row: row["vnet"]),
            "subnets": {
                name: sorted(rows, key=lambda row: json.dumps(row, sort_keys=True))
                for name, rows in value["subnets"].items()
            },
        }
    resources = []
    for row in value["resources"]:
        resources.append(
            {
                key: row[key]
                for key in (
                    "id",
                    "type",
                    "node",
                    "vmid",
                    "template",
                    "maxcpu",
                    "maxmem",
                    "maxdisk",
                )
                if key in row
            }
        )
    return {
        "volumes": sorted(
            [
                {key: row[key] for key in ("volid", "content", "size")}
                for row in value["volumes"]
            ],
            key=lambda row: row["volid"],
        ),
        "resources": sorted(resources, key=lambda row: row["id"]),
        "storage_total": value["storage"]["total"],
        "cpu_count": value["status"]["cpuinfo"]["cpus"],
        "memory_total": value["status"]["memory"]["total"],
    }


def signature(workload, result):
    normalized = json.dumps(
        stable_view(workload, result), sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(normalized.encode()).hexdigest()


def call(method, workload, count=1):
    language, mode = method.split("-")
    command = (
        [sys.executable, str(ROOT / "client.py")]
        if language == "python"
        else [str(ROOT / "carrel-pve-read-benchmark")]
    )
    start = time.perf_counter()
    raw = subprocess.check_output(
        [*command, mode, workload, str(count), str(ROOT / "config.json")],
        timeout=240,
    )
    wall = time.perf_counter() - start
    value = json.loads(raw)
    assert len(value["samples"]) == count
    return wall, value


def stats(values):
    quartiles = statistics.quantiles(values, n=4)
    return {
        "n": len(values),
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
        "q1": quartiles[0],
        "q3": quartiles[2],
    }


def main():
    rng = random.Random(20261002)
    records, validation, expected = [], {}, {}
    for workload in ("inventory", "topology"):
        fingerprints = {}
        for method in METHODS:
            _, value = call(method, workload)
            fingerprints[method] = signature(workload, value["result"])
        if len(set(fingerprints.values())) != 1:
            raise RuntimeError(
                f"Preflight payload mismatch: {workload}, {fingerprints}"
            )
        expected[workload] = fingerprints[METHODS[0]]
        validation[workload] = {
            "all_five_methods_match": True,
            "fingerprint": expected[workload],
        }
        print(
            json.dumps({"event": "preflight_passed", "workload": workload}), flush=True
        )

    for trial in range(12):
        work = [(w, m) for w in ("inventory", "topology") for m in METHODS]
        rng.shuffle(work)
        for workload, method in work:
            wall, value = call(method, workload)
            if signature(workload, value["result"]) != expected[workload]:
                raise RuntimeError(
                    f"Allocation/config changed during run: {workload}, {method}"
                )
            records.append(
                {
                    "phase": "new_process",
                    "trial": trial,
                    "workload": workload,
                    "method": method,
                    "seconds": wall,
                    "query_seconds": value["samples"][0],
                }
            )
        (ROOT / "partial.json").write_text(json.dumps(records))
        print(json.dumps({"event": "round_complete", "round": trial + 1}), flush=True)

    # Five process blocks per method, each with one discarded initial query and
    # ten measured observations sharing the same HTTP client and connection pool.
    for block in range(5):
        work = [
            (w, m)
            for w in ("inventory", "topology")
            for m in ("python-http", "rust-http")
        ]
        rng.shuffle(work)
        for workload, method in work:
            _, value = call(method, workload, count=11)
            if signature(workload, value["result"]) != expected[workload]:
                raise RuntimeError("Allocation/config changed during warm run")
            for iteration, seconds in enumerate(value["samples"][1:]):
                records.append(
                    {
                        "phase": "reused_client",
                        "trial": block,
                        "iteration": iteration,
                        "workload": workload,
                        "method": method,
                        "seconds": seconds,
                    }
                )
        print(
            json.dumps({"event": "warm_block_complete", "block": block + 1}), flush=True
        )

    summary = {}
    for phase in ("new_process", "reused_client"):
        summary[phase] = {}
        for workload in ("inventory", "topology"):
            summary[phase][workload] = {}
            for method in METHODS:
                values = [
                    r["seconds"]
                    for r in records
                    if (r["phase"], r["workload"], r["method"])
                    == (phase, workload, method)
                ]
                if values:
                    summary[phase][workload][method] = stats(values)
    result = {
        "seed": 20261002,
        "python": sys.version,
        "kernel": platform.release(),
        "pve": subprocess.check_output(["pveversion"], text=True).strip(),
        "validation": validation,
        "summary_seconds": summary,
        "records": records,
    }
    (ROOT / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"event": "complete", "summary_seconds": summary}), flush=True)


if __name__ == "__main__":
    main()
