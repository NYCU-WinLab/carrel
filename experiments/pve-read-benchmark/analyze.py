"""Report absolute Python minus Rust differences, paired by process block."""

import json
import random
import statistics
import sys


def interval(values):
    rng = random.Random(20261002)
    medians = sorted(
        statistics.median(rng.choices(values, k=len(values))) for _ in range(10000)
    )
    return [medians[250], medians[9749]]


def main(path):
    with open(path) as source:
        data = json.load(source)
    comparisons = []
    for phase in ("new_process", "reused_client"):
        for workload in ("inventory", "topology"):
            pairs = {}
            for row in data["records"]:
                if (row["phase"], row["workload"]) != (phase, workload):
                    continue
                if row["method"] not in ("python-http", "rust-http"):
                    continue
                pairs.setdefault(row["trial"], {}).setdefault(row["method"], []).append(
                    row["seconds"]
                )
            differences = [
                statistics.median(pair["python-http"])
                - statistics.median(pair["rust-http"])
                for pair in pairs.values()
            ]
            comparisons.append(
                {
                    "phase": phase,
                    "workload": workload,
                    "paired_blocks": len(differences),
                    "python_minus_rust_seconds": differences,
                    "median_difference_seconds": statistics.median(differences),
                    "bootstrap_95_interval_seconds": interval(differences),
                }
            )
    print(json.dumps(comparisons, indent=2))


if __name__ == "__main__":
    main(sys.argv[1])
