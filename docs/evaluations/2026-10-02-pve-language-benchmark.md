# Python and Rust PVE read experiment

Rust HTTPS was faster when every observation launched a new client process:
inventory took 347 ms versus Python's 409 ms, and topology took 16.4 ms versus
80.0 ms. With an existing client, inventory medians were 338/335 ms and topology
medians 10.98/11.22 ms respectively. The approximately 63 ms cold-client advantage
is real in these implementations; most of it is outside the timed query function.
Timing only `python3 -c pass` did not capture imports and HTTP-client setup.

The largest improvement is changing the PVE access path. Replacing only Python
with Rust while continuing to launch `pvesh` leaves inventory above four seconds.
Both direct HTTPS implementations avoid repeated PVE CLI/module initialization.
The existing per-request helper design favors Rust for the lowest latency; a
persistent Python HTTP client attains similar read latency in this experiment.
These measurements do not establish a benefit from rewriting the whole service.

## Same host, data and workload

The experiment ran on B09 `carrel01`, Intel Xeon Gold 5218, PVE 9.1.1, kernel
6.17.2-1-pve, Python 3.13.5 and OpenSSL 3.5.4. Rust 1.98.1 built the release musl
binary on sandbox VM 104, with locked reqwest 0.12.28 and rustls 0.23.45. No build
or dependency installation ran on the PVE node or Mac. Production stayed on 0.5.1.

Inventory reads the same four endpoints as the production reader: local-lvm content,
cluster resources, local-lvm status and node status, in sequence. Topology reads
the VNet list and eight tenant subnet lists. Both legacy CLI implementations use
four concurrent subnet reads. Batched Perl and both HTTP implementations read
topology sequentially. HTTP clients use the same token, trusted PVE CA, verified
destination IP, HTTP/1.1 and connection reuse over local HTTPS port 8006.

All five methods pass normalized allocation/config equality before measurements
and throughout all 12 rounds. All 15 volumes are present. Volatile CPU usage,
uptime and free-space readings are excluded from equality because they change
between requests. The experiment does not include the separate `lvs` observation,
quota/admission policy, gateway writes, outer SSH or MCP transport, or guest boot.
The topology column below is observation time, not full network reconciliation.

## Results

Each fresh-process row has 12 samples. The ten method/workload combinations run
in a randomized order each round, using seed 20261002. Times include process start,
imports, client initialization, reads, JSON processing/output and process exit.
OS caches and PVE daemons remain warm; “fresh process” does not mean a cold host.

| Fresh process, median | Inventory | Topology |
| --- | ---: | ---: |
| Python with `pvesh` | 4,359 ms | 3,069 ms |
| Rust with `pvesh` | 4,295 ms | 3,030 ms |
| Python with current batched Perl reader | 1,349 ms | 1,029 ms |
| Python direct HTTPS | 409 ms | 80.0 ms |
| Rust direct HTTPS | 347 ms | 16.4 ms |

Relative to Python HTTPS, Rust's median wall time is about 15% lower for inventory
and 79% lower for topology. Absolute differences are 62.6 and 63.5 ms. Relative to
the current batch reader, Python HTTPS saves about 940/949 ms, and Rust HTTPS saves
about 1,002/1,013 ms for inventory/topology respectively.

The warm comparison uses five fresh process blocks per method/workload. Each block
discards its initial observation and measures ten more with the same client, giving
50 observations per cell. Times exclude client/process initialization and final
output. These are correlated observations from five process blocks.

| Reused client, median | Inventory | Topology |
| --- | ---: | ---: |
| Python direct HTTPS | 334.97 ms | 11.22 ms |
| Rust direct HTTPS | 337.87 ms | 10.98 ms |

Inventory variability exceeds the small difference between warm client medians.
Paired block bootstrap intervals for Python minus Rust are -33.0 to +12.4 ms for
inventory and +0.13 to +0.34 ms for topology. Five warm blocks give limited precision;
the experiment does not prove universal equivalence. Cold paired intervals are
50.4 to 82.9 ms and 63.0 to 63.9 ms. The analysis resamples process blocks, not each
correlated warm observation independently. These are descriptive percentile
bootstrap intervals, not an end-to-end service SLA.

## Preconditions caught before timing

Python 3.13 strict X.509 validation initially rejected PVE's CA for lacking keyUsage.
The client uses OpenSSL's compatible validation rules while retaining CA-chain and
hostname/IP verification. Rust trusts the same CA. Neither disables TLS verification.

A `PVEAuditor` token initially returned zero volumes, while local CLI reads returned
15. On this PVE version, image/rootdir content is filtered by `check_volume_access`,
which requires `VM.Config.Disk` per guest or `Datastore.Allocate` on the storage.
For the experiment, a temporary expiring token received `PVEAuditor` at `/` plus
`Datastore.Audit Datastore.Allocate` specifically at `/storage/local-lvm`. Audit must
also be included because the specific ACL overrides inheritance. The token thus
had a storage management privilege, although every benchmark operation was a GET.
All equality checks passed before measured rounds began; failed preflights were
not performance samples. A future production HTTP reader must preserve complete
volume visibility and cannot assume HTTP 200 means complete admission data.

## Reproduction and cleanup

The [standalone experiment](../../experiments/pve-read-benchmark/README.md) includes
both clients, the runner, block analysis and Cargo.lock. The
[JSON evidence](2026-10-02-pve-language-benchmark.json) contains all 320 measured
observations, summary distributions, environment details and measured source/binary
hashes. Rust build, Clippy and formatting checks and Python Ruff/compilation checks
passed on sandbox. No payloads or credentials are included in evidence.

Both temporary ACLs, the temporary role, the token and its credential file were
removed. A request with the revoked token returned HTTP 401. The installed
production reader hash is unchanged. No guests or networks were created or
modified, and no production transport replacement was deployed by this experiment.
