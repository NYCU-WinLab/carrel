# PVE read-path benchmark

This isolated experiment compares process/transport implementations for the fixed
Carrel inventory and tenant topology reads on B09 `carrel01`. It is not a production
adapter, and does not change the installed service or allocate guests/networks.

The methods are Python with `pvesh`, Rust with `pvesh`, Python with the installed
0.5.1 batched Perl reader, Python with HTTPS (`http.client`/OpenSSL), and Rust with
HTTPS (`reqwest`/rustls). Both CLI implementations use four concurrent subnet reads,
matching the legacy topology adapter. Inventory is sequential in all methods.
Both HTTP implementations read topology sequentially and reuse their connection.

`run.py` first checks matching normalized allocations and network configuration.
It then interleaves 12 rounds of fresh client processes with a fixed random seed.
These wall times include client startup, imports, TLS/client setup, all reads,
JSON parsing/output and exit. They exclude SSH into the node. No OS page caches,
server caches or PVE daemons are restarted or flushed.

The reused-client comparison has five process blocks per HTTP implementation and
workload, each discarding its first observation and timing ten more with the same
client. Those samples exclude process/client initialization and final JSON output.
Block samples are correlated, so 50 observations are not 50 independent processes.
All calls still read the live APIs; no client result cache is present.

Results contain timings, summary statistics and validation hashes, not raw guest
inventory or authentication material. Volatile CPU load, free memory, storage used
and uptime are excluded from equality checks; allocation sizes, resource identities,
hardware totals and complete network configuration are compared. This experiment
does not measure LVM pressure sampling, admission policy, mutation/boot readiness,
multi-user queueing, full MCP latency or end-to-end VM creation.

## Reproduction

Build only in a development VM. This run used sandbox VM 104, Rust 1.98.1 and the
locked dependency graph. A static musl binary avoids installing a Rust runtime or
linker dependencies on the PVE host.

```sh
rustup target add x86_64-unknown-linux-musl
# Install musl-tools in the development VM if musl-gcc is unavailable.
export CARGO_TARGET_DIR="$PWD/target"
cargo build --locked --release --target x86_64-unknown-linux-musl -j 4
cargo clippy --locked --release --target x86_64-unknown-linux-musl -j 4 -- -D warnings
```

Copy `client.py`, `run.py` and the resulting `carrel-pve-read-benchmark` executable
to a task-specific directory on the PVE node. Keep the existing installed
`/usr/local/lib/carrel/pve-read.pl` in place. The benchmark invokes only its read
modes; it never invokes reconciliation or other mutating adapters.

An authorized administrator must supply `config.json` with mode 0600 in that task
directory. Use a temporary, expiring, privilege-separated PVE API token with
`PVEAuditor` at `/` and a temporary role containing `Datastore.Audit Datastore.Allocate` at
`/storage/local-lvm`. Remove both ACLs, the token, role and credential file after
the run. Never put its value in command arguments, terminal output, source control
or benchmark results.

The specific storage ACL includes Audit because it overrides inherited permissions.
The extra Allocate privilege is necessary on this PVE version: `PVEAuditor` alone
returns an empty image/rootdir list because `check_volume_access` also requires
`VM.Config.Disk` per guest or `Datastore.Allocate` on the storage. This token therefore
has a storage management privilege even though the benchmark sends only GETs.
The equality preflight caught the empty list before timing began. Do not treat a
successful HTTP response with a filtered volume list as complete admission data.

```json
{
  "base": "https://127.0.0.1:8006",
  "ca": "/etc/pve/pve-root-ca.pem",
  "authorization": "PVEAPIToken=<token-id>=<secret>"
}
```

Both HTTP clients verify the PVE CA and destination hostname/IP. Python 3.13's
strict X.509 mode rejects the PVE-generated CA because it lacks a keyUsage
extension. The comparator uses OpenSSL's compatible validation rules while
retaining certificate-chain and hostname verification. Verification is never
disabled. The Rust client trusts the same CA and uses rustls validation.

Run `python3 run.py` from the node. It aborts on HTTP/CLI failure, allocation/config
drift or differing normalized payloads. `results.json` contains the full completed
run; `partial.json` is only a progress checkpoint. Check the exit status before
using results. The comparison measures these two concrete client stacks, not a
universal ranking of Python and Rust.

Copy the completed result back to the development VM and run
`python3 analyze.py results.json` for paired Python-minus-Rust differences and
descriptive percentile bootstrap intervals. Warm comparisons resample the five
process-block medians, not the 50 correlated observations independently.
