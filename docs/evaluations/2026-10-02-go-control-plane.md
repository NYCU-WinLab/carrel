# Go control plane, 0.6

The control plane is rewritten in Go with the existing MCP contract, SQLite state,
OAuth bindings and root mutation adapters. Guest readiness no longer holds the
infrastructure writer. Independent jobs can provision while an earlier guest boots;
resource admission and shared network writes remain serialized.

## PVE read experiment

Twelve randomized, interleaved trials on B09 compare the installed 0.5.1 Perl reader
with the native Go HTTPS reader. Each observation starts a fresh process and includes
Go's inventory permission check. Stable normalized data signatures match before
measurement and in every trial, including all 15 storage volumes. Raw evidence:
[read measurements](2026-10-02-go-reads.json).

| Read | Existing median | Go HTTPS median | Reduction |
| --- | ---: | ---: | ---: |
| Capacity inventory | 1.3191 s | 0.2402 s | 81.8% |
| SDN topology | 0.9882 s | 0.0162 s | 98.4% |

These timings exclude outer SSH, LVM pressure sampling, mutations and guest boot.
The main gain is querying PVE's running HTTPS service instead of repeatedly loading
PVE modules. This is not evidence that Go alone makes VM creation five times faster.
The preceding Python/Rust experiment separates language and transport effects.

The token is root-only and privilege-separated. PVEAuditor alone silently filters
volumes; the inventory path also requires Datastore.Audit and Datastore.Allocate on
local-lvm and checks both on every observation. TLS verifies the PVE CA and hostname.
Only two fixed read modes are exposed; failed reads cannot admit from stale data.

## Validation

The native suite covers 79 frozen Python behavior cases, MCP HTTP discovery/calls,
tenant isolation, JWT/PKCE/offline renewal, durable restart checkpoints, retry identity,
client cancellation, concurrent provisioning, pending capacity reservations,
suspension during readiness, rollback preserving existing resources and a complete
SQLite/config/certificate-link backup roundtrip. Go race tests and vet pass.
The legacy Python suite remains as the reference/adaptor safety suite.

Display capacity uses a two-second timestamped observation cache with singleflight.
Allocation always obtains fresh physical data and current reservations. Network-only
plans skip compute inventory. Storage-retention accounting moves off ordinary creation
and reconciliation into maintenance and snapshot operations. SSH connections are reused.

## Rollout

Live Go service acceptance and end-to-end timing will be recorded after the reviewed
upgrade. The read experiment itself made no guest/network changes. The existing
member VM dev-01 is outside the disposable acceptance scope. No warm pool is used.
