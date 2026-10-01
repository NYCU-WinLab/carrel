# Carrel 0.4.2 native agent acceptance

Carrel's existing machine, connection and publication specification works with natural-language
requests. This acceptance closes the missing native-agent follow-up to 0.4.0. It fixes observable
discovery and recovery problems without introducing new tools or another orchestration layer.

## Interface changes

- `whoami` and `catalog_get` return `service.version`. The model no longer needs access to MCP
  handshake metadata or local client configuration to identify the running version.
- `deployment_plan` returns a next action instead of an internal execution sequence. It is the
  complete preview; the agent should submit one `deployment_apply` when execution is authorized.
- `machine_get` returns timestamped `runtime.power_state` and `uptime_seconds`, replacing the raw
  hypervisor payload, including block statistics, host interface names and QEMU implementation data.
  Detailed usage remains available through `machine_metrics`.
- Catalog and tool descriptions identify VM/CT setup restrictions. Invalid jobs with no remaining
  reservations return `revise_request`, avoiding retries with the same invalid arguments.

The member tool count remains 40. Normal application requests use machines, connections and
publications. Additional networks and NICs remain available for explicit network experiments.
Default tenant-wide connectivity is unchanged; isolation requires `network_access=restricted`.

## Paired natural-language runs

Codex CLI 0.159.3 used the existing `gpt-6-astra` model, `github_copilot` provider and `xhigh` effort.
No model, provider or effort override was supplied. Each case started in an empty workspace using
saved Carrel OAuth credentials. Prompts described the task without naming an expected tool.
The guard allowed queries and previews only and prohibited credential reads, SSH, direct API
workarounds and subagents. Missing-key creation was continued later with an ephemeral public key.

| Request | 0.4.1 MCP calls | 0.4.2 MCP calls | Observed result |
| --- | ---: | ---: | --- |
| Exact version and supported tasks | 4 | 2 | Reports 0.4.2 from ordinary tools; no speculative deployment |
| Ubuntu VM, 2 vCPU, 2 GiB, 50 GiB, no key yet | 3 | 3 | Checks quota/capacity and identifies the missing public key |
| Two VMs, only app to db TCP 5432, app HTTPS | 4 | 3 | One composed preview with restricted ingress |
| Publish an existing website | 4 | 3 | One publication preview, no new machine |
| Total | 15 | 11 | No repeated plan plus apply-dry-run |

These are one paired run per case, not statistical performance evidence. Existing user instructions
remained active: some publication runs read a local FDE skill or operations memory. Call counts
exclude those reads, which are included separately in the trace. No native MCP call failed. Exact prompts, ordered calls, session IDs and
final responses are in the [JSON evidence](2026-10-01-agent-intent.json).

The paired runs and three live flows used the initial 0.4.2 build. Their machine queries exposed
an additional raw-hypervisor payload problem. The final build removes that payload; a fresh MCP
query verified the compact runtime response, and the independent live probes below ran after
that final deployment. Both build hashes are recorded in the JSON evidence.

## Actual resource acceptance

The native Codex sessions received explicit permission to operate only the named disposable
resources. All provisioning and application setup went through Carrel MCP. The agent did not
select hosts, bridges, VLANs, gateways or proxies, and did not assemble network tools manually.

1. Continue the missing-key VM request: the agent supplied the key inline, previewed the updated
   specification, applied it, waited for success and returned the public SSH command.
2. Publish the existing `intent-web:80`: the agent applied a publication-only specification and
   waited for HTTPS readiness without allocating another machine.
3. Create the app/database test stack: one deployment installed nginx and a Python HTTP test
   listener on TCP 5432, configured systemd startup and local health checks, enforced the source
   grant, and published the app over HTTPS. The database role was a TCP test service, not PostgreSQL.

The agent correctly distinguished configured routing from an externally verified application.
Independent probes from sandbox VM 104 then verified:

- Owner-key public SSH to all four temporary VMs.
- Both public HTTPS endpoints return HTTP 200 and the expected body with normal TLS validation.
- App to database TCP 5432 succeeds.
- App to TCP 5433, app to UDP 5432, and another same-tenant VM to database TCP 5432 time out.
  Positive controls first verified listeners on all three destination protocol/port combinations.

Cross-tenant isolation was previously exercised in the [0.4.0 acceptance](2026-10-01-intent.md);
this run checks the ordinary same-tenant intent flow and does not claim to repeat that scenario.

## Validation and delivery

The final source passed 138 tests, Ruff lint/format, script compilation, locked dependency checks
and wheel build on sandbox VM 104 using Python 3.13.15. The control service's installed package
and source hashes match the wheel. `whoami` reports 0.4.2. The existing Codex offline OAuth binding
survived both updates, and discovery still exposes 40 member tools.

Protected application/database rollback archives were created before each deployment. Test
resources and temporary credentials are removed after acceptance; audit and operation history
remain. Cleanup state is recorded in the JSON evidence. Existing staging VM 190 is preserved.

This change does not add custom images, GPU allocation, backup expansion or multi-node scheduling.
The result is an accepted agent workflow for the existing single-node service.
