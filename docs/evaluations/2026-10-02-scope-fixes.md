# Member scope corrections (0.8.0, 2026-10-02)

The v0.7.2 audit findings A1 through A8 are corrected through existing tools. This release
adds an existing-machine ingress field to deployment tools and keeps the 40-tool member surface.
It introduces no warm pool, guest execution API, new language or separate intent service.

## Outcomes

| Finding | Corrected outcome |
|---|---|
| A1 | Machine summaries retain IP, ingress and named NICs. Grant lists resolve machine names and usable endpoints. |
| A2 | Targeted get observes power and SSH. Reports expire after 120 seconds; previous-boot or stale health becomes unknown. Lists do not probe every guest. |
| A3 | Stopped/paused managed NIC attachment succeeds as configuration, preserves power and reports pending guest verification. Active guests require the reported interface. |
| A4 | Application warm-up has a persistent, bounded 120-second deadline after initialization. Failed bootstrap remains immediate; failed check indices survive timeout. |
| A5 | Quota requests enforce total-limit/address constraints and tenant-scoped idempotency. Approval rechecks expiry and current limits; approval and expiry are transactional. |
| A6 | Recovery distinguishes input changes, capacity, prerequisites, guest repair and infrastructure retry. Deterministic input conflicts are not requeued unchanged. Retained machine access is included. |
| A7 | Confirmed snapshot, network, domain, port and peer removal returns deleted. Partial cleanup retains diagnostics. |
| A8 | Deployment access entries change existing ingress and connection grants without rebuilding. Preview explains connectivity impact; rollback respects policy ownership and allocation identity. |

Disk resize now reports allocated capacity separately from unverified guest filesystem growth,
with owner SSH inspection/growth instructions. Certificate preparation persists a publication
reservation before DNS/ACME work outside the infrastructure writer. Certbot remains serialized
on its shared work directories. Finalization revalidates identities and tenant access. Node
failures return bounded codes and operation/request correlation without arbitrary backend output.

## Automated validation

All development validation runs on sandbox VM104. The local Mac only edits and uses git.

- Full Go race suite, including 79 legacy parity fixtures with explicit normalization of the
  intentionally changed presentation/observation fields. New behavior has separate regressions.
- Direct/composed stopped and paused NIC attachment; active interface verification; stale/failed
  health and previous-boot reports; no SSH fan-out on list.
- Failed application sample followed by health, persistent failure cleanup, and saved application
  deadline recovery without replaying a machine mutation.
- Quota deduplication after approval, invalid limits, expired approval and injected decision-write
  failure proving quota rollback. Typed deterministic recovery and definitive removal receipts.
- Existing policy preview/apply/rollback, foreign-tenant rejection, experiment NIC rejection and
  protection of newer policy owners/replacement allocations.
- Blocked certificate preparation with an unrelated power job completing while the target-machine
  job remains ordered. This is a deterministic scheduling test, not a production ACME latency SLA.
- Go vet, static Linux builds, 178 Python reference tests, deployment lint and script compilation.

## Live acceptance

Live evidence is in [the JSON record](2026-10-02-scope-fixes.json). Three disposable guests used
VMIDs 10302/10303, reusing 10302 after deletion. Existing ubuntu and sysinfo-demo were preserved.

| Scenario | Observed result |
|---|---|
| Warm-up | Debian with an intentional 25-second application delay completed in 58.421 seconds. Ubuntu deployment was observed with fresh failed app health, verified SSH and state initializing, then succeeded in 110.915 seconds without rollback. These include deliberately delayed test services and guest reporting, not default creation benchmarks. |
| Existing isolation | Restricting the running VM and publishing HTTPS completed in 11.586 seconds. The allowed source received the expected body; another same-tenant source timed out. Owner SSH and public HTTPS remained usable. Switching back preserved existing grants until explicit revocation. |
| Offline networking | Direct attachment to a stopped VM took 6.322 seconds and returned pending_guest_start. Composed attachment while paused took 7.281 seconds and returned pending_guest_resume. A fresh post-change interface report completed verification on resume. VM/CT private HTTP and SSH traffic worked in both directions. |
| Paused removal | Initial live hot-unplug exposed a PVE pending-delete failure. After the correction, rejection took about 2 seconds, returned resolve_prerequisite and left PVE net0/net1 with no pending fields. Resume followed by retry of the same operation succeeded. |
| Deletion/recovery | Snapshot, peer, private network, public port and HTTPS removal returned deleted. A duplicate machine name returned revise_request; retry kept attempts=1. A request for 11 public ports was rejected before creating an approval request. |
| Capacity | Both prepared VM images accepted 20 to 25 GiB block growth while their filesystems initially stayed unchanged. Debian used ext4 on sda3, grew online with owner growpart/resize2fs, and retained 26,206,609,408 filesystem bytes after reboot. Ubuntu used ext4 on sda1 and automatically grew to 24,883,167,232 filesystem bytes after the authorized reboot. |

The current tenant wildcard certificate was reused for live publication. First-issuance queue
isolation is covered by the blocked-issuer scheduling regression, not a live ACME timing claim.
Operation durations include time between retries. One stopped-VM start included installation of
a persistent owner test service after a transient fixture service disappeared on shutdown; its
62.331-second total is not a normal startup benchmark. The minimal CT lacked curl, so private HTTP
was verified using bash TCP instead of installing dependencies. A first SSH connection to the
existing demo accepted its previously unknown host key; no host-key checking was disabled.

Cleanup restored the original 17 PVE volumes, with no 10302/10303 volumes, two machines, 70 GiB of
allocated disk, no test NICs/networks/peers/snapshots, two original SSH grants and the original demo
HTTPS grant. Task aliases and their dedicated known-host files were removed. Both original owner
SSH logins passed and the existing demo returned HTTP 200. MCP authentication survived control
restarts; deployment checks preserved all seven OAuth clients.

The final observation guard also distinguishes a missing first report from a previous-boot report.
This was found while observing Ubuntu initialization and is covered by a regression.

## Boundaries

Publication routing is not application health. SSH readiness verifies a banner, not owner-key
login. Offline NIC configuration is not guest verification. Allocated VM disk space is not a
filesystem-size claim. Existing peer/public grants survive an ingress-mode change and must be
removed explicitly if the user's isolation intent excludes them.

Saved-key edits affect future guests. Console/lost-key recovery is deferred. Control backups
exclude tenant disks; full tenant disaster recovery and clean installation acceptance remain
separate gates. Custom images and multi-node scheduling remain outside this release.

Live follow-up found that paused NIC hot-unplug writes pending PVE configuration before failing.
The final adapter/control path rejects that case before mutation with a resume/shutdown prerequisite.
Prepared Debian uses /dev/sda3 in this run; resize guidance now uses the observed partition number.
