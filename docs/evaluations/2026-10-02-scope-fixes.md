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

Pending deployment of the merged runtime. Record disposable guest operations, networking,
filesystem growth and complete cleanup here before publishing the release acceptance.

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
