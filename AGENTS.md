# AGENTS.md

Rules for anyone changing this repository, people and coding agents alike. What carrel is and how
it is designed lives in `PLAN.md`; how to use and run it lives in `README.md`.

## Where to work

- Edit anywhere. Build and test in a development VM, not on a laptop: the tests use the race
  detector, and some Python tests need Linux tools.
- Go 1.26 or newer (CI uses 1.27.1). Python through `uv`.

## Checks

CI (`.github/workflows/check.yml`) runs these on every pull request. Run them before you push:

```sh
test -z "$(gofmt -l cmd internal plugins)"
go vet ./...
go test ./... -count=1
go test -race -count=1 ./cmd/carrel-deployd/
uv sync --locked
uv run ruff check tests scripts
uv run ruff format --check tests
uv run pytest -q
python3 -m compileall -q scripts
```

A push to `main` also runs `go test -race ./...`. The `alint` check runs the house rules on the
diff.

## Pull requests

1. One issue, one branch, one pull request. The branch is `<type>/<slug>`.
2. The title is a Conventional Commit (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`),
   because releases are cut from titles (PLAN 10.4).
3. The body says `Closes #n` only when the pull request finishes the issue. Partial work says
   `Part of #n`, so the issue stays open.
4. The body has a Verification section: what you ran and what you saw.
5. Squash merge once every check passes. Delete the branch.

Release Please keeps one release pull request open with the next version and `CHANGELOG.md`.
Merging it tags `vX.Y.Z` and bumps `Version` in `internal/carrel/value.go`; never edit that line
by hand. A release does not deploy.

## High risk changes

A change is high risk when a mistake leaks access, loses data or acts outside carrel: auth and
tokens, tenant isolation and firewall rules, quota and admission, database schema, deletes and
cleanup, DNS and certificates, public ports and addresses, anything the node programs run as root.

- Label the issue and the pull request `risk:high`.
- A high risk pull request needs a second reviewer before it merges (label `needs-review`).
- Rate a review finding against today's real tenants and data. A path production cannot reach is
  noted in the pull request, not filed as a new issue.

## Labels and milestones

| Label | Meaning |
|---|---|
| `size:s`, `size:m`, `size:l` | scope: 1 or 2 files, up to about 5, more than 5 or more than 1 module |
| `risk:low`, `risk:high` | see above |
| `agent:hold` | automated agents leave the issue alone; a person removes it to release the work |
| `agent:case` | an automated issue table is handling it |
| `later` | decided not now; the issue says what has to change first |

Milestones are numbered themes, done in order: `1 Docs and positioning` first.

## Deploying

A merge does not deploy. An admin with SSH access to the first exit node builds the binaries in a
development VM and runs `scripts/deploy-go.py` from a workstation that reaches that node
(README, "Install a site"). The script installs the control plane and the node programs, checks
`/healthz` for the new version and restores the previous binaries if the check fails. It never
restores the database.

## The tool contract

`internal/carrel/contract.json` is the live MCP contract: tool names, schemas, toolsets. A new or
renamed tool appears in a client only after the client reconnects.

The HTTP routes outside MCP are described in `internal/carrel/openapi.json`, served at
`/openapi.json`. A test fails when a route is registered without an entry, so add the entry with
the route.

## Writing

Everything in the repository and on GitHub is in English: code comments, docs, issues, pull
requests. Use one name for one thing; PLAN 14 lists the names.
