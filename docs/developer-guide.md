# Developer guide

For people changing carrel. Pull request, review and label rules are in [AGENTS.md](../AGENTS.md); the design is in [PLAN.md](../PLAN.md).

## Build and test

The runtime is Go (1.26 or newer; CI uses 1.27.1). Run builds and tests in a development VM:

```sh
go test -race ./... -count=1
go vet ./...
for cmd in carrel carrel-agent carrel-deployd carrel-fetch; do CGO_ENABLED=0 go build -trimpath -o dist/$cmd ./cmd/$cmd; done
uv sync --locked
uv run pytest -q
uv run ruff check tests
python3 -m compileall -q scripts
```

Go owns the MCP server, OAuth, durable jobs, admission, state and backups. The existing bounded
Python node adapter, gateway sync, backup target and guest reporter remain. Go issues certificates itself
(ACME DNS-01 through Cloudflare). The Python tests cover these scripts; the Go tests cover the
service. The live wire contract is `internal/carrel/contract.json`.

`/mcp` lists every tool the caller may use (admins also see the admin toolset). A client that loads every listed
tool on every turn can ask for fewer with `?toolsets=core` (under 50 tools, under 60 KB) plus any of
`machines,network,apps,services`, or the `X-Carrel-Toolsets` header. Claude Code defers tool loading and can call
only listed tools, so it should keep the default. Toolsets only shape the list: every tool the caller may use stays
callable by name for clients that allow it. `/mcp/read-only` registers and lists
`readOnlyHint` tools plus `whoami`. The admin filter applies on every endpoint. Toolsets are defined in `contract.json`.

`/mcp/read-only` only filters the tool list and the call set. It is not a credential boundary: both endpoints accept the
same bearer token (audience `carrel-mcp`, no resource check), so a token obtained for `/mcp/read-only` also works on
`/mcp`. Do not use it to delegate read-only access to another party.

## Plugin contract

A plugin runs one operation under one idempotency key. Carrel sends the same key on every start and every `get` of that run, also across its own restarts, a re-queue and a retry whose run may still be going. Only a run known to have ended gives way to a new key.

Keep operations by key:

- A plugin must keep each operation by its key, also across the plugin's own restarts. Save the run under the key before you send the work, and keep it until the run has ended and carrel has read the outcome.
- If a plugin loses a key, `get` answers `not_found`, and carrel treats that as "no record of the run". The operation fails with `plugin_failed` and the recovery `retry`, and a retry starts the same key again. The work can then run twice, so a plugin that cannot keep its keys cannot promise a single run.

Retry after a migrate:

- A retry of an operation whose last run's fate is unknown accepts only the node that ran it (the `plug["node"] != node` branch in `internal/carrel/plugin_tools.go`). Reason: running it on another node could run the work twice.
- While the machine is on another node, the retry waits for the first node to report the plugin again, then fails with `unsupported` and the recovery `retry_infrastructure`.
- A run known to have ended (refused at its first start, or finished) does not have this limit: the next run takes a new key and any node that has the plugin.
