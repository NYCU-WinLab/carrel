# Developer guide

For people changing carrel. Pull request, review and label rules are in [AGENTS.md](../AGENTS.md); the design is in [PLAN.md](../PLAN.md).

## Build and test

The runtime is Go (1.26 or newer; CI uses 1.27.1). Run builds and tests in a development VM:

```sh
go test -race ./... -count=1
go vet ./...
CGO_ENABLED=0 go build -trimpath -o dist/carrel ./cmd/carrel
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
`machines,network,apps,functions`, or the `X-Carrel-Toolsets` header. Claude Code defers tool loading and can call
only listed tools, so it should keep the default. Toolsets only shape the list: every tool the caller may use stays
callable by name for clients that allow it. `/mcp/read-only` registers and lists
`readOnlyHint` tools plus `whoami`. The admin filter applies on every endpoint. Toolsets are defined in `contract.json`.

`/mcp/read-only` only filters the tool list and the call set. It is not a credential boundary: both endpoints accept the
same bearer token (audience `carrel-mcp`, no resource check), so a token obtained for `/mcp/read-only` also works on
`/mcp`. Do not use it to delegate read-only access to another party.
