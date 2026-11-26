# Plugin mechanism prototypes (#563)

The code behind [the evaluation](../2026-11-26-plugin-mechanism.md). It is its own Go module, so the
service's `go.mod` and release build do not take grpc or go-plugin.

| Path | What |
|---|---|
| `proto/plugin.proto` | Contract 2: Describe, Probe, StartOperation, GetOperation, Cancel |
| `proto/v1/plugin.proto` | Contract 1: the same, before `Operation.message` |
| `task/` | A stand-in for a Proxmox task: a worker in its own session, known by an id |
| `snapshot/` | The plugin: one record per idempotency key on disk |
| `cmd/gp-host`, `cmd/gp-plugin`, `cmd/gp-plugin-v1` | hashicorp/go-plugin v1.8.0 |
| `cmd/svc-host`, `cmd/svc-plugin`, `cmd/svc-plugin-v1` | The plugin as a service on a unix socket |
| `python/plugin.py` | The plugin in Python, for both mechanisms |
| `scenarios/` | The scenarios, with real SIGKILLs |

## Run

On Linux, from this directory:

```sh
mkdir -p bin && for c in cmd/*; do go build -o bin/ ./$c; done
uv venv python/.venv
uv pip install -p python/.venv grpcio==1.76.0 grpcio-health-checking==1.76.0
RESULTS=results.json go test ./scenarios -count=1 -v
```

To change a contract, regenerate the code:

```sh
uvx --from grpcio-tools==1.76.0 python -m grpc_tools.protoc -Iproto \
  --go_out=gen/pluginpb --go_opt=paths=source_relative \
  --go-grpc_out=gen/pluginpb --go-grpc_opt=paths=source_relative \
  --python_out=python --grpc_python_out=python plugin.proto
uvx --from grpcio-tools==1.76.0 python -m grpc_tools.protoc -Iproto/v1 \
  --go_out=gen --go_opt=module=github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/gen \
  --go-grpc_out=gen --go-grpc_opt=module=github.com/NYCU-WinLab/carrel/docs/evaluations/plugin-mechanism/gen \
  plugin.proto
```

`protoc-gen-go` v1.36.12 and `protoc-gen-go-grpc` v1.6.0 must be on `PATH`.
