# freeze

The carrel plugin for parking machines (#664): `machine_freeze` and `machine_thaw`, through the
Proxmox VE HTTP API. A frozen machine is a record of the `frozen` object kind; it charges
`frozen_gb` and keeps the machine's name, address, domains and ports.

This is the skeleton. It declares the two operations and the object kind and probes the site, and
no operation does work yet.

## Settings

The plugin reads its own environment, never the control plane config:

| Variable | Meaning |
|---|---|
| `CARREL_PVE_URL` | `https://localhost:8006` unless set |
| `CARREL_PVE_TOKEN` | `PVEAPIToken=<user>!<token>=<secret>` |
| `CARREL_PVE_NODE` | the PVE node name |
| `CARREL_PVE_CA` | `/etc/carrel/plugins/freeze-ca.pem` unless set |
| `CARREL_BACKUP_STORAGE` | the backup storage to freeze to |

Probe says unsupported when no backup storage is set, or when the token lacks `VM.Audit` and
`VM.Backup` on `/vms`, or `Datastore.Audit` and `Datastore.AllocateSpace` on the storage.

## Build

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=1.0.0" -o plugin ./plugins/freeze/cmd/freeze
tar -czf freeze.tar.gz plugin
```

## Test

```sh
go test -race ./plugins/freeze/
```
