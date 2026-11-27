# freeze

The carrel plugin for parking machines (#664): `machine_freeze` and `machine_thaw`, through the
Proxmox VE HTTP API. A frozen machine is a record of the `frozen` object kind; it charges
`frozen_gb` and keeps the machine's name, address, domains and ports.

`machine_freeze` runs: the plugin takes a stop-mode backup of the stopped machine to the backup
storage (`vzdump`), waits for the backup server to verify it, protects it, then removes the machine
from the node. A failed, unverified or cancelled backup is removed and the machine stays. If the
removal itself fails the backup is kept, since a half removed machine leaves it the only whole copy.
The PVE task's UPID is stored under the idempotency key in `$STATE_DIRECTORY`, so a restarted plugin
finds the task again. The core checks the site's release list (public IPs, special ports and
domains) before it calls the plugin; the plugin refuses a running machine and one with snapshots.
`machine_thaw` does not run yet. carrel does not route to the plugin until the last sub-issue of
#664.

## Settings

The plugin reads its own environment, never the control plane config:

| Variable | Meaning |
|---|---|
| `CARREL_PVE_URL` | `https://localhost:8006` unless set |
| `CARREL_PVE_TOKEN` | `PVEAPIToken=<user>!<token>=<secret>` |
| `CARREL_PVE_NODE` | the PVE node name |
| `CARREL_PVE_CA` | `/etc/carrel/plugins/freeze-ca.pem` unless set |
| `CARREL_BACKUP_STORAGE` | the backup storage to freeze to |
| `CARREL_FREEZE_VERIFY_WAIT` | seconds to wait for a backup's verification, 0 to 3600, `1800` unless set |

Probe says unsupported when no backup storage is set, or when the token lacks `VM.Audit`,
`VM.Backup` and `VM.Allocate` on `/vms`, or `Datastore.Audit`, `Datastore.AllocateSpace` and
`Datastore.Allocate` on the storage.

## Build

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=1.0.0" -o plugin ./plugins/freeze/cmd/freeze
tar -czf freeze.tar.gz plugin
```

## Test

```sh
go test -race ./plugins/freeze/
```
