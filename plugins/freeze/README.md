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
carrel does not route to the plugin until the last sub-issue of #664.

`machine_thaw` restores the backup under the old VMID (`qmrestore` or `vzrestore`, every disk to the
site's guest storage, as the node agent does), checks that the guest is there, unlocked and named as the frozen record
says, and only then removes the backup. carrel sends the frozen record's facts as the machine:
`vmid`, `kind`, `name`, `backup_volid`, `backup_storage` and `backup_note`. A restore that fails
keeps the backup, and a half it left locked is removed. PVE destroys a locked guest only with
`skiplock`, which only `root@pam` may set and never an API token: when it refuses, the thaw fails
with the backup kept and says so, and an admin on the node removes the half with
`qm unlock <vmid> && qm destroy <vmid> --purge` (`pct` for a container) and asks again. Unlocking
alone is not enough: an unlocked half looks like the machine or like another guest. A thaw that
finds a guest with the machine's name while the backup is still on the storage, and did not restore
it in its own run, refuses and keeps the backup; an admin removes the guest as above if it is a
half, or removes the backup with `frozen_delete` if it is the machine. A backup that cannot be removed after the
restore does not fail the thaw: the result carries `thaw_backup` (`volid`, `note`) so `machine_delete`
can remove it later with `frozen_delete`. A thaw asked again after it finished changes nothing.

Two operations are for admins only. `frozen_delete` removes a frozen machine's backup (`volid`, and
`note` to match the record), and with `vmid`, `kind` and `name` first removes a cut-off restore of
that machine. `backup_sweep` lists the freeze backups no record names (`keep` notes, `keep_volids`)
and, only when `older_than` is given, removes the listed ones older than that many seconds. Both
touch only backups whose notes start with `carrel-freeze`, on the site's backup storage. Freeze notes
do not name the site, so two sites on one datastore must not both sweep with `older_than`.

## Settings

The plugin reads its own environment, never the control plane config:

| Variable | Meaning |
|---|---|
| `CARREL_PVE_URL` | `https://localhost:8006` unless set |
| `CARREL_PVE_TOKEN` | `PVEAPIToken=<user>!<token>=<secret>` |
| `CARREL_PVE_NODE` | the PVE node name |
| `CARREL_PVE_CA` | `/etc/carrel/plugins/freeze-ca.pem` unless set |
| `CARREL_BACKUP_STORAGE` | the backup storage to freeze to |
| `CARREL_GUEST_STORAGE` | the site's guest storage (the node agent's `storage`), where a thaw restores the disks |
| `CARREL_FREEZE_VERIFY_WAIT` | seconds to wait for a backup's verification, 0 to 3600, `1800` unless set |

Probe says unsupported when no backup storage or guest storage is set, or when the token lacks `VM.Audit`,
`VM.Backup`, `VM.Allocate` and `VM.Config.Options` on `/vms`, `Datastore.Audit`,
`Datastore.AllocateSpace` and `Datastore.Allocate` on the storage, `Datastore.AllocateSpace` on the
guest storage, or `Sys.Audit` on
`/nodes/<node>`. `VM.Config.Options` clears the machine's `onboot` before the backup; `Sys.Audit`
lets the plugin see starts of the machine by any user, which prove it unchanged before removal.

## Build

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=1.0.0" -o plugin ./plugins/freeze/cmd/freeze
tar -czf freeze.tar.gz plugin
```

## Test

```sh
go test -race ./plugins/freeze/
```
