# snapshot

The carrel plugin for disk snapshots (#663): `snapshot_create`, `snapshot_delete`,
`snapshot_rollback` and `snapshot_list`, through the Proxmox VE HTTP API.

carrel keeps the record of each snapshot, charges the tenant's `snapshots` and `snapshot_gb`
quota and stops the guest around a rollback. The plugin starts the PVE task and follows it. It
keeps each run in `$STATE_DIRECTORY` with the task's UPID, so a restart finds the task again.

## Install

See "The snapshot plugin" in [`docs/operator-handbook.md`](../../docs/operator-handbook.md):
run `scripts/configure-snapshot-plugin.py` on each node, then list the release's
`snapshot.tar.gz` in the site file with `network: true` and `env_file: true`.

## Build

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=1.0.0" -o plugin ./plugins/snapshot/cmd/plugin
tar -czf snapshot.tar.gz plugin
```

## Test

```sh
go test -race ./plugins/snapshot/
```

The tests run the plugin against a fake PVE API over TLS.
