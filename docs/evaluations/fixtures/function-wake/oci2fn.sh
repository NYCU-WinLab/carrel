#!/bin/bash
# OCI image -> rootfs -> boot -> snapshot. Prints seconds per stage. Run as root.
# usage: oci2fn.sh <image> <name> <guest MiB>
set -euo pipefail
IMG=$1; NAME=$2; MEM=${3:-512}
W=/opt/fnlab; D=$W/fn-$NAME
now() { date +%s.%N; }
lap() { awk -v a="$T" -v b="$(now)" -v n="$1" 'BEGIN {printf "%-34s %6.2f s\n", n, b-a}'; T=$(now); }
START=$(now); T=$START

rm -rf "$D"; mkdir -p "$D/root"
cid=$(docker create "$IMG")
docker export "$cid" | tar -x -C "$D/root"
lap "export image filesystem"

# init: mounts, network, then the image's own entrypoint and command
mkdir -p "$D/root/.fn" && cp /bin/busybox "$D/root/.fn/busybox"   # busybox picks its applet from its own file name
docker inspect "$cid" | python3 -c '
import json, shlex, sys
c = json.load(sys.stdin)[0]["Config"]
cmd = (c.get("Entrypoint") or []) + (c.get("Cmd") or [])
out = ["#!/.fn/busybox sh", "B=/.fn/busybox",
       "$B mount -t proc proc /proc", "$B mount -t sysfs sys /sys",
       "$B mount -t devtmpfs dev /dev 2>/dev/null", "$B mkdir -p /dev/shm /dev/pts",
       "$B mount -t tmpfs tmpfs /dev/shm", "$B mount -t devpts devpts /dev/pts",
       "$B mount -t tmpfs tmpfs /tmp", "$B mount -t tmpfs tmpfs /run",
       "$B ip link set lo up", "$B ip addr add 172.16.0.2/30 dev eth0", "$B ip link set eth0 up",
       "export HOME=/root"]
out += ["export " + shlex.quote(e) for e in c.get("Env") or []]
out += ["cd " + shlex.quote(c.get("WorkingDir") or "/"), "exec " + " ".join(map(shlex.quote, cmd))]
print("\n".join(out))' > "$D/root/fn-init"
chmod +x "$D/root/fn-init"
docker rm "$cid" >/dev/null

SIZE=$(( $(du -sm "$D/root" | cut -f1) * 12 / 10 + 50 ))
truncate -s ${SIZE}M "$D/rootfs.ext4"
/usr/sbin/mkfs.ext4 -q -d "$D/root" "$D/rootfs.ext4"
rm -rf "$D/root"
lap "build rootfs (${SIZE} MiB)"

cd /tmp && MEM=$MEM ROOTFS=$D/rootfs.ext4 SNAP=fn-$NAME/snap INIT=/fn-init SETTLE=${SETTLE:-1} python3 -c '
import bench
boot, snap = bench.make_snapshot()
print("%-34s %6.2f s" % ("cold boot -> first HTTP 200", boot))
print("%-34s %6.2f s" % ("pause + write snapshot", snap))'
awk -v a="$START" -v b="$(now)" 'BEGIN {printf "%-34s %6.2f s (includes settle wait)\n", "TOTAL image -> ready to wake", b-a}'
