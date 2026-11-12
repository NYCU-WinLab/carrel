#!/bin/bash
# Restore K copies of the same Python function, each in its own network namespace, and measure memory.
set -uo pipefail
K=${K:-30}
avail() { awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo; }
cleanup() { pkill -f "bench.py hold"; pkill firecracker; sleep 0.5; for i in $(seq 1 $K); do ip netns del fn$i 2>/dev/null; done; rm -f /tmp/fc-*.sock /tmp/hold-*.out; }
cleanup 2>/dev/null
cat /opt/fnlab/pysnap.mem > /dev/null   # snapshot in page cache, as on a warm host
HOSTMAC=$(cat /sys/class/net/tap0/address)
B=$(avail); echo "MemAvailable before: $B MiB"
for i in $(seq 1 $K); do
  ip netns add fn$i
  ip -n fn$i link set lo up
  ip -n fn$i tuntap add dev tap0 mode tap
  ip -n fn$i link set tap0 address $HOSTMAC   # the snapshot's ARP cache points at the original tap
  ip -n fn$i addr add 172.16.0.1/30 dev tap0
  ip -n fn$i link set tap0 up
  ip -n fn$i neigh replace 172.16.0.2 lladdr 06:00:AC:10:00:02 dev tap0 nud permanent
  ip netns exec fn$i env SOCK=/tmp/fc-$i.sock MEM=512 SNAP=pysnap python3 /tmp/bench.py hold > /tmp/hold-$i.out 2>&1 &
  for _ in $(seq 1 3000); do [ -s /tmp/hold-$i.out ] && break; sleep 0.01; done
done
sleep 2
A=$(avail); N=$(pgrep -c firecracker)
echo "running microVMs: $N"
echo "MemAvailable after:  $A MiB -> $(( (B - A) / (N > 0 ? N : 1) )) MiB per sleeping-but-loaded function"
echo "restore ms per VM (in launch order):"; cut -d' ' -f1 /tmp/hold-*.out | tr '\n' ' '; echo
cut -d' ' -f1 /tmp/hold-*.out | sort -n | awk '{a[NR]=$1} END {print "restore p50=" a[int((NR+1)/2)] " p95=" a[int(NR*0.95+0.5)] " max=" a[NR] " ms (n=" NR ")"}'
for p in $(pgrep firecracker); do awk '/^Pss:/ {print $2}' /proc/$p/smaps_rollup; done | awk '{s+=$1} END {printf "firecracker Pss: total %.0f MiB, %.1f MiB each\n", s/1024, s/1024/NR}'
# every VM still answers?
ok=0; for i in $(seq 1 $K); do ip netns exec fn$i python3 -c 'import urllib.request;print(urllib.request.urlopen("http://172.16.0.2/",timeout=5).status)' 2>/dev/null | grep -q 200 && ok=$((ok+1)); done
echo "answering after load: $ok / $K"
cleanup
