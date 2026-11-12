#!/usr/bin/env python3
"""Exp 5: memory growth of a restored function under load. Exp 6: what two copies of one snapshot share."""
import json, time, urllib.request
import bench


def get(path="/"):
    return json.load(urllib.request.urlopen(f"http://172.16.0.2{path}", timeout=30))


def mem(pid):
    out = {}
    for line in open(f"/proc/{pid}/smaps_rollup"):
        k, _, v = line.partition(":")
        if k in ("Rss", "Anonymous"):
            out[k] = int(v.split()[0]) / 1024
    return out


def show(label, pid):
    m = mem(pid)
    print(f"  {label:38s} RSS {m['Rss']:6.1f} MiB   private (not shared with snapshot) {m['Anonymous']:6.1f} MiB")


print("== exp 5: memory growth after wake")
p = bench.spawn(); bench.load(); bench.wait_http()
show("after wake + 1 request", p.pid)
t = time.monotonic()
for _ in range(2000):
    get("/")
dt = time.monotonic() - t
show("after 2,000 light requests", p.pid)
print(f"  light request: {dt / 2000 * 1e3:.2f} ms each, sequential")
t = time.monotonic()
for _ in range(300):
    get("/work")
dt = time.monotonic() - t
show("after 300 requests that allocate", p.pid)
print(f"  allocating request: {dt / 300 * 1e3:.1f} ms each")
bench.kill(p)

print("== exp 6: two copies restored from the same snapshot")
rows = []
for i in (1, 2):
    p = bench.spawn(); bench.load(); bench.wait_http()
    rows.append(get("/rand"))
    bench.kill(p)
    time.sleep(1.5)
for k in ("urandom", "uuid4", "random", "time"):
    a, b = rows[0][k], rows[1][k]
    print(f"  {k:8s} copy1={a}  copy2={b}  -> {'SAME' if a == b else 'different'}")
print(f"  host clock now {time.time():.1f}")
