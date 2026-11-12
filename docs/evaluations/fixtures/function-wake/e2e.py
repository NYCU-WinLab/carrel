#!/usr/bin/env python3
"""End-to-end check of carrel-fnd on a function host: reuse, idle sleep, fresh, clock, overlay."""
import json, subprocess, time, urllib.request

def call(name, path="/"):
    req = urllib.request.Request("http://127.0.0.1:8090" + path, headers={"X-Carrel-Function": name})
    t = time.monotonic()
    with urllib.request.urlopen(req, timeout=30) as r:
        body = json.load(r)
    return (time.monotonic() - t) * 1e3, body

def vms():
    return int(subprocess.run(["pgrep", "-c", "firecracker"], capture_output=True, text=True).stdout or 0)

def stats(name, xs):
    xs = sorted(xs); q = lambda f: xs[min(len(xs) - 1, int(round(f * (len(xs) - 1))))]
    print(f"{name:44s} n={len(xs)} p50={q(.5):7.1f} p95={q(.95):7.1f} max={xs[-1]:7.1f} ms")

results = []
def check(name, ok, detail=""):
    results.append(ok); print(("PASS " if ok else "FAIL ") + name + (" : " + detail if detail else ""))

# reuse: first request wakes, later ones do not
ms, body = call("py", "/rand")
skew = abs(body["time"] - time.time())
check("reuse: first request wakes and answers", body["urandom"] != "", f"{ms:.0f} ms")
check("guest clock is set on wake", skew < 1.0, f"skew {skew * 1e3:.0f} ms")
warm = [call("py")[0] for _ in range(200)]
stats("reuse: warm request through the router", warm)
check("reuse: one microVM for 201 requests", vms() == 1, f"{vms()} running")

# idle: the instance stops after idle_seconds (3 here), then wakes again
time.sleep(5)
check("reuse: asleep after idle_seconds", vms() == 0, f"{vms()} running")
wakes = []
for _ in range(15):
    wakes.append(call("py")[0]); time.sleep(4.5)
stats("reuse: request that wakes the function", wakes)

# fresh: a new microVM per request, gone after the answer
fresh = [call("job")[0] for _ in range(30)]
stats("fresh: request with its own microVM", fresh)
time.sleep(0.5)
check("fresh: no microVM left after the answers", vms() == 0, f"{vms()} running")
a, b = call("job", "/rand")[1], call("job", "/rand")[1]
check("fresh: kernel randomness differs between instances", a["urandom"] != b["urandom"])
check("fresh: guest clock is current", abs(b["time"] - time.time()) < 1.0)

# overlay: the function can write, and the write is gone in the next instance
w1 = call("job", "/write")[1]; w2 = call("job", "/write")[1]
check("overlay: root file system is writable", w1.get("wrote") is True, str(w1))
check("overlay: writes do not survive the instance", w1.get("seen_before") is False and w2.get("seen_before") is False, str(w2))
print("RESULT", "all pass" if all(results) else "FAILED")
