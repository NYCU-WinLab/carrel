#!/usr/bin/env python3
"""End-to-end check of carrel-fnd on a function host: reuse, idle sleep, fresh, clock, overlay, jail.

Run as root on the function host while `carrel-fnd serve` listens on 127.0.0.1:8090.
Functions `py` (reuse, idle 3 s, 512 MiB) and `job` (fresh) must be built from the test image.
"""
import glob, json, os, subprocess, time, urllib.request

ROOT = "/var/lib/carrel-fn"

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

# jail: what the one awake Firecracker process may see and do
pid = int(subprocess.run(["pgrep", "-o", "firecracker"], capture_output=True, text=True).stdout)
status = dict(line.split(":\t", 1) for line in open(f"/proc/{pid}/status").read().splitlines() if ":\t" in line)
uid = int(status["Uid"].split()[0])
check("jail: Firecracker does not run as root", uid >= 300000, f"uid {uid}")
check("jail: no capabilities", int(status["CapEff"], 16) == 0 and int(status["CapPrm"], 16) == 0, status["CapEff"])
check("jail: seccomp filter is on", status["Seccomp"].strip() == "2", status["Seccomp"].strip())
check("jail: own PID namespace", len(status["NSpid"].split()) == 2, status["NSpid"].strip())
# The jailer pivots into the jail in a new mount namespace, so the host reads the jail through /proc.
root = f"/proc/{pid}/root"
top = sorted(os.listdir(root))
mount_ns = os.readlink(f"/proc/{pid}/ns/mnt")
check("jail: own root directory with nothing of the host", mount_ns != os.readlink("/proc/self/ns/mnt")
      and set(top) <= {"api.sock", "dev", "firecracker", "firecracker.pid", "fn", "run"} and "fn" in top, str(top))
cgroup = open(f"/proc/{pid}/cgroup").read().strip().split("::")[1]
limit = int(open(f"/sys/fs/cgroup{cgroup}/memory.max").read())
check("jail: memory limit is guest memory + 128 MiB", limit == (512 + 128) << 20, f"{limit >> 20} MiB in {cgroup}")
check("jail: process limit", open(f"/sys/fs/cgroup{cgroup}/pids.max").read().strip() == "64")
netns = os.readlink(f"/proc/{pid}/ns/net")
check("jail: own network namespace", netns != os.readlink("/proc/self/ns/net"), netns)
seen = sorted(os.listdir(root + "/fn"))
check("jail: sees only its own function files", seen == ["rootfs.ext4", "snap.mem", "snap.state"], str(seen))
modes = {oct(os.stat(f).st_mode & 0o777) for f in glob.glob(ROOT + "/py/v/*/*")}
owners = {os.stat(f).st_uid for f in glob.glob(ROOT + "/py/v/*/*")}
check("jail: function files are read-only and owned by root", modes == {"0o440"} and owners == {0}, f"{modes} {owners}")

# idle: the instance stops after idle_seconds (3 here), then wakes again
time.sleep(5)
check("reuse: asleep after idle_seconds", vms() == 0, f"{vms()} running")
left = glob.glob(ROOT + "/.jail/firecracker/*") + glob.glob("/sys/fs/cgroup/carrel-fn/cfn*")
check("jail: directory and cgroup are removed after sleep", left == [], str(left))
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
