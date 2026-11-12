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
# disk: the instance can create no file in its jail, and no file may grow
dirs = [d for d, _, _ in os.walk(root)]
mine = [d for d in dirs if os.stat(d).st_uid != 0 or os.stat(d).st_mode & 0o022]
check("disk: every directory of the jail is root's and not writable by others", dirs and not mine, str(mine[:3]))
fsize = [line for line in open(f"/proc/{pid}/limits") if line.startswith("Max file size")][0].split()
check("disk: no file may grow past 1 MiB", fsize[3] == fsize[4] == str(1 << 20), " ".join(fsize[3:5]))
core = [line for line in open(f"/proc/{pid}/limits") if line.startswith("Max core file size")][0].split()
check("disk: Firecracker may write no core file", core[4] == core[5] == "0", " ".join(core[4:6]))
# The serial log is a pipe the router reads; the only files Firecracker holds are its read-only inputs.
held = [os.readlink(f"/proc/{pid}/fd/{fd}") for fd in os.listdir(f"/proc/{pid}/fd")]
files = sorted({h for h in held if h.startswith("/") and not h.startswith(("/dev/", "/fn/"))})
check("disk: Firecracker holds no writable host file, its log included", files == [], str(files))
check("disk: the serial output goes to a pipe", any(h.startswith("pipe:") for h in held))
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
# egress: a function reaches the internet and public names, and no private address.
# Each blocked target accepts connections from the host itself, so a refusal is the filter's work.
import socket
probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); probe.connect(("1.1.1.1", 53))
host_addr = probe.getsockname()[0]; probe.close()
def connect(host, port):
    return call("job", f"/connect?host={host}&port={port}")[1]
def from_host(host, port):
    try:
        socket.create_connection((host, port), timeout=2).close(); return True
    except OSError:
        return False
check("egress: reaches a public address", connect("1.1.1.1", 443)["ok"])
resolved = call("job", "/resolve?name=example.com")[1]
check("egress: resolves a public name", resolved["ok"], str(resolved))
link = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True).stdout
link_addr = next(line.split()[3].split("/")[0] for line in link.splitlines() if line.split()[1].startswith("cfnv"))
for label, host, port in [("the function host's own address", host_addr, 22),
                          ("the host's end of an egress link", link_addr, 22)]:
    check(f"egress control: the host itself reaches {label}", from_host(host, port), f"{host}:{port}")
    check(f"egress: cannot reach {label}", connect(host, port)["ok"] is False, f"{host}:{port}")
for label, host, port in [("the guest link's host end", "172.16.0.1", 22), ("a metadata address", "169.254.169.254", 80),
                          ("the platform gateway", "10.200.0.2", 443), ("a node", "192.168.19.101", 8006),
                          ("a tailnet address", "100.100.1.4", 22), ("loopback of the host", "127.0.0.2", 22)]:
    check(f"egress: cannot reach {label}", connect(host, port)["ok"] is False, f"{host}:{port}")

# egress: a packet with a forged source, or one that connection tracking calls invalid, must not
# leave the host. The capture is shown to work first, with an ordinary connection attempt.
uplink = subprocess.run(["ip", "-o", "-4", "route", "show", "default"], capture_output=True, text=True).stdout.split("dev ")[1].split()[0]
def leaving(send):
    capture = subprocess.Popen(["timeout", "4", "tcpdump", "-l", "-n", "-i", uplink, "dst host 1.1.1.1 and tcp dst port 4444"],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    time.sleep(1); send(); out = capture.communicate()[0]
    return [line.split()[2] for line in out.splitlines() if " > 1.1.1.1.4444" in line]
seen = leaving(lambda: connect("1.1.1.1", 4444))
check("egress control: the capture sees an ordinary connection, from the host's address",
      len(seen) > 0 and all(src.startswith(host_addr + ".") for src in seen), str(seen[:2]))
SYN, SYN_FIN = 0x02, 0x03
for label, src, flags in [("a forged public source", "198.51.100.7", SYN), ("a forged private source", "10.200.0.2", SYN),
                          ("an invalid packet from the guest's own address", "172.16.0.2", SYN_FIN),
                          ("an invalid packet with a forged source", "198.51.100.7", SYN_FIN)]:
    sent = []
    seen = leaving(lambda: sent.append(call("job", f"/spoof?src={src}&dst=1.1.1.1&port=4444&flags={flags}")[1]))
    check(f"egress: {label} does not leave the host", sent[0]["ok"] and seen == [], f"sent {sent[0]} captured {seen[:2]}")

# egress: a slot's namespace is made new after every instance, so it remembers no connection.
def tracked(ns):
    out = subprocess.run(["ip", "netns", "exec", ns, "cat", "/proc/sys/net/netfilter/nf_conntrack_count"], capture_output=True, text=True)
    return int(out.stdout or -1)
call("py", "/resolve?name=example.com")
slots = [line.split()[0] for line in subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout.splitlines() if line.startswith("cfn")]
check("egress control: an awake instance's namespace tracks its connections", max(tracked(ns) for ns in slots) > 0)
for _ in range(12):
    call("job", "/resolve?name=example.com")
time.sleep(5)
counts = {ns: tracked(ns) for ns in slots}
check("egress: no namespace remembers a connection once its instance is gone", set(counts.values()) == {0}, str(counts))

# limits: what one instance may use of the network (PLAN 13.4)
ms, body = call("py", "/conns?host=1.1.1.1&port=443&n=700")
check("limits: an instance holds at most 512 connections", 300 <= body.get("held", 0) <= 512, str(body))
pid = int(subprocess.run(["pgrep", "-n", "firecracker"], capture_output=True, text=True).stdout)
ns = subprocess.run(["ip", "netns", "identify", str(pid)], capture_output=True, text=True).stdout.strip()
shaped = {dev: subprocess.run(["ip", "netns", "exec", ns, "tc", "qdisc", "show", "dev", dev], capture_output=True, text=True).stdout
          for dev in ("eth0", "tap0")}
check("limits: both directions are shaped to 100 Mbit/s", all("tbf" in q and "rate 100Mbit" in q for q in shaped.values()), str(shaped))
def tx(dev):
    return int(subprocess.run(["ip", "netns", "exec", ns, "cat", f"/sys/class/net/{dev}/statistics/tx_packets"],
                              capture_output=True, text=True).stdout)
before = tx("eth0")
ms, body = call("py", "/udp?host=198.51.100.1&port=9&n=2000")
left = tx("eth0") - before
check("limits: one UDP flow is not cut by the new-connection limit", left >= 1900, f"{left} of 2000 left in {body.get('seconds', 0):.2f} s")
start = time.monotonic()
req = urllib.request.Request("http://127.0.0.1:8090/big?mib=40", headers={"X-Carrel-Function": "py"})
size = len(urllib.request.urlopen(req, timeout=60).read())
mbit = size * 8 / (time.monotonic() - start) / 1e6
check("limits: an answer to the router is limited too", size == 40 << 20 and mbit < 110, f"{mbit:.0f} Mbit/s")
ms, body = call("py", "/churn?host=1.1.1.1&port=443&n=2500")
tracked = sum(" src=10.251." in l for l in subprocess.run(["conntrack", "-L"], capture_output=True, text=True).stdout.splitlines())
check("limits: connections that open and close do not pile up in the host's table", tracked <= 512 + 200 * 10 + 100,
      f"{tracked} tracked after {body.get('made')} connections in {body.get('seconds', 0):.0f} s")
conntrack = int(open("/proc/sys/net/netfilter/nf_conntrack_max").read())
check("limits: the host tracks every slot at its limit", conntrack >= 8 * (512 + 200 * 10) * 2, str(conntrack))
time.sleep(5)  # py is built with -idle 3: asleep again before the next checks
ms, body = call("job", "/conns?host=1.1.1.1&port=443&n=50")  # a fresh instance that leaves connections behind
time.sleep(2)
left = [l for l in subprocess.run(["conntrack", "-L"], capture_output=True, text=True).stdout.splitlines() if " src=10.251." in l]
check("limits: no slot leaves connections in the host's table", body.get("held", 0) > 0 and left == [], f"held {body.get('held')}, left {len(left)}")

# images: pulled from a registry with no Docker daemon, and an image whose USER is not root.
# Functions `whoami` (traefik/whoami) and `nginx` (nginxinc/nginx-unprivileged, port 8080) must be built, with -idle 3.
if os.path.exists(ROOT + "/whoami/function.json") and os.path.exists(ROOT + "/nginx/function.json"):
    def raw(name):
        req = urllib.request.Request("http://127.0.0.1:8090/", headers={"X-Carrel-Function": name})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode(errors="replace")
    status, body = raw("whoami")
    check("image: a function pulled from a registry answers", status == 200 and "Hostname" in body, body[:40].replace("\n", " "))
    status, body = raw("nginx")
    check("image: a function whose image user is not root answers", status == 200 and "nginx" in body.lower())
    log = "".join(open(f, errors="replace").read() for f in glob.glob(ROOT + "/nginx/*log"))  # build.log and log
    check("image: its output reaches the function's log", "start worker process" in log and "GET / HTTP" in log)
    time.sleep(5)  # both are built with -idle 3, so they are asleep again for the next run
print("RESULT", "all pass" if all(results) else "FAILED")
