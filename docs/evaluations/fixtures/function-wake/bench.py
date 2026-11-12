#!/usr/bin/env python3
"""Measure Firecracker cold boot vs snapshot restore: process start -> first HTTP 200 from the guest.

Modes: (default) full benchmark | hold: restore one VM, print its time, stay alive.
Env: MEM (MiB), N (runs), ROOTFS, SNAP (snapshot name), SOCK.
"""
import http.client, json, os, socket, statistics, subprocess, sys, time

W = "/opt/fnlab"
FC = f"{W}/firecracker"
SOCK = os.environ.get("SOCK", "/tmp/fc.sock")
ROOTFS = os.environ.get("ROOTFS", f"{W}/rootfs.ext4")
SNAP = os.environ.get("SNAP", "snap")
GUEST = ("172.16.0.2", 80)
MEM = int(os.environ.get("MEM", "128"))
N = int(os.environ.get("N", "30"))
BOOT_ARGS = ("console=ttyS0 quiet loglevel=0 reboot=k panic=1 pci=off ro init=" + os.environ.get("INIT", "/init") + " "
             "i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd random.trust_cpu=on")


class Unix(http.client.HTTPConnection):
    def connect(self):
        for _ in range(2000):  # the socket file appears before Firecracker listens on it
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                self.sock.connect(SOCK)
                return
            except ConnectionRefusedError:
                self.sock.close()
                time.sleep(0.0005)
        raise ConnectionRefusedError(SOCK)


def api(method, path, body):
    c = Unix("localhost")
    c.request(method, path, json.dumps(body), {"Content-Type": "application/json"})
    r = c.getresponse()
    data = r.read().decode()
    c.close()
    if r.status >= 300:
        raise RuntimeError(f"{method} {path} -> {r.status} {data}")


def spawn():
    if os.path.exists(SOCK):
        os.unlink(SOCK)
    p = subprocess.Popen([FC, "--api-sock", SOCK], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    while not os.path.exists(SOCK):
        time.sleep(0.0005)
    return p


def wait_http(deadline=60.0):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        s = socket.socket()
        s.settimeout(0.005)
        try:
            s.connect(GUEST)
            s.settimeout(5)
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            if b"200" in s.recv(64):
                return time.monotonic()
        except OSError:
            pass
        finally:
            s.close()
    raise TimeoutError("guest did not answer")


def configure_and_boot():
    api("PUT", "/boot-source", {"kernel_image_path": f"{W}/vmlinux", "boot_args": BOOT_ARGS})
    api("PUT", "/drives/rootfs", {"drive_id": "rootfs", "path_on_host": ROOTFS,
                                   "is_root_device": True, "is_read_only": True})
    api("PUT", "/network-interfaces/eth0", {"iface_id": "eth0", "guest_mac": "06:00:AC:10:00:02",
                                            "host_dev_name": "tap0"})
    api("PUT", "/machine-config", {"vcpu_count": 1, "mem_size_mib": MEM})
    api("PUT", "/actions", {"action_type": "InstanceStart"})


def kill(p):
    p.kill()
    p.wait()


def rss_kb(pid):
    for line in open(f"/proc/{pid}/status"):
        if line.startswith("VmRSS"):
            return int(line.split()[1])


def stats(name, xs):
    xs = sorted(xs)
    q = lambda f: xs[min(len(xs) - 1, int(round(f * (len(xs) - 1))))]
    print(f"{name:34s} n={len(xs)} p50={q(.5):7.1f} p95={q(.95):7.1f} min={xs[0]:7.1f} max={xs[-1]:7.1f} ms")


def cold():
    t0 = time.monotonic(); p = spawn(); t1 = time.monotonic()
    configure_and_boot(); t2 = time.monotonic()
    t3 = wait_http()
    r = rss_kb(p.pid); kill(p)
    return (t3 - t0) * 1e3, (t1 - t0) * 1e3, (t2 - t1) * 1e3, (t3 - t2) * 1e3, r


def make_snapshot():
    t0 = time.monotonic(); p = spawn(); configure_and_boot(); t1 = wait_http()
    time.sleep(float(os.environ.get("SETTLE", "1")))  # let the app settle before freezing it
    t2 = time.monotonic()
    api("PATCH", "/vm", {"state": "Paused"})
    api("PUT", "/snapshot/create", {"snapshot_type": "Full", "snapshot_path": f"{W}/{SNAP}.state",
                                    "mem_file_path": f"{W}/{SNAP}.mem"})
    t3 = time.monotonic()
    kill(p)
    return t1 - t0, t3 - t2


def load():
    api("PUT", "/snapshot/load", {"snapshot_path": f"{W}/{SNAP}.state",
                                  "mem_backend": {"backend_type": "File", "backend_path": f"{W}/{SNAP}.mem"},
                                  "resume_vm": True})


def restore():
    t0 = time.monotonic(); p = spawn(); t1 = time.monotonic()
    load(); t2 = time.monotonic()
    t3 = wait_http()
    r = rss_kb(p.pid); kill(p)
    return (t3 - t0) * 1e3, (t1 - t0) * 1e3, (t2 - t1) * 1e3, (t3 - t2) * 1e3, r


def run(name, fn, labels):
    rows = [fn() for _ in range(N)]
    print(f"== {name} (guest {MEM} MiB, 1 vCPU, {os.path.basename(ROOTFS)})")
    stats("total: spawn -> first HTTP 200", [r[0] for r in rows])
    for i, lab in enumerate(labels, 1):
        stats("  " + lab, [r[i] for r in rows])
    print(f"  firecracker RSS after 1 request: median {statistics.median(r[4] for r in rows) / 1024:.1f} MiB")


if __name__ == "__main__":
    if sys.argv[1:] == ["hold"]:
        t0 = time.monotonic(); p = spawn(); load(); t = wait_http()
        print(f"{(t - t0) * 1e3:.1f} {p.pid}", flush=True)
        p.wait()
        sys.exit(0)
    cold(); make_snapshot(); restore()  # warm page cache once
    run("cold boot", cold, ["process + API socket", "configure + start", "kernel boot -> HTTP"])
    run("snapshot restore", restore, ["process + API socket", "load snapshot + resume", "resume -> HTTP"])
    for f in (f"{SNAP}.state", f"{SNAP}.mem"):
        st = os.stat(f"{W}/{f}")
        print(f"{f}: apparent {st.st_size / 2**20:.1f} MiB, on disk {st.st_blocks * 512 / 2**20:.1f} MiB")
