#!/usr/bin/env python3
"""Container baseline: time from `docker run` / `docker start` to the first HTTP 200."""
import os, socket, subprocess, time

N = int(os.environ.get("N", "20"))
ADDR = ("127.0.0.1", 8080)


def sh(*a):
    return subprocess.run(a, check=True, capture_output=True, text=True).stdout.strip()


def wait_http(deadline=60.0):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        s = socket.socket()
        s.settimeout(0.05)
        try:
            s.connect(ADDR)
            s.settimeout(5)
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            if b"200" in s.recv(64):
                return time.monotonic()
        except OSError:
            time.sleep(0.002)
        finally:
            s.close()
    raise TimeoutError


def stats(name, xs):
    xs = sorted(xs)
    q = lambda f: xs[min(len(xs) - 1, int(round(f * (len(xs) - 1))))]
    print(f"{name:34s} n={len(xs)} p50={q(.5):7.1f} p95={q(.95):7.1f} min={xs[0]:7.1f} max={xs[-1]:7.1f} ms")


subprocess.run(["docker", "rm", "-f", "fnlab"], capture_output=True)
fresh, restart = [], []
for _ in range(N + 1):
    t0 = time.monotonic()
    sh("docker", "run", "-d", "--name", "fnlab", "-p", "127.0.0.1:8080:80", "fnlab-py")
    fresh.append((wait_http() - t0) * 1e3)
    sh("docker", "kill", "fnlab")
    t0 = time.monotonic()
    sh("docker", "start", "fnlab")
    restart.append((wait_http() - t0) * 1e3)
    sh("docker", "rm", "-f", "fnlab")
print("== docker baseline (same Python app)")
stats("docker run -> first HTTP 200", fresh[1:])
stats("docker start (stopped) -> HTTP 200", restart[1:])
