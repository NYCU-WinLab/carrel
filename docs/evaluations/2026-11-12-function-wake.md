# Function wake time: microVM snapshots against containers

These experiments ran on 2026-11-12 to decide if carrel should offer functions (PLAN 7.11): code
that uses no memory while it has no work and wakes when a request arrives. They answer four
questions. How fast is a wake? How many sleeping functions fit on one host? How long does a
container image take to become a function? What goes wrong when one snapshot is restored many
times? Machine-readable numbers are in [the accompanying report](2026-11-12-function-wake.json).
The scripts are in [fixtures/function-wake](fixtures/function-wake).

## Setup

| Item | Value |
| --- | --- |
| Test machine | carrel VM `fn-lab`, tenant `zyx1121`, 1 vCPU, 2 GiB, 10 GiB, `nested_virt` |
| Node CPU | Intel Xeon E5-2630 v4, so every microVM is a nested guest |
| VM monitor | Firecracker v1.18.0 |
| Guest kernel | 6.1.155 from the Firecracker CI bucket (`firecracker-ci/v1.15/x86_64`) |
| Baseline | Docker from Debian 13 on the same machine |
| Timer | from the start of the process to the first HTTP 200, measured on the host |

Three workloads were used.

- **Minimal**: static busybox `httpd`, 128 MiB guest.
- **Python**: Python 3.13 that imports ten standard modules, builds about 50 MB of data and then
  serves HTTP, 512 MiB guest. Built from `python:3.13-slim` (118 MB image).
- **Browser**: Playwright with the Chromium headless shell. Each request renders a page and takes
  a screenshot, 1024 MiB guest. 945 MB image.

## 1. Wake time

Python function:

| Method | Runs | p50 | p95 |
| --- | ---: | ---: | ---: |
| Snapshot restore, snapshot in the page cache | 30 | 95 ms | 104 ms |
| Snapshot restore, page cache dropped before each run | 15 | 218 ms | 223 ms |
| `docker start` of a stopped container | 20 | 1,368 ms | 1,611 ms |
| `docker run` of a new container | 20 | 2,287 ms | 2,524 ms |
| microVM cold boot | 30 | 2,509 ms | 3,026 ms |

The 95 ms restore has three parts: 1 ms to start the process, 5 ms to load the snapshot and
88 ms from resume to the answer. The last part is the bottleneck. The guest loads each memory page
on first touch, and under nested virtualization each of those faults is expensive. No bare-metal
host was available for comparison.

Browser function, timed to the first screenshot:

| Method | Runs | p50 | p95 |
| --- | ---: | ---: | ---: |
| Snapshot restore, snapshot in the page cache | 10 | 892 ms | 913 ms |
| Snapshot restore, page cache dropped | 1 | 2,178 ms | |
| `docker start` of a stopped container | 5 | 1,625 ms | 1,811 ms |
| `docker run` of a new container | 5 | 2,068 ms | 2,105 ms |
| microVM cold boot | 5 | 5,899 ms | 6,421 ms |

The first screenshot touches 221 MiB, one page at a time, so the restore is only 1.8 times faster
than `docker start`, and slower when the snapshot must come from disk. After the wake, each
screenshot takes 83 ms (50 runs). Loading the pages of the first request in one read at restore
time is the known fix. It was not measured here.

Minimal function, for scale: restore p50 60 ms and p95 84 ms, cold boot p50 170 ms and p95 184 ms
(30 runs each).

## 2. Density

The Python snapshot was restored 30 times on the 2 GiB machine. Each copy had its own network
namespace and all 30 answered afterwards.

| Observation | Value |
| --- | ---: |
| Memory each copy added (`MemAvailable` delta / 30) | 16 MiB |
| Restore while the other copies ran, p50 | 173 ms |
| Restore while the other copies ran, p95 | 191 ms |

Copies share every page they have not written, because each maps the same snapshot file. The
restore times include one `ip netns exec` and one Python start per copy, on a single vCPU.

One copy under load, counting only the memory it does not share with the snapshot:

| State | Private memory |
| --- | ---: |
| After the wake and 1 request | 6.8 MiB |
| After 2,000 light requests (1.7 ms each) | 9.1 MiB |
| After 300 more requests that allocate (49 ms each) | 15.6 MiB |

## 3. From image to function

`oci2fn.sh` exports the image, adds an init that honours the image's entrypoint, command,
environment and working directory, builds an ext4 root file system, boots it, waits for the first
HTTP 200, waits 1 second and writes the snapshot. The image itself is not changed.

| Image | Runs | Export | Root file system | Cold boot | Snapshot | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Python, 118 MB | 3 | 1.3 s | 2.6 s | 3.9 s | 1.2 s | 10.4 s |
| Browser, 945 MB | 1 | 7.8 s | 10.9 s | 10.7 s | 3.1 s | 33.5 s |

Copying files and the cold boot dominate, and both grow with the image.

## 4. What copies of one snapshot share

Two copies were restored from the same Python snapshot, 23 seconds after it was taken.

| Source | Result |
| --- | --- |
| `os.urandom`, `uuid.uuid4` | different in each copy |
| `random.random()` | identical in both copies |
| Wall clock | both copies read the time of the snapshot, 23 seconds behind the host |

The kernel's random pool differs after a restore. Random state held in user space does not. The
guest clock must be set on every wake.

## Problems found while measuring

- A restored guest keeps the ARP entry of the tap device it had at snapshot time. A new tap with
  another MAC address makes the first answer wait about 46 seconds. Each copy's tap must carry the
  MAC address the snapshot expects.
- The API socket file appears before Firecracker listens on it. A client must retry the connect.
- busybox selects its applet from its own file name, so the helper must be named `busybox`.
- The Firecracker CI bucket publishes guest kernels up to `v1.15` only.

## Not covered

- Bare-metal Firecracker, which removes the nested page fault cost.
- A writable overlay on the read-only root file system.
- The real AIntern runner images. The browser workload stands in for the browser pool.
- More than one vCPU, concurrent wakes of different functions, and memory pressure on the host.
- A restore on a node with a different CPU model.

These are a few runs on one small machine. They are not a latency guarantee.
