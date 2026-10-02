"""Read-only Python comparator. Never emit the credential configuration."""

import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor


def cli(path):
    return json.loads(
        subprocess.check_output(
            ["pvesh", "get", path, "--output-format", "json"],
            stderr=subprocess.PIPE,
            timeout=30,
        )
    )


class Http:
    def __init__(self, config_path):
        import http.client
        import ssl
        from urllib.parse import urlsplit

        with open(config_path) as source:
            config = json.load(source)
        parsed = urlsplit(config["base"])
        assert parsed.scheme == "https"
        context = ssl.create_default_context(cafile=config["ca"])
        # PVE's CA lacks keyUsage. Keep chain and hostname verification, using
        # OpenSSL's compatible validation rules rather than Python 3.13 strict mode.
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        self.connection = http.client.HTTPSConnection(
            parsed.hostname,
            parsed.port,
            context=context,
            timeout=30,
        )
        self.authorization = config["authorization"]

    def __call__(self, path):
        self.connection.request(
            "GET", "/api2/json" + path, headers={"Authorization": self.authorization}
        )
        response = self.connection.getresponse()
        payload = response.read()
        if response.status != 200:
            raise RuntimeError(f"HTTP status {response.status}")
        return json.loads(payload)["data"]


def observe(mode, workload, get):
    if mode == "batch":
        return json.loads(
            subprocess.check_output(
                ["/usr/local/lib/carrel/pve-read.pl", workload],
                stderr=subprocess.PIPE,
                timeout=30,
            )
        )
    if workload == "inventory":
        return {
            "volumes": get("/nodes/carrel01/storage/local-lvm/content"),
            "resources": get("/cluster/resources"),
            "storage": get("/nodes/carrel01/storage/local-lvm/status"),
            "status": get("/nodes/carrel01/status"),
        }
    if workload == "topology":
        vnets = get("/cluster/sdn/vnets")
        names = [
            v["vnet"]
            for v in vnets
            if len(v["vnet"]) == 4
            and v["vnet"].startswith("t")
            and v["vnet"][1:].isdigit()
        ]
        paths = [f"/cluster/sdn/vnets/{name}/subnets" for name in names]
        if mode == "pvesh":
            with ThreadPoolExecutor(max_workers=4) as pool:
                values = list(pool.map(get, paths))
        else:
            values = list(map(get, paths))
        return {"vnets": vnets, "subnets": dict(zip(names, values))}
    raise ValueError("unknown workload")


if __name__ == "__main__":
    mode, workload, count, config_path = sys.argv[1:]
    assert mode in {"http", "pvesh", "batch"} and 1 <= int(count) <= 100
    get = Http(config_path) if mode == "http" else cli
    samples = []
    for _ in range(int(count)):
        start = time.perf_counter()
        result = observe(mode, workload, get)
        samples.append(time.perf_counter() - start)
    print(json.dumps({"samples": samples, "result": result}))
