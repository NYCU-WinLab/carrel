"""The snapshot plugin in Python, contract 2, for both mechanisms.

--go-plugin prints go-plugin's handshake line and serves the health service
go-plugin asks for; --socket serves on a unix socket like svc-plugin.
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from concurrent import futures

import grpc
import plugin_pb2
import plugin_pb2_grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc

KEY = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SCHEMA = '{"type":"object","properties":{"seconds":{"type":"integer","minimum":1,"maximum":600}},"required":["seconds"]}'


class Snapshot(plugin_pb2_grpc.PluginServicer):
    def __init__(self, state):
        self.state = state
        self.lock = threading.Lock()
        os.makedirs(os.path.join(state, "ops"), exist_ok=True)
        os.makedirs(os.path.join(state, "tasks"), exist_ok=True)

    def _path(self, key):
        return os.path.join(self.state, "ops", key + ".json")

    def _task(self, task):
        return os.path.join(self.state, "tasks", task.replace(":", "_"))

    def _get(self, key, context):
        try:
            with open(self._path(key)) as f:
                record = json.load(f)
        except FileNotFoundError:
            context.abort(grpc.StatusCode.NOT_FOUND, f"no operation {key!r}")
        base = self._task(record["task"])
        try:
            progress = int(open(base + ".progress").read().strip())
        except (FileNotFoundError, ValueError):
            progress = 0
        op = plugin_pb2.Operation(idempotency_key=key, task=record["task"], progress=progress)
        try:
            exit_status = open(base + ".exit").read().strip()
        except FileNotFoundError:
            pid = int(open(base + ".pid").read())
            try:
                os.kill(pid, 0)
                op.state, op.message = "running", f"snapshot {progress}%"
                return op
            except ProcessLookupError:
                exit_status = "task worker is gone"
        op.done = True
        if exit_status == "OK":
            op.state, op.progress, op.result = "succeeded", 100, json.dumps({"snapshot": "snap-" + key})
        elif exit_status == "cancelled":
            op.state = "cancelled"
        else:
            op.state, op.error = "failed", exit_status
        return op

    def Describe(self, request, context):
        return plugin_pb2.DescribeResponse(
            name="snapshot",
            version="0.1.0-python",
            contract=2,
            operations=[plugin_pb2.OperationType(name="snapshot", params_schema=SCHEMA)],
        )

    def Probe(self, request, context):
        return plugin_pb2.ProbeResponse(supported=True)

    def StartOperation(self, request, context):
        key = request.idempotency_key
        if not KEY.match(key):
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "idempotency_key must be 1 to 128 of A-Za-z0-9._-")
        seconds = json.loads(request.params or "{}").get("seconds")
        if not isinstance(seconds, int) or not 1 <= seconds <= 600:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'params must be {"seconds": 1 to 600}')
        with self.lock:
            if not os.path.exists(self._path(key)):
                task = f"UPID:fakepy:{time.time_ns()}"
                base = self._task(task)
                steps = seconds * 5
                script = (
                    f"i=0; while [ $i -lt {steps} ]; do i=$((i+1)); echo $((i*100/{steps})) > '{base}.progress';"
                    f" sleep 0.2; done; echo OK > '{base}.exit'"
                )
                worker = subprocess.Popen(["sh", "-c", script], start_new_session=True)
                with open(base + ".pid", "w") as f:
                    f.write(str(worker.pid))
                with open(self._path(key) + ".next", "w") as f:
                    json.dump({"key": key, "operation": "snapshot", "task": task}, f)
                os.replace(self._path(key) + ".next", self._path(key))
            return self._get(key, context)

    def GetOperation(self, request, context):
        with self.lock:
            return self._get(request.idempotency_key, context)

    def Cancel(self, request, context):
        with self.lock:
            op = self._get(request.idempotency_key, context)
            if not op.done:
                base = self._task(op.task)
                try:
                    os.killpg(int(open(base + ".pid").read()), signal.SIGTERM)
                except ProcessLookupError:
                    pass
                if not os.path.exists(base + ".exit"):
                    with open(base + ".exit", "w") as f:
                        f.write("cancelled\n")
            return self._get(request.idempotency_key, context)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", default="/tmp/snapshot-plugin-py")
    parser.add_argument("--socket")
    parser.add_argument("--go-plugin", action="store_true")
    args = parser.parse_args()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    plugin_pb2_grpc.add_PluginServicer_to_server(Snapshot(args.state), server)
    if args.go_plugin:
        checks = health.HealthServicer()
        checks.set("plugin", health_pb2.HealthCheckResponse.SERVING)
        health_pb2_grpc.add_HealthServicer_to_server(checks, server)
        socket = os.path.join(tempfile.mkdtemp(), "plugin.sock")
    else:
        socket = args.socket
        if os.path.exists(socket):
            os.remove(socket)
    server.add_insecure_port("unix://" + socket)
    server.start()
    if args.go_plugin:
        # go-plugin's handshake: core version|app version|network|address|protocol.
        print(f"1|2|unix|{socket}|grpc", flush=True)
    else:
        print(json.dumps({"event": "listening", "pid": os.getpid(), "contract": 2}), flush=True)
    server.wait_for_termination()


if __name__ == "__main__":
    sys.exit(main())
