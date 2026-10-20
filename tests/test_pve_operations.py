import http.client
import importlib.util
import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

GIB = 1024**3


def script(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / "scripts" / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_paused_nic_unplug_never_writes_pending_configuration(monkeypatch):
    module = script("node-agent.py")
    monkeypatch.setattr(module, "owned", lambda *args, **kwargs: {"net1": "existing"})
    monkeypatch.setattr(module, "power_status", lambda m: "paused")
    calls = []
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError, match="resume or shut down"):
        module.action({"action": "nic_detach", "index": 1, "machine": {"kind": "vm", "vmid": 10100}})
    assert not calls


@pytest.fixture
def gateway(tmp_path, monkeypatch):
    module = script("gateway-sync.py")
    monkeypatch.setattr(module, "HOSTS", tmp_path / "hosts")
    monkeypatch.setattr(module, "CADDY", tmp_path / "Caddyfile")
    monkeypatch.setattr(module, "STATE", tmp_path / "state")
    calls = []
    monkeypatch.setattr(module, "run", lambda *args: calls.append(args))
    return module, calls


def test_gateway_converges_without_reloading_unchanged_services(gateway):
    module, calls = gateway
    state = {"hosts": "10.200.1.10 app.alice.internal\n", "caddy": ":80 { respond 404 }\n"}
    assert module.apply(state) == {"changed": ["hosts", "caddy"]}
    calls.clear()
    assert module.apply(state) == {"changed": []}
    assert calls == [("systemctl", "start", "carrel-dns"), ("systemctl", "start", "caddy")]
    calls.clear()
    state["hosts"] += "10.200.1.11 db.alice.internal\n"
    assert module.apply(state) == {"changed": ["hosts"]}
    assert calls == [("systemctl", "restart", "carrel-dns"), ("systemctl", "start", "caddy")]
    # Repair drift in the actual file, even when the successful receipt matches.
    module.HOSTS.write_text("incorrect\n")
    assert module.apply(state) == {"changed": ["hosts"]}
    assert module.HOSTS.read_text() == state["hosts"]


@pytest.mark.parametrize("name,service", [("hosts", "carrel-dns"), ("caddy", "caddy")])
def test_gateway_retries_failed_apply_after_file_was_written(gateway, monkeypatch, name, service):
    module, calls = gateway
    state = {"hosts": "", "caddy": ":80 { respond 404 }\n"}
    module.apply(state)
    state[name] += "\n"

    def fail(*args):
        if args[0] == "systemctl" and args[-1] == service:
            raise RuntimeError("temporary service failure")

    monkeypatch.setattr(module, "run", fail)
    with pytest.raises(RuntimeError, match="temporary"):
        module.apply(state)
    assert (module.HOSTS if name == "hosts" else module.CADDY).read_text() == state[name]
    monkeypatch.setattr(module, "run", lambda *args: calls.append(args))
    assert module.apply(state) == {"changed": [name]}


def test_gateway_validates_before_replacing_working_routes(gateway, monkeypatch):
    module, _ = gateway
    state = {"hosts": "", "caddy": ":80 { respond 404 }\n"}
    module.apply(state)

    def fail(*args):
        if args[0] == "/usr/local/bin/caddy":
            raise RuntimeError("invalid route")

    monkeypatch.setattr(module, "run", fail)
    with pytest.raises(RuntimeError, match="invalid route"):
        module.apply({**state, "caddy": "invalid"})
    assert module.CADDY.read_text() == state["caddy"]
    assert not module.CADDY.with_name("Caddyfile.carrel-validate").exists()
    with pytest.raises(ValueError):
        module.apply({**state, "path": "/etc/passwd"})


def pve_api(responses, reads):
    """A fake local PVE API: fixed GET responses by path, every read recorded."""

    def get(resource, **params):
        reads.append((resource, params))
        return responses[resource]

    return get


def test_inventory_stays_fresh_and_counts_every_volume(tmp_path, monkeypatch, capsys):
    module = script("node-agent.py")
    monkeypatch.setattr(module, "STATE", tmp_path)
    monkeypatch.setattr(module, "CONFIG", tmp_path / "node.json")
    monkeypatch.setattr(module, "NODE", "fixture")
    (tmp_path / "node.json").write_text('{"storage": "local-zfs"}')
    responses = {
        "/access/permissions": {"/storage/local-zfs": {"Datastore.Audit": 1, "Datastore.Allocate": 1}},
        "/cluster/resources": [],
        "/nodes/fixture/storage/local-zfs/status": {"total": 1000 * GIB, "used": 100 * GIB},
        "/nodes/fixture/status": {"cpuinfo": {"cpus": 8}, "memory": {"total": 64 * GIB}},
        "/nodes/fixture/storage/local-zfs/content": [
            {"content": "images", "size": 10 * GIB},  # Immutable template.
            {"content": "images", "size": 20 * GIB},  # Guest primary disk.
            {"content": "images", "size": 30 * GIB},  # Secondary or unused disk.
            {"content": "rootdir", "size": 40 * GIB},
            {"content": "backup", "size": 200 * GIB},
        ],
    }
    reads = []
    monkeypatch.setattr(module, "pve_get", pve_api(responses, reads))

    def inventory():
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b'{"op":"inventory"}')))
        module.main()
        return json.loads(capsys.readouterr().out)["result"]

    first = inventory()
    assert first["disk_committed_bytes"] == 100 * GIB
    assert first["storage"]["used"] == 100 * GIB and first["storage_id"] == "local-zfs"
    # No cache: the next inventory sees the new usage.
    responses["/nodes/fixture/storage/local-zfs/status"]["used"] = 900 * GIB
    assert inventory()["storage"]["used"] == 900 * GIB
    assert reads.count(("/access/permissions", {"path": "/storage/local-zfs"})) == 2
    # PVEAuditor alone hides volumes: an incomplete grant never reaches admission.
    responses["/access/permissions"] = {"/storage/local-zfs": {"Datastore.Audit": 1}}
    with pytest.raises(RuntimeError, match="authority is incomplete"):
        module.inventory_read("local-zfs")


def test_topology_observes_missing_subnets(tmp_path, monkeypatch):
    module = script("node-agent.py")

    def local(path):
        path = Path(path)
        return path if path.is_relative_to(tmp_path) else tmp_path / str(path).lstrip("/")

    monkeypatch.setattr(module, "Path", local)
    monkeypatch.setattr(module, "STATE", tmp_path / "state")
    monkeypatch.setattr(module, "CONFIG", tmp_path / "node.json")
    module.CONFIG.write_text('{"protected_addresses": []}')
    local("/sys/class/net/t001").mkdir(parents=True)
    responses = {
        # Only tenant VNets are read for subnets; private networks are not.
        "/cluster/sdn/vnets": [{"vnet": "t001", "zone": "tenants"}, {"vnet": "p00101", "zone": "private"}],
        "/cluster/sdn/vnets/t001/subnets": [{}],
    }
    reads, entries, mutations = [], [], []

    def run(*args, **kwargs):
        if args[0] == "pct":
            entries.append((args, kwargs))
        return "clsact"

    monkeypatch.setattr(module, "run", run)
    monkeypatch.setattr(module, "pve_get", pve_api(responses, reads))
    monkeypatch.setattr(module, "api", lambda *a, **kw: mutations.append((a, kw)))
    monkeypatch.setattr(module, "private_dhcp", lambda state, serve=True: None)
    monkeypatch.setattr(module, "first_exit_node", lambda: True)
    monkeypatch.setattr(module, "public_ingress", lambda: None)
    state = {
        "tenants": [{"n": 1, "slug": "alice"}],
        "networks": [],
        "machines": [],
        "domains": [],
    }
    assert module.reconcile(state)["changed"] == []
    assert [r[0] for r in reads] == ["/cluster/sdn/vnets", "/cluster/sdn/vnets/t001/subnets"]
    # The gateway is the control plane's to sync, never a node's.
    assert not mutations and not entries
    module.reconcile(state)
    responses["/cluster/sdn/vnets/t001/subnets"] = []
    assert module.reconcile(state)["changed"] == ["subnet-1"]
    assert len(reads) == 6
    assert mutations[0][0] == ("create", "/cluster/sdn/vnets/t001/subnets")
    assert mutations[1][0] == ("set", "/cluster/sdn")


REQUESTS = []


class FakeConnection:
    """Stands in for the HTTPS connection to the local PVE API."""

    def __init__(self, host, port, context, timeout):
        self.host, self.port, self.context = host, port, context
        self.status, self.body = 200, b'{"data": {"ok": 1}}'
        self.drops, self.closed = 0, 0

    def request(self, method, url, headers):
        REQUESTS.append((method, url, headers, self))

    def getresponse(self):
        if self.drops:
            self.drops -= 1
            raise http.client.RemoteDisconnected("idle connection closed")
        return SimpleNamespace(status=self.status, read=lambda limit: self.body)

    def close(self):
        self.closed += 1


def test_pve_reads_use_one_verified_connection_and_the_token(tmp_path, monkeypatch):
    module = script("node-agent.py")
    reader = tmp_path / "carrel-reader.json"
    reader.write_text(json.dumps({"authorization": "PVEAPIToken=root@pam!carrel-reader=secret"}))
    monkeypatch.setattr(module, "READER", reader)
    monkeypatch.setattr(module, "NODE", "carrel02")
    contexts = []

    def context(cafile):
        contexts.append(cafile)
        return SimpleNamespace(
            verify_flags=module.ssl.VERIFY_X509_STRICT | module.ssl.VERIFY_X509_TRUSTED_FIRST
        )

    monkeypatch.setattr(module.ssl, "create_default_context", context)
    monkeypatch.setattr(module.http.client, "HTTPSConnection", FakeConnection)
    REQUESTS.clear()
    assert module.pve_get("/nodes/carrel02/status") == {"ok": 1}
    assert module.pve_get("/nodes/carrel02/qemu/10100/rrddata", timeframe="hour") == {"ok": 1}
    assert contexts == ["/etc/pve/pve-root-ca.pem"]
    (method, url, headers, connection), (_, second, _, again) = REQUESTS
    assert method == "GET" and url == "/api2/json/nodes/carrel02/status"
    assert second == "/api2/json/nodes/carrel02/qemu/10100/rrddata?timeframe=hour"
    assert headers == {"Authorization": "PVEAPIToken=root@pam!carrel-reader=secret"}
    # The node's own name, so TLS checks the certificate PVE issued for it.
    assert connection is again and (connection.host, connection.port) == ("carrel02", 8006)
    assert not connection.context.verify_flags & module.ssl.VERIFY_X509_STRICT
    # pveproxy drops a keep-alive connection idle for 5 s, as after a slow write.
    connection.drops = 1
    assert module.pve_get("/nodes/carrel02/status") == {"ok": 1} and connection.closed == 1
    connection.drops = 2
    with pytest.raises(ConnectionError):
        module.pve_get("/nodes/carrel02/status")
    connection.status = 403
    with pytest.raises(module.CommandFailure, match="HTTP 403"):
        module.pve_get("/cluster/resources")
    connection.status, connection.body = 200, b'{"data": null}'
    with pytest.raises(module.CommandFailure, match="missing"):
        module.pve_get("/cluster/resources")


@pytest.mark.parametrize(
    "action,before,after,command,onboot",
    [
        ("pause", "running", "paused", "suspend", 0),
        ("resume", "paused", "running", "resume", 1),
        ("start", "paused", "running", "resume", 1),
        ("start", "stopped", "running", "start", 1),
        ("shutdown", "running", "stopped", "shutdown", 0),
        ("shutdown", "paused", "stopped", "shutdown", 0),
        ("reboot", "paused", "running", "reboot", 1),
        ("stop", "paused", "stopped", "stop", 0),
        ("reboot", "running", "running", "reboot", 1),
    ],
)
def test_power_verifies_transitions_and_never_implicitly_forces_shutdown(
    monkeypatch, action, before, after, command, onboot
):
    module = script("node-agent.py")
    states = iter([before, after])
    calls = []
    monkeypatch.setattr(module, "power_status", lambda m: next(states))
    monkeypatch.setattr(module, "run", lambda *a, **kw: calls.append((a, kw)))
    result = module.power_action({"vmid": 10100, "kind": "vm"}, {"onboot": 1 - onboot}, action)
    assert result["power_state"] == after
    assert result["changed"]
    assert result["boot_changed"] == (action == "reboot" or before == "stopped")
    command_index = 0
    if before == "paused" and action in ("shutdown", "reboot"):
        assert calls[0][0] == ("qm", "resume", 10100)
        command_index = 1
    assert calls[command_index][0][:3] == ("qm", command, 10100)
    assert calls[-1][0] == ("qm", "set", 10100, "--onboot", onboot)
    if action == "pause":
        assert calls[0][0][-2:] == ("--todisk", "0")
    if action == "shutdown":
        assert calls[command_index][0][-2:] == ("--forceStop", "0")
        assert not any(a[1] == "stop" for a, _ in calls)


@pytest.mark.parametrize(
    "action,state,onboot",
    [("start", "running", 1), ("shutdown", "stopped", 0), ("pause", "paused", 0), ("resume", "running", 1)],
)
def test_repeated_power_requests_are_noops(monkeypatch, action, state, onboot):
    module = script("node-agent.py")
    monkeypatch.setattr(module, "power_status", lambda m: state)
    calls = []
    monkeypatch.setattr(module, "run", lambda *a, **kw: calls.append(a))
    result = module.power_action({"vmid": 10100, "kind": "vm"}, {"onboot": onboot}, action)
    assert result == {"power_state": state, "changed": False, "boot_changed": False}
    assert calls == []


@pytest.mark.parametrize(
    "action,state",
    [
        ("pause", "stopped"),
        ("resume", "stopped"),
        ("reboot", "stopped"),
    ],
)
def test_invalid_power_transition_makes_no_changes(monkeypatch, action, state):
    module = script("node-agent.py")
    monkeypatch.setattr(module, "power_status", lambda m: state)
    calls = []
    monkeypatch.setattr(module, "run", lambda *a, **kw: calls.append(a))
    with pytest.raises(ValueError):
        module.power_action({"vmid": 10100, "kind": "vm"}, {"onboot": 1}, action)
    assert calls == []


def test_power_timeout_does_not_turn_into_force_stop_or_success(monkeypatch):
    module = script("node-agent.py")
    monkeypatch.setattr(module, "power_status", lambda m: "running")
    calls = []

    def fail(*args, **kwargs):
        calls.append(args)
        raise RuntimeError("graceful timeout")

    monkeypatch.setattr(module, "run", fail)
    with pytest.raises(RuntimeError, match="graceful timeout"):
        module.power_action({"vmid": 10100, "kind": "vm"}, {"onboot": 1}, "shutdown")
    assert len(calls) == 1 and calls[0][1] == "shutdown"
    monkeypatch.setattr(module, "run", lambda *a, **kw: calls.append(a))
    ticks = iter([0, 31])
    monkeypatch.setattr(module.time, "monotonic", lambda: next(ticks))
    with pytest.raises(ValueError, match="not confirmed"):
        module.power_action({"vmid": 10100, "kind": "vm"}, {"onboot": 1}, "pause")
    assert not any(a[1] == "set" for a in calls)
    for action in ("pause", "resume"):
        with pytest.raises(ValueError, match="CT checkpoint"):
            module.power_action({"vmid": 10100, "kind": "ct"}, {}, action)


def test_qemu_paused_status_is_not_running(monkeypatch):
    module = script("node-agent.py")
    monkeypatch.setattr(module, "pve_get", lambda *a, **kw: {"status": "running", "qmpstatus": "paused"})
    assert module.power_status({"kind": "vm", "vmid": 10100}) == "paused"


def test_reboot_waits_for_separate_pve_start_worker(monkeypatch):
    module = script("node-agent.py")
    states = iter(["running", "stopped", "running"])
    calls = []
    monkeypatch.setattr(module, "power_status", lambda m: next(states))
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(module, "run", lambda *a, **kw: calls.append(a))
    result = module.power_action({"vmid": 10100, "kind": "vm"}, {"onboot": 1}, "reboot")
    assert result == {"power_state": "running", "changed": True, "boot_changed": True}
    assert calls == [("qm", "reboot", 10100)]
