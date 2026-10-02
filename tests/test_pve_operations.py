import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from carrel.capacity import GIB, summarize


def script(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1] / "scripts" / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def test_inventory_stays_fresh_and_counts_every_volume(tmp_path, monkeypatch, capsys):
    module = script("node-agent.py")
    monkeypatch.setattr(module, "STATE", tmp_path)
    observed = {
        "resources": [],
        "storage": {"total": 1000 * GIB, "used": 100 * GIB},
        "status": {"cpuinfo": {"cpus": 8}, "memory": {"total": 64 * GIB}},
        "volumes": [
            {"content": "images", "size": 10 * GIB},  # Immutable template.
            {"content": "images", "size": 20 * GIB},  # Guest primary disk.
            {"content": "images", "size": 30 * GIB},  # Secondary or unused disk.
            {"content": "rootdir", "size": 40 * GIB},
            {"content": "backup", "size": 200 * GIB},
        ],
    }
    calls = []

    def run(*args, **kwargs):
        calls.append(args)
        if args[0].endswith("pve-read.pl"):
            return json.dumps(observed)
        assert args[0] == "lvs"
        return json.dumps({"report": [{"lv": [{"data_percent": "10", "metadata_percent": "2"}]}]})

    monkeypatch.setattr(module, "run", run)

    def inventory():
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b'{"op":"inventory"}')))
        module.main()
        return json.loads(capsys.readouterr().out)["result"]

    first = inventory()
    assert first["disk_committed_bytes"] == 100 * GIB
    assert not summarize(first)["policy"]["storage_admission_blocked"]
    observed["storage"]["used"] = 900 * GIB
    assert summarize(inventory())["policy"]["storage_admission_blocked"]
    assert sum(args[-1] == "inventory" for args in calls) == 2
    monkeypatch.setattr(module, "run", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("read failed")))
    with pytest.raises(RuntimeError, match="read failed"):
        inventory()


def test_topology_observes_missing_subnets_and_uses_one_gateway_entry(tmp_path, monkeypatch):
    module = script("node-agent.py")

    def local(path):
        path = Path(path)
        return path if path.is_relative_to(tmp_path) else tmp_path / str(path).lstrip("/")

    monkeypatch.setattr(module, "Path", local)
    monkeypatch.setattr(module, "STATE", tmp_path / "state")
    monkeypatch.setattr(module, "CONFIG", tmp_path / "node.json")
    monkeypatch.setattr(module, "NODE", "carrel01")
    module.CONFIG.write_text('{"protected_addresses": []}')
    local("/sys/class/net/t001").mkdir(parents=True)
    helper = local("/usr/local/lib/carrel/gateway-sync.py")
    helper.parent.mkdir(parents=True)
    helper.write_text("fixed gateway helper")
    topology = {"vnets": [{"vnet": "t001", "zone": "tenants"}], "subnets": {"t001": [{}]}}
    reads, entries, mutations = [], [], []

    def run(*args, **kwargs):
        if args[0].endswith("pve-read.pl"):
            reads.append(args)
            return json.dumps(topology)
        if args[0] == "pct":
            entries.append((args, kwargs))
        return "clsact"

    monkeypatch.setattr(module, "run", run)
    monkeypatch.setattr(module, "api", lambda *a, **kw: mutations.append((a, kw)))
    monkeypatch.setattr(module, "private_dhcp", lambda state: None)
    state = {"tenants": [{"n": 1, "slug": "alice"}], "networks": [], "machines": [], "domains": []}
    assert module.reconcile(state)["changed"] == []
    assert len(entries) == 1 and len(reads) == 1 and not mutations
    assert entries[0][0][:6] == ("pct", "exec", "101", "--", "python3", "-c")
    payload = json.loads(entries[0][1]["input"])
    assert payload["hosts"] == "" and "respond 404" in payload["caddy"]
    topology["subnets"]["t001"] = []
    assert module.reconcile(state)["changed"] == ["subnet-1"]
    assert len(reads) == 2
    assert mutations[0][0] == ("create", "/cluster/sdn/vnets/t001/subnets")
    assert mutations[1][0] == ("set", "/cluster/sdn")


def test_pve_reader_allows_only_fixed_get_operations(tmp_path):
    pve = tmp_path / "PVE"
    pve.mkdir()
    (pve / "API2.pm").write_text("""package PVE::API2;
sub find_handler {
    my ($class, $method, $path, $params) = @_;
    die "not GET" unless $method eq 'GET';
    $params->{path} = $path;
    return (__PACKAGE__, {});
}
sub handle {
    my ($class, $info, $params) = @_;
    my $path = $params->{path};
    return [{vnet => 't001'}, {vnet => 'p00101'}] if $path eq '/cluster/sdn/vnets';
    return [{subnet => 'fixture'}] if $path eq '/cluster/sdn/vnets/t001/subnets';
    return $path;
}
1;
""")
    (pve / "INotify.pm").write_text("package PVE::INotify; sub nodename { 'fixture' }; 1;\n")
    (pve / "RPCEnvironment.pm").write_text("package PVE::RPCEnvironment; sub setup_default_cli_env {} 1;\n")
    # JSON::PP is part of Perl core on the CI runner and sandbox.
    (tmp_path / "JSON.pm").write_text("""package JSON;
use JSON::PP ();
use Exporter 'import';
our @EXPORT_OK = qw(encode_json);
sub encode_json { JSON::PP::encode_json($_[0]) }
1;
""")
    command = ["perl", "-I", str(tmp_path), str(Path(__file__).parents[1] / "scripts/pve-read.pl")]
    topology = json.loads(subprocess.check_output([*command, "topology"]))
    assert topology["subnets"] == {"t001": [{"subnet": "fixture"}]}
    inventory = json.loads(subprocess.check_output([*command, "inventory"]))
    assert inventory == {
        "volumes": "/nodes/fixture/storage/local-lvm/content",
        "resources": "/cluster/resources",
        "storage": "/nodes/fixture/storage/local-lvm/status",
        "status": "/nodes/fixture/status",
    }
    for arguments in [["delete"], ["inventory", "/nodes/other/status"]]:
        result = subprocess.run([*command, *arguments], capture_output=True, check=False)
        assert result.returncode and not result.stdout


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
    monkeypatch.setattr(module, "api", lambda *a, **kw: {"status": "running", "qmpstatus": "paused"})
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
