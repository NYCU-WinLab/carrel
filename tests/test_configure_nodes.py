"""CT 100 reaches the node adapter on every site node (PLAN 15.15 gap 5)."""

import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE = json.loads((ROOT / "sites/b09/cluster.json").read_text())
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIControlPlaneKey"


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_first_exit_node_keeps_the_carrel_node_alias():
    nodes = load("configure-nodes.py").targets(SITE, "carrel01")
    assert nodes[0] == {
        "name": "carrel01",
        "target": "carrel-node",
        "host": "10.200.0.1",
        "address": "192.168.19.101",
    }
    assert [n["target"] for n in nodes[1:]] == ["carrel02", "carrel03", "carrel04"]
    assert nodes[2]["host"] == "192.168.19.103"


def test_one_authorized_line_serves_every_node_and_replaces_older_ones():
    module = load("configure-nodes.py")
    line = module.authorized_line(KEY, "192.168.19.101")
    assert (
        line
        == f'from="10.200.0.3,192.168.19.101",restrict,command="/usr/local/lib/carrel/node-agent.py" {KEY}'
    )
    existing = "\n".join(
        [
            "ssh-rsa AAAA root@carrel02",
            f'from="10.200.0.3",restrict,command="/usr/local/lib/carrel/node-agent.py" {KEY}',
        ]
    )
    merged = module.merge_authorized(existing, line, KEY).splitlines()
    assert merged == ["ssh-rsa AAAA root@carrel02", line]
    other = 'restrict,command="/usr/local/lib/carrel/node-agent.py",from="10.200.0.3" ssh-ed25519 OLDKEY'
    assert module.merge_authorized(other + "\n" + "\n".join(merged), line, KEY).splitlines() == merged
    assert module.merge_authorized("\n".join(merged), line, KEY).splitlines() == merged


def test_ssh_config_replaces_the_hand_written_node_block_and_keeps_other_hosts():
    module = load("configure-nodes.py")
    nodes = module.targets(SITE, "carrel01")
    legacy = "Host *\n  User root\nHost carrel-node\n  HostName 10.200.0.1\nHost carrel-backup\n  HostName 140.113.194.229\n  Port 1121\n"
    first = module.ssh_config(legacy, nodes)
    assert (
        first.count("Host carrel-node\n") == 1
        and "Host carrel-backup\n  HostName 140.113.194.229\n  Port 1121" in first
    )
    assert "Host carrel04\n  HostName 192.168.19.104" in first
    assert module.ssh_config(first, nodes) == first
    fresh = module.ssh_config("", nodes)
    assert fresh.startswith("Host *\n  User root\n  IdentityFile /etc/carrel/node_key")


def test_known_hosts_pins_each_node_and_keeps_other_hosts():
    module = load("configure-nodes.py")
    existing = "10.200.0.1 ssh-ed25519 OLD\n[140.113.194.229]:1121 ssh-ed25519 BACKUP\n"
    merged = module.known_hosts(
        existing, [("10.200.0.1", "ssh-ed25519 NEW"), ("192.168.19.102", "ssh-ed25519 TWO")]
    )
    assert merged.splitlines() == [
        "[140.113.194.229]:1121 ssh-ed25519 BACKUP",
        "10.200.0.1 ssh-ed25519 NEW",
        "192.168.19.102 ssh-ed25519 TWO",
    ]


def test_infra_firewall_lets_the_control_plane_reach_peer_ssh():
    module = load("bootstrap-platform.py")
    assert module.peer_ssh(SITE, "carrel01") == [
        'iifname "vmbr98" ip saddr 10.200.0.3 ip daddr { 192.168.19.102, 192.168.19.103, 192.168.19.104 } tcp dport 22 accept'
    ]


def test_authorized_keys_are_replaced_by_rename(tmp_path):
    module = load("configure-nodes.py")
    target = tmp_path / "authorized_keys"
    target.write_text("old\n")
    link = tmp_path / "link"
    link.symlink_to(target)
    module.replace_file(link, "new\n", 0o600)
    assert target.read_text() == "new\n" and link.is_symlink()
    assert (
        oct(target.stat().st_mode & 0o777) == "0o600"
        and not (tmp_path / "authorized_keys.carrel-next").exists()
    )


def test_a_node_name_cannot_inject_ssh_options():
    import pytest

    site = {**SITE, "nodes": [*SITE["nodes"], {"name": "x\n  ProxyCommand sh", "address": "192.168.19.105"}]}
    with pytest.raises(SystemExit):
        load("configure-nodes.py").targets(site, "carrel01")


def test_bootstrap_runs_only_on_the_first_exit_node_of_the_site(monkeypatch, tmp_path):
    module = load("bootstrap-platform.py")
    (tmp_path / "site.json").write_text(json.dumps(SITE))
    monkeypatch.setattr(module, "SITE", tmp_path / "site.json")
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: "carrel02")
    monkeypatch.setattr(sys, "argv", ["bootstrap-platform.py", "--admin-key", "k"])
    try:
        module.main()
    except AssertionError as e:
        assert "first exit node" in str(e)
    else:
        raise AssertionError("bootstrap ran on a node that is not the first exit node")


def test_infra_containers_match_the_infra_bridge_mtu(monkeypatch):
    module = load("bootstrap-platform.py")
    calls = []
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: calls.append(args) or "status: running")
    real = Path
    # No existing CT config and no cached template; everything else is real.
    monkeypatch.setattr(
        module,
        "Path",
        lambda p: (
            real("/nonexistent") / str(p).lstrip("/")
            if str(p).startswith(("/etc/pve", "/var/lib/vz"))
            else real(p)
        ),
    )
    module.ct(
        101, "carrel-gateway", "10.200.0.2", "vmbr98", "10.200.0.1", 512, "k", "local-zfs", "local:vztmpl/t"
    )
    net = next(a[a.index("--net0") + 1] for a in calls if "--net0" in a)
    assert net.endswith(",mtu=1450")


def test_the_gateway_takes_the_control_planes_keys_as_a_forced_command(monkeypatch):
    module = load("configure-nodes.py")
    calls = []

    def run(*args, input=None):
        calls.append((args, input))
        if args[-1] == "cat /root/.ssh/authorized_keys 2>/dev/null || true":
            return 'ssh-ed25519 ADMIN admin\nfrom="10.200.0.3",restrict,command="/usr/local/lib/carrel/gateway-sync.py" ssh-ed25519 OLD\n'
        if args[-1] == "/etc/ssh/ssh_host_ed25519_key.pub":
            return "ssh-ed25519 HOSTKEY root@carrel-gateway\n"
        return ""

    monkeypatch.setattr(module, "run", run)
    assert module.gateway("ssh-ed25519 NEW") == "ssh-ed25519 HOSTKEY"
    written = next(i for a, i in calls if i and "authorized_keys.carrel-next" in a[-1])
    lines = written.splitlines()
    assert lines[0] == "ssh-ed25519 ADMIN admin"
    assert lines[1:] == [
        'from="10.200.0.3",restrict,command="/usr/local/lib/carrel/gateway-sync.py" ssh-ed25519 NEW'
    ]
    assert ("pct", "push", "101", module.GATEWAY_SYNC, module.GATEWAY_SYNC, "--perms", "755") in [
        a for a, _ in calls
    ]
    sshd = next(i for a, i in calls if i and "sshd_config.d/carrel.conf" in a[-1])
    assert "PasswordAuthentication no" in sshd.splitlines()
    assert "reload" not in next(a[-1] for a, i in calls if i == sshd)
    config = module.ssh_config("", [*module.targets(SITE, "carrel01"), module.GATEWAY])
    assert "Host carrel-gateway\n  HostName 10.200.0.2" in config
    # The service key and, until #604, the node key: both lines replace the old one.
    calls.clear()
    module.gateway("ssh-ed25519 SERVICE", "ssh-ed25519 NODE")
    written = next(i for a, i in calls if i and "authorized_keys.carrel-next" in a[-1])
    assert written.splitlines()[1:] == [
        'from="10.200.0.3",restrict,command="/usr/local/lib/carrel/gateway-sync.py" ssh-ed25519 SERVICE',
        'from="10.200.0.3",restrict,command="/usr/local/lib/carrel/gateway-sync.py" ssh-ed25519 NODE',
    ]


def test_the_pinned_caddy_replaces_the_running_package_caddy(monkeypatch, tmp_path):
    module = load("bootstrap-platform.py")
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as tar:
        info = tarfile.TarInfo("caddy")
        info.size = 4
        tar.addfile(info, io.BytesIO(b"\x7fELF"))
    data = archive.getvalue()
    monkeypatch.setattr(module, "CADDY_SHA512", hashlib.sha512(data).hexdigest())
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda url, timeout: io.BytesIO(data))
    calls = []
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: calls.append(args))
    module.caddy(101)
    steps = [a[4:] for a in calls if a[:2] == ("pct", "exec")]
    assert steps.index(("systemctl", "daemon-reload")) < steps.index(("systemctl", "restart", "caddy"))


def test_infra_cts_keep_mtu_1450_and_reruns_repair_existing_ones(monkeypatch, tmp_path):
    module = load("bootstrap-platform.py")
    calls = []

    def run(*args, capture=False):
        calls.append(args)
        return "status: running" if args[:2] == ("pct", "status") else None

    monkeypatch.setattr(module, "run", run)
    conf = tmp_path / "101.conf"
    conf.write_text("hostname: carrel-gateway\ntags: carrel-infra\n")
    monkeypatch.setattr(module, "Path", lambda p: conf if p == "/etc/pve/lxc/101.conf" else Path(p))
    module.ct(101, "carrel-gateway", "10.200.0.2", "vmbr98", "10.200.0.1", 512, "k", "local", "t")
    script = next(c[-1] for c in calls if c[:2] == ("pct", "exec") and c[4:6] == ("sh", "-c"))
    assert ("pct", "exec", "101", "--", "ip", "link", "set", "eth0", "mtu", "1450") in calls
    # The shell edit itself: adds the line once, under the eth0 stanza.
    interfaces = tmp_path / "interfaces"
    interfaces.write_text("auto eth0\niface eth0 inet static\n\taddress 10.200.0.2/24\n")
    for _ in range(2):
        subprocess.run(["sh", "-c", script.replace("/etc/network/interfaces", str(interfaces))], check=True)
    assert (
        interfaces.read_text() == "auto eth0\niface eth0 inet static\n\tmtu 1450\n\taddress 10.200.0.2/24\n"
    )


def test_infra_mtu_skips_other_bridges_and_stopped_cts(monkeypatch):
    module = load("bootstrap-platform.py")
    calls = []
    monkeypatch.setattr(module, "run", lambda *a, capture=False: calls.append(a) or "status: stopped")
    module.infra_mtu(103, "vmbr0")
    assert calls == []
    module.infra_mtu(103, "t255")
    assert calls == [("pct", "status", "103")]


def apply_jump_certs(
    tmp_path,
    text="new\n",
    sshd_ok=True,
    systemctl_ok=True,
    rm_fails=False,
    mv_fails=False,
    sshd_results=None,
    unit_state=False,
):
    # Stub sshd and systemctl: a log of calls, and each fails on demand.
    # sshd_results: the exit status of the nth `sshd -t` (the last one repeats).
    # unit_state: systemctl tracks the unit; try-restart fails and leaves it
    # stopped, only `restart` starts it again.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "calls"
    state = tmp_path / "unit"
    state.write_text("running\n")
    results = sshd_results or [0 if sshd_ok else 1]
    case = "".join(f"{i}) exit {r};; " for i, r in enumerate(results[:-1])) + f"*) exit {results[-1]};;"
    sshd = bin_dir / "sshd"
    sshd.write_text(
        f'#!/bin/sh\necho "sshd $*" >> {log}\nn=$(grep -c "^sshd " {log})\ncase $((n - 1)) in {case} esac\n'
    )
    systemctl = bin_dir / "systemctl"
    if unit_state:
        body = (
            f'case "$1" in try-restart) echo stopped > {state}; exit 1;; '
            f"restart) echo running > {state}; exit 0;; esac\nexit 0\n"
        )
    else:
        body = f"exit {0 if systemctl_ok else 1}\n"
    systemctl.write_text(f'#!/bin/sh\necho "systemctl $*" >> {log}\n{body}')
    for stub in (sshd, systemctl):
        stub.chmod(0o755)
    f = tmp_path / "carrel-jump-certs.conf"
    if rm_fails:
        # Fails only for the rollback's `rm -f <drop-in>`, not for the .next and .prev cleanups.
        rm = bin_dir / "rm"
        rm.write_text(
            '#!/bin/sh\nfor last; do :; done\ncase "$last" in *.next|*.prev) exec /bin/rm "$@";; esac\nexit 1\n'
        )
        rm.chmod(0o755)
    if mv_fails:
        # Fails only for the rollback's `mv <drop-in>.prev <drop-in>`, not the staging `mv .next`.
        mv = bin_dir / "mv"
        mv.write_text('#!/bin/sh\ncase "$1" in *.prev) exit 1;; esac\nexec /bin/mv "$@"\n')
        mv.chmod(0o755)
    script = load("configure-nodes.py").jump_cert_apply(f)
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin"}
    result = subprocess.run(
        ["sh", "-c", script], input=text, text=True, env=env, capture_output=True, check=False
    )
    calls = log.read_text().splitlines() if log.exists() else []
    return result.returncode, f, calls, result


def test_jump_certs_replace_the_drop_in_and_restart_ssh(tmp_path):
    (tmp_path / "carrel-jump-certs.conf").write_text("old\n")
    code, f, calls, _ = apply_jump_certs(tmp_path)
    assert code == 0
    assert f.read_text() == "new\n"
    assert calls == ["sshd -t", "systemctl try-restart ssh.service"]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["bin", "calls", f.name, "unit"]


def test_a_failed_staging_step_leaves_the_live_jump_drop_in_alone(tmp_path):
    (tmp_path / "carrel-jump-certs.conf").write_text("old\n")
    (tmp_path / "carrel-jump-certs.conf.prev").write_text("stale\n")
    (tmp_path / "carrel-jump-certs.conf.next").mkdir()  # cat > .next fails
    code, f, calls, _ = apply_jump_certs(tmp_path)
    assert code == 1
    assert f.read_text() == "old\n"
    assert calls == []
    assert not (tmp_path / "carrel-jump-certs.conf.prev").exists()


def test_a_failed_check_restores_this_runs_jump_drop_in_not_a_stale_one(tmp_path):
    (tmp_path / "carrel-jump-certs.conf").write_text("old\n")
    (tmp_path / "carrel-jump-certs.conf.prev").write_text("stale\n")
    code, f, calls, _ = apply_jump_certs(tmp_path, sshd_ok=False)
    assert code == 1
    assert f.read_text() == "old\n"
    assert calls == ["sshd -t"]  # the running sshd is left alone
    assert not (tmp_path / "carrel-jump-certs.conf.prev").exists()


def test_a_failed_check_without_a_previous_jump_drop_in_removes_the_new_one(tmp_path):
    code, f, calls, _ = apply_jump_certs(tmp_path, sshd_ok=False)
    assert code == 1
    assert not f.exists()
    assert calls == ["sshd -t"]


def test_a_failed_restart_restores_the_jump_drop_in_and_checks_before_restarting(tmp_path):
    (tmp_path / "carrel-jump-certs.conf").write_text("old\n")
    code, f, calls, _ = apply_jump_certs(tmp_path, systemctl_ok=False)
    assert code == 1
    assert f.read_text() == "old\n"
    assert calls == [
        "sshd -t",
        "systemctl try-restart ssh.service",
        "sshd -t",
        "systemctl reset-failed ssh.service",
        "systemctl restart ssh.service",
    ]
    assert not (tmp_path / "carrel-jump-certs.conf.prev").exists()


def test_a_failed_restart_brings_sshd_back_when_the_unit_is_left_stopped(tmp_path):
    (tmp_path / "carrel-jump-certs.conf").write_text("old\n")
    code, f, _, _ = apply_jump_certs(tmp_path, unit_state=True)
    assert code == 1
    assert f.read_text() == "old\n"
    assert (tmp_path / "unit").read_text() == "running\n"


def test_a_restored_file_that_fails_the_check_gets_no_restart(tmp_path):
    (tmp_path / "carrel-jump-certs.conf").write_text("old\n")
    # The new file passes sshd -t, the restart fails, the restored file fails sshd -t.
    code, f, calls, _ = apply_jump_certs(tmp_path, systemctl_ok=False, sshd_results=[0, 1])
    assert code == 1
    assert f.read_text() == "old\n"
    assert calls == ["sshd -t", "systemctl try-restart ssh.service", "sshd -t"]


def test_a_failed_rollback_step_stops_without_calling_systemd(tmp_path):
    code, _, calls, result = apply_jump_certs(tmp_path, systemctl_ok=False, rm_fails=True)
    assert code == 1
    assert calls == ["sshd -t", "systemctl try-restart ssh.service"]  # no second check, no restart
    assert "rollback failed" in result.stderr and "unknown state" in result.stderr


def test_a_failed_restore_of_an_existing_drop_in_stops_without_calling_systemd(tmp_path):
    (tmp_path / "carrel-jump-certs.conf").write_text("old\n")
    code, _, calls, result = apply_jump_certs(tmp_path, systemctl_ok=False, mv_fails=True)
    assert code == 1
    assert calls == ["sshd -t", "systemctl try-restart ssh.service"]
    assert "rollback failed" in result.stderr and "unknown state" in result.stderr


def test_a_failed_check_with_a_failed_rollback_reports_and_leaves_sshd_alone(tmp_path):
    code, _, calls, result = apply_jump_certs(tmp_path, sshd_ok=False, rm_fails=True)
    assert code == 1
    assert calls == ["sshd -t"]
    assert "rollback failed" in result.stderr and "unknown state" in result.stderr


def test_a_failed_check_with_a_failed_restore_of_an_existing_drop_in_reports(tmp_path):
    (tmp_path / "carrel-jump-certs.conf").write_text("old\n")
    code, _, calls, result = apply_jump_certs(tmp_path, sshd_ok=False, mv_fails=True)
    assert code == 1
    assert calls == ["sshd -t"]
    assert "rollback failed" in result.stderr and "unknown state" in result.stderr


def test_ksmtuned_is_disabled_masked_and_ksm_stopped_on_every_node(monkeypatch):
    module = load("configure-nodes.py")
    nodes = module.targets(SITE, "carrel01")
    calls = []
    monkeypatch.setattr(module, "run", lambda *args, **kwargs: calls.append(args))
    for n in nodes:
        module.ksm_off(n, n is nodes[0])
    assert calls[0] == ("sh", "-c", module.KSM_OFF)
    assert [c[-2] for c in calls[1:]] == [f"root@{n['address']}" for n in nodes[1:]]
    assert all(c[-1] == module.KSM_OFF for c in calls[1:])
    assert "systemctl disable --now ksmtuned.service || true" in module.KSM_OFF
    assert "systemctl mask ksmtuned.service" in module.KSM_OFF
    assert "echo 0 > /sys/kernel/mm/ksm/run" in module.KSM_OFF


def test_the_ksm_command_succeeds_on_a_second_run_and_when_the_unit_is_absent(tmp_path):
    module = load("configure-nodes.py")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "systemctl").write_text('#!/bin/sh\n[ "$1" = disable ] && exit 5\nexit 0\n')
    (bin_dir / "systemctl").chmod(0o755)
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin"}
    run_file = tmp_path / "run"
    run_file.write_text("1\n")
    command = module.KSM_OFF.replace("/sys/kernel/mm/ksm/run", str(run_file))
    for _ in range(2):
        done = subprocess.run(["sh", "-c", command], env=env, capture_output=True, text=True, check=False)
        assert done.returncode == 0, done.stderr
        assert run_file.read_text() == "0\n"
    # No KSM in the kernel: nothing to write, still fine.
    run_file.unlink()
    done = subprocess.run(["sh", "-c", command], env=env, capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr


def test_any_site_node_may_run_the_agent():
    module = load("configure-nodes.py")
    nodes = module.targets(SITE, "carrel01")
    assert module.agent_nodes({}, nodes) == set()
    assert module.agent_nodes({"agent_nodes": ["carrel01", "carrel02"]}, nodes) == {"carrel01", "carrel02"}
    try:
        module.agent_nodes({"agent_nodes": ["pve9"]}, nodes)
    except SystemExit as e:
        assert "not a site node" in str(e)
    else:
        raise AssertionError("pve9")


def test_an_agent_node_carries_its_transport_and_the_others_stay_on_ssh():
    module = load("configure-nodes.py")
    nodes = module.targets(SITE, "carrel01")
    entries = module.node_entries(
        nodes, {"carrel01", "carrel02"}, {"carrel01": "ab" * 32, "carrel02": "cd" * 32}
    )
    assert entries[0] == {
        "name": "carrel01",
        "target": "carrel-node",
        "transport": "agent",
        "agent_token_sha256": "ab" * 32,
        "agent_source": "10.200.0.1",
    }
    # Another node is seen at its own underlay address, with its own token.
    assert entries[1] == {
        "name": "carrel02",
        "target": "carrel02",
        "transport": "agent",
        "agent_token_sha256": "cd" * 32,
        "agent_source": nodes[1]["address"],
    }
    assert entries[2] == {"name": "carrel03", "target": "carrel03"}
    assert module.node_entries(nodes, set(), {}) == [
        {"name": n["name"], "target": n["target"]} for n in nodes
    ]


def test_another_node_routes_to_the_listener_through_the_first_node_from_its_own_address():
    module = load("configure-nodes.py")
    nodes = module.targets(SITE, "carrel01")
    unit = module.peer_unit(nodes[0], nodes[1])
    route = f"ExecStartPre=/usr/sbin/ip route replace 10.200.0.3/32 via {nodes[0]['address']} src {nodes[1]['address']}"
    assert route in unit and unit.index(route) < unit.index("ExecStart=/usr/local")


def test_infra_firewall_admits_the_agent_port_from_the_other_nodes_only():
    module = load("bootstrap-platform.py")
    [rule] = module.peer_agent(SITE, "carrel01")
    assert rule.startswith(
        f'iifname "{SITE["underlay_interface"]}" oifname "vmbr98" ip saddr {{ 192.168.19.102,'
    )
    assert "192.168.19.101" not in rule and rule.endswith("ip daddr 10.200.0.3 tcp dport 8443 accept")


def test_the_agent_token_is_made_once_and_its_digest_matches(tmp_path, monkeypatch):
    module = load("configure-nodes.py")
    monkeypatch.setattr(module, "AGENT_TOKEN", tmp_path / "agent-token")
    first = module.agent_token()
    token = (tmp_path / "agent-token").read_text()
    assert len(token) >= 40 and (tmp_path / "agent-token").stat().st_mode & 0o777 == 0o600
    assert first == hashlib.sha256(token.encode()).hexdigest()
    assert module.agent_token() == first and (tmp_path / "agent-token").read_text() == token


def test_the_agent_certificates_chain_to_the_ca_and_a_second_run_keeps_them(tmp_path):
    module = load("configure-nodes.py")
    script = module.AGENT_CERTIFICATES.replace(str(module.AGENT_CA), str(tmp_path / "ca"))
    subprocess.run(["sh", "-c", script], check=True, capture_output=True)
    d = tmp_path / "ca"
    files = {name: (d / name).read_bytes() for name in ("ca.key", "ca.pem", "server.key", "server.pem")}
    assert (d / "ca.key").stat().st_mode & 0o777 == 0o600
    subprocess.run(
        ["openssl", "verify", "-CAfile", d / "ca.pem", d / "server.pem"], check=True, capture_output=True
    )
    text = subprocess.run(
        ["openssl", "x509", "-in", d / "server.pem", "-noout", "-text"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "IP Address:10.200.0.3" in text and "TLS Web Server Authentication" in text
    subprocess.run(["sh", "-c", script], check=True, capture_output=True)
    assert {name: (d / name).read_bytes() for name in files} == files
    assert sorted(p.name for p in d.iterdir()) == sorted(files)
    # A new CA makes a new listener certificate under it.
    (d / "ca.key").unlink()
    subprocess.run(["sh", "-c", script], check=True, capture_output=True)
    assert (d / "server.pem").read_bytes() != files["server.pem"]
    subprocess.run(
        ["openssl", "verify", "-CAfile", d / "ca.pem", d / "server.pem"], check=True, capture_output=True
    )


def test_the_agent_unit_lets_running_jobs_finish():
    unit = load("configure-nodes.py").AGENT_SERVICE
    assert "KillMode=mixed" in unit and "TimeoutStopSec=4h30min" in unit
    assert "ExecStart=/usr/local/lib/carrel/carrel-agent -config /etc/carrel/agent.json" in unit


def test_the_agent_service_follows_the_site_file_without_blocking(tmp_path, monkeypatch):
    module = load("configure-nodes.py")
    calls = []
    monkeypatch.setattr(module, "run", lambda *a, **kw: calls.append(a) or "")
    monkeypatch.setattr(module.socket, "gethostname", lambda: "carrel01")
    monkeypatch.setattr(module, "SITE", tmp_path / "site.json")
    monkeypatch.setattr(module, "AGENT_JSON", tmp_path / "agent.json")
    monkeypatch.setattr(module, "AGENT_UNIT", tmp_path / "carrel-agent.service")
    ssh_only = {k: v for k, v in SITE.items() if k != "agent_nodes"}
    assert module.SITE.write_text(json.dumps(ssh_only)) and module.agent_service() == "absent"
    assert calls == []
    module.SITE.write_text(json.dumps({**SITE, "agent_nodes": ["carrel01"]}))
    assert module.agent_service() == "started"
    assert json.loads((tmp_path / "agent.json").read_text()) == {
        "control": "https://10.200.0.3:8443",
        "ca_file": "/etc/carrel/agent-ca/ca.pem",
        "token_file": "/etc/carrel/agent-token",
        "node": "carrel01",
    }
    assert ("systemctl", "restart", "--no-block", "carrel-agent.service") in calls
    calls.clear()
    module.SITE.write_text(json.dumps(ssh_only))
    assert module.agent_service() == "stopped"
    assert calls == [("systemctl", "disable", "--now", "--no-block", "carrel-agent.service")]


def test_a_token_rotates_only_when_asked_and_the_old_one_stays_until_then(tmp_path, monkeypatch):
    module = load("configure-nodes.py")
    monkeypatch.setattr(module, "AGENT_TOKEN", tmp_path / "agent-token")
    monkeypatch.setattr(module, "AGENT_ROTATE", tmp_path / "agent-token.rotate")
    first = module.agent_token()
    assert module.agent_token() == first
    (tmp_path / "agent-token.rotate").touch()
    second = module.agent_token()
    assert second != first and not (tmp_path / "agent-token.rotate").exists()
    assert (tmp_path / "agent-token").stat().st_mode & 0o777 == 0o600


def test_a_peer_agent_that_never_connects_is_named(tmp_path, monkeypatch):
    module = load("configure-nodes.py")
    site = {**SITE, "agent_nodes": ["carrel02", "carrel03"]}
    (tmp_path / "site.json").write_text(json.dumps(site))
    monkeypatch.setattr(module, "SITE", tmp_path / "site.json")
    monkeypatch.setattr(module.socket, "gethostname", lambda: "carrel01")
    monkeypatch.setattr(module.time, "sleep", lambda s: None)
    nodes = module.targets(SITE, "carrel01")
    seen = []

    def fake(args, **kw):
        seen.append(args)
        connected = args[-2] == "root@" + nodes[1]["address"]
        assert (
            "ConnectTimeout=5" in args and args[-1] == "journalctl -u carrel-agent --since @1700000000 -o cat"
        )
        return subprocess.CompletedProcess(args, 0, '{"msg":"agent_connected"}' if connected else "", "")

    monkeypatch.setattr(module.subprocess, "run", fake)
    assert module.peers_connected(1700000000, wait=3) == ["carrel03"]
    # carrel02 is asked once, carrel03 on every round.
    assert sum(a[-2].endswith(nodes[1]["address"]) for a in seen) == 1
    assert sum(a[-2].endswith(nodes[2]["address"]) for a in seen) == 3


def test_the_handbook_names_the_rotate_files_the_code_reads():
    module = load("configure-nodes.py")
    handbook = (ROOT / "docs/operator-handbook.md").read_text()
    assert f"`{module.AGENT_ROTATE}`" in handbook
    assert f"`{module.AGENT_TOKENS}/<node>.rotate`" in handbook
    assert "bootstrap-platform.py --firewall" in handbook and "8443" in handbook


def test_ssh_config_gives_the_gateway_jump_and_backup_the_service_key():
    module = load("configure-nodes.py")
    nodes = module.targets(SITE, "carrel01")
    legacy = "Host *\n  User root\n  IdentityFile /etc/carrel/node_key\nHost carrel-backup\n  HostName 140.113.194.229\n  Port 1121\n"
    config = module.ssh_config(legacy, [*nodes, module.GATEWAY, module.JUMP, module.BACKUP])
    assert "Host carrel-gateway\n  HostName 10.200.0.2\n  IdentityFile /etc/carrel/service_key\n" in config
    assert "Host carrel-jump\n  HostName 10.200.0.4\n  IdentityFile /etc/carrel/service_key\n" in config
    # The hand-written address of the backup target stays; only its key is added.
    assert "Host carrel-backup\n  HostName 140.113.194.229\n  Port 1121\n" in config
    assert "Host carrel-backup\n  IdentityFile /etc/carrel/service_key\n" in config
    # Nodes keep the node key of "Host *" and get no service key.
    assert "Host carrel-node\n  HostName 10.200.0.1\nHost" in config
    assert module.ssh_config(config, [*nodes, module.GATEWAY, module.JUMP, module.BACKUP]) == config


def test_the_jump_host_takes_both_keys_as_a_forced_command(monkeypatch):
    module = load("configure-nodes.py")
    calls = []

    def run(*args, input=None):
        calls.append((args, input))
        if args[-1] == "cat /root/.ssh/authorized_keys 2>/dev/null || true":
            return 'ssh-ed25519 ADMIN admin\nfrom="10.200.0.3",restrict,command="/usr/local/lib/carrel/jump-sync.py" ssh-ed25519 OLD\n'
        if args[-1] == "/etc/ssh/ssh_host_ed25519_key.pub":
            return "ssh-ed25519 HOSTKEY root@carrel-jump\n"
        return ""

    monkeypatch.setattr(module, "run", run)
    assert module.jump("ssh-ed25519 SERVICE", "ssh-ed25519 NODE") == "ssh-ed25519 HOSTKEY"
    written = next(i for a, i in calls if i and "authorized_keys.carrel-next" in a[-1])
    assert written.splitlines() == [
        "ssh-ed25519 ADMIN admin",
        'from="10.200.0.3",restrict,command="/usr/local/lib/carrel/jump-sync.py" ssh-ed25519 SERVICE',
        'from="10.200.0.3",restrict,command="/usr/local/lib/carrel/jump-sync.py" ssh-ed25519 NODE',
    ]


CA = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEypPi2e="


def apply_node_sshd(tmp_path, site, reload_fails=0, sshd_t="0", in_force=True):
    """Run the node sshd script against files under tmp_path with stub sshd
    and systemctl. reload_fails: how many reloads fail before one works."""
    module = load("configure-nodes.py")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "log"
    log.unlink(missing_ok=True)
    ca = tmp_path / "ca.pub"
    shown = "passwordauthentication no\\n" + (f"trustedusercakeys {ca}\\n" if in_force else "")
    (bin_dir / "sshd").write_text(
        f'#!/bin/sh\necho "sshd $*" >> {log}\n[ "$1" = -T ] && printf "{shown}"\n[ "$1" = -t ] && exit {sshd_t}\nexit 0\n'
    )
    (bin_dir / "systemctl").write_text(
        f'#!/bin/sh\necho "systemctl $*" >> {log}\nn=$(grep -c "^systemctl reload" {log})\n[ "$n" -le {reload_fails} ] && exit 1\nexit 0\n'
    )
    for stub in ("sshd", "systemctl"):
        (bin_dir / stub).chmod(0o755)
    conf, script = module.node_sshd_apply(
        site, str(tmp_path / "drop.conf"), str(ca), str(tmp_path / "principals")
    )
    result = subprocess.run(
        ["sh", "-c", script],
        input=conf,
        text=True,
        capture_output=True,
        check=False,
        env={"PATH": f"{bin_dir}:/usr/bin:/bin"},
    )
    calls = log.read_text().splitlines() if log.exists() else []
    return result.returncode, conf, calls


def files(tmp_path):
    return sorted(
        str(p.relative_to(tmp_path))
        for p in tmp_path.rglob("*")
        if p.is_file() and "bin" not in p.parts and p.name != "log"
    )


def test_node_root_takes_lab_certificates_for_the_principals_the_site_names(tmp_path):
    module = load("configure-nodes.py")
    (tmp_path / "drop.conf").write_text(module.NODE_SSHD)
    site = {
        "node_ssh_ca": {"key": CA + " lab-ssh-ca", "principals": ["zyx1121", "svc:carrel-admin", "zyx1121"]}
    }
    code, conf, _ = apply_node_sshd(tmp_path, site)
    assert code == 0
    assert conf.startswith(module.NODE_SSHD)
    assert f"TrustedUserCAKeys {tmp_path}/ca.pub\n" in conf
    assert f"AuthorizedPrincipalsFile {tmp_path}/principals/%u\n" in conf
    assert (tmp_path / "drop.conf").read_text() == conf
    assert (tmp_path / "ca.pub").read_text() == CA + "\n"
    assert (tmp_path / "principals/root").read_text() == "svc:carrel-admin\nzyx1121\n"
    assert files(tmp_path) == ["ca.pub", "drop.conf", "principals/root"]
    # The site drops the setting: the files go and the drop-in has keys only.
    code, conf, _ = apply_node_sshd(tmp_path, {})
    assert code == 0 and conf == module.NODE_SSHD
    assert files(tmp_path) == ["drop.conf"]
    assert (tmp_path / "drop.conf").read_text() == module.NODE_SSHD


def test_a_failed_node_sshd_apply_puts_the_previous_policy_back(tmp_path):
    module = load("configure-nodes.py")
    before = {
        "drop.conf": "previous drop-in\n",
        "ca.pub": "previous ca\n",
        "principals/root": "alice\n",
        "principals/other": "bob\n",
    }

    def seed():
        for name in ["drop.conf", "ca.pub"]:
            (tmp_path / name).write_text(before[name])
        (tmp_path / "principals").mkdir(exist_ok=True)
        for name in ["principals/root", "principals/other"]:
            (tmp_path / name).write_text(before[name])

    site = {"node_ssh_ca": {"key": CA, "principals": ["zyx1121"]}}
    for case in [{"reload_fails": 1}, {"sshd_t": "1"}, {"in_force": False}, {}]:
        seed()
        removing = case == {}
        if removing:
            # Removing the setting, with sshd -t failing: nothing is removed.
            code, _, _ = apply_node_sshd(tmp_path, {}, sshd_t="1")
        else:
            code, _, calls = apply_node_sshd(tmp_path, site, **case)
            # After a reload, the restored policy is loaded again.
            reloads = calls.count("systemctl reload ssh.service")
            assert reloads == (0 if case.get("sshd_t") else 2), (case, calls)
        assert code == 1, case
        assert files(tmp_path) == sorted(before), case
        for name, text in before.items():
            assert (tmp_path / name).read_text() == text, (case, name)
    assert module.NODE_SSHD not in (tmp_path / "drop.conf").read_text()


def test_a_new_node_sshd_drop_in_that_fails_is_removed(tmp_path):
    code, _, calls = apply_node_sshd(tmp_path, {}, sshd_t="1")
    assert code == 1
    assert files(tmp_path) == []
    assert "systemctl reload ssh.service" not in calls


def test_a_bad_node_ca_setting_is_refused():
    module = load("configure-nodes.py")
    for ca in [
        {"key": "not a key", "principals": ["zyx1121"]},
        {"key": CA, "principals": []},
        {"key": CA, "principals": "zyx1121"},
        {"key": CA, "principals": ["a b"]},
        {"key": CA, "principals": ["zyx1121\nroot"]},
        {"key": CA, "principals": ["$(reboot)"]},
        {"key": CA, "principals": ["svc:"]},
        {"key": CA, "principals": ["project:robotics"]},
    ]:
        try:
            module.node_ssh_ca({"node_ssh_ca": ca})
        except SystemExit:
            continue
        raise AssertionError(ca)
    for value in ["ssh-ed25519 AAAA", ["x"]]:
        try:
            module.node_ssh_ca({"node_ssh_ca": value})
        except SystemExit:
            continue
        raise AssertionError(value)
    # Only the key type and the key are kept, never a line after them.
    key, _ = module.node_ssh_ca(
        {"node_ssh_ca": {"key": CA + "\nPermitRootLogin yes", "principals": ["zyx1121"]}}
    )
    assert key == CA


def test_the_b09_site_node_ca_setting_is_valid():
    module = load("configure-nodes.py")
    key, principals = module.node_ssh_ca(SITE)
    assert key.startswith("ecdsa-sha2-nistp256 ") and principals


IDENTITY = {
    "ca_url": "https://ca.winlab.tw",
    "lab_root": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    "provisioner": "5Ys6ZRy1hvsI-FHi_831uQptxvkKQ3vtGxyz-TzbwGw",
    "certificate_nodes": ["carrel02"],
}


def test_agent_identity_is_checked_before_anything_changes():
    module = load("configure-nodes.py")
    nodes = module.targets(SITE, "carrel01")
    agents = {"carrel01", "carrel02"}
    assert module.agent_identity({**SITE, "agent_identity": IDENTITY}, nodes, agents) == IDENTITY
    assert module.agent_identity(SITE, nodes, agents) is None
    for bad, says in [
        ({**IDENTITY, "ca_url": "http://ca.winlab.tw"}, "https URL"),
        ({**IDENTITY, "ca_url": "https://ca.winlab.tw/x"}, "https URL"),
        ({**IDENTITY, "provisioner": "short"}, "key id"),
        ({**IDENTITY, "lab_root": "not a certificate"}, "PEM"),
        ({**IDENTITY, "lab_root": IDENTITY["lab_root"] * 2}, "PEM"),
        ({**IDENTITY, "certificate_nodes": ["carrel03"]}, "not in agent_nodes"),
        ({**IDENTITY, "token": "x"}, "takes ca_url"),
    ]:
        try:
            module.agent_identity({**SITE, "agent_identity": bad}, nodes, agents)
        except SystemExit as e:
            assert says in str(e), (bad, e)
        else:
            raise AssertionError(bad)


def test_a_certificate_node_carries_its_name_and_no_token():
    module = load("configure-nodes.py")
    nodes = module.targets(SITE, "carrel01")
    entries = module.node_entries(
        nodes,
        {"carrel01", "carrel02"},
        {"carrel01": "ab" * 32, "carrel02": "cd" * 32},
        {"carrel02": module.agent_certificate_name(SITE, "carrel02")},
    )
    assert entries[0]["agent_token_sha256"] == "ab" * 32 and "agent_certificate" not in entries[0]
    assert entries[1] == {
        "name": "carrel02",
        "target": "carrel02",
        "transport": "agent",
        "agent_source": nodes[1]["address"],
        "agent_certificate": "carrel02.b09.agent.carrel.winlab.tw",
    }


def test_the_agent_config_names_its_certificate_with_agent_identity(tmp_path, monkeypatch):
    module = load("configure-nodes.py")
    calls = []
    monkeypatch.setattr(module, "run", lambda *a, **kw: calls.append(a) or "")
    monkeypatch.setattr(module.socket, "gethostname", lambda: "carrel01")
    monkeypatch.setattr(module, "SITE", tmp_path / "site.json")
    monkeypatch.setattr(module, "AGENT_JSON", tmp_path / "agent.json")
    monkeypatch.setattr(module, "AGENT_UNIT", tmp_path / "carrel-agent.service")
    monkeypatch.setattr(module, "AGENT_LAB_ROOT", tmp_path / "lab-root.pem")
    monkeypatch.setattr(module, "AGENT_IDENTITY", tmp_path / "agent-identity")
    module.SITE.write_text(
        json.dumps(
            {**SITE, "agent_nodes": ["carrel01"], "agent_identity": {**IDENTITY, "certificate_nodes": []}}
        )
    )
    assert module.agent_service() == "started"
    assert json.loads((tmp_path / "agent.json").read_text()) == {
        "control": "https://10.200.0.3:8443",
        "ca_file": "/etc/carrel/agent-ca/ca.pem",
        "token_file": "/etc/carrel/agent-token",
        "node": "carrel01",
        "cert_file": str(tmp_path / "agent-identity/agent.crt"),
        "key_file": str(tmp_path / "agent-identity/agent.key"),
        "certificate_name": "carrel01.b09.agent.carrel.winlab.tw",
        "ca_url": "https://ca.winlab.tw",
        "lab_root_file": str(tmp_path / "lab-root.pem"),
    }
    assert (tmp_path / "lab-root.pem").read_text() == IDENTITY["lab_root"]
    assert (tmp_path / "agent-identity").stat().st_mode & 0o777 == 0o700


def test_the_listener_gets_the_lab_root_and_drops_it_without_agent_identity(monkeypatch):
    module = load("configure-nodes.py")
    calls = []
    monkeypatch.setattr(module, "run", lambda *a, **kw: calls.append((a, kw.get("input"))) or "")
    assert module.listener_identity(SITE, None) == (
        {"agent_client_ca_file": None, "agent_provisioner": None},
        {},
    )
    assert calls == []
    client, names = module.listener_identity(SITE, IDENTITY)
    assert client == {
        "agent_client_ca_file": "/etc/carrel/agent/lab-root.pem",
        "agent_provisioner": IDENTITY["provisioner"],
    }
    assert names == {"carrel02": "carrel02.b09.agent.carrel.winlab.tw"}
    [(args, given)] = calls
    assert args[:4] == ("pct", "exec", "100", "--") and given == IDENTITY["lab_root"]
