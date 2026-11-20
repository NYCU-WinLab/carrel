"""The jump host's certificate path against a real sshd run with the production config (issue #361).

The two drop-ins are the real JUMP_SSHD (bootstrap-platform.py) and JUMP_CERT_SSHD
(configure-nodes.py). Only what an unprivileged sshd cannot do is swapped: the
command's path, the user it runs as and the keys file's path. One local account
stands in for both `ca` and `jump`.
"""

import getpass
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SSHD = shutil.which("sshd") or ("/usr/sbin/sshd" if Path("/usr/sbin/sshd").exists() else None)

pytestmark = pytest.mark.skipif(
    not SSHD or not shutil.which("ssh") or not shutil.which("ssh-keygen") or os.geteuid() == 0,
    reason="needs sshd, ssh and ssh-keygen, and a non-root user",
)

OWNER, OTHER = "10.200.1.10:22", "10.200.2.10:22"


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def keygen(path, *args):
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path, *args], check=True)


@pytest.fixture(scope="module")
def jump(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("jump")
    tmp.chmod(0o700)
    for name in ("ca", "id", "key", "host"):
        keygen(tmp / name)
    subprocess.run(
        ["ssh-keygen", "-q", "-s", tmp / "ca", "-I", "test", "-n", "alice,project:robotics", tmp / "id.pub"],
        check=True,
    )
    ca = " ".join((tmp / "ca.pub").read_text().split()[:2])
    (tmp / "certs.json").write_text(json.dumps({"ca": ca, "principals": {"alice": [OWNER], "bob": [OTHER]}}))
    # jump-cert.py as sshd runs it, for the local account instead of `ca`.
    wrapper = tmp / "jump-cert"
    wrapper.write_text(
        f"#!{sys.executable}\n"
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('jump_cert', {str(ROOT / 'scripts/jump-cert.py')!r})\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(m)\n"
        f"m.CERTS, m.USER = {str(tmp / 'certs.json')!r}, {getpass.getuser()!r}\n"
        "found = m.line(*sys.argv[1:4])\n"
        "print(found or '', end='')\n"
    )
    # sshd runs the command only from a root-owned path: go through env.
    assert Path("/usr/bin/env").owner() == "root"
    command = f"/usr/bin/env {sys.executable} {wrapper}"
    keys = tmp / "jump-keys"
    pub = (tmp / "key.pub").read_text().strip()
    keys.write_text(f'restrict,port-forwarding,permitopen="{OWNER}" {pub}\n')

    jump_sshd = load("bootstrap-platform.py").JUMP_SSHD
    cert_sshd = load("configure-nodes.py").JUMP_CERT_SSHD
    for text, old in (
        (jump_sshd, "/etc/carrel-jump/%u"),
        (cert_sshd, load("configure-nodes.py").JUMP_CERT),
        (cert_sshd, "AuthorizedKeysCommandUser nobody"),
        (cert_sshd, "Match User ca"),
    ):
        assert old in text
    jump_sshd = jump_sshd.replace("/etc/carrel-jump/%u", str(keys))
    cert_sshd = (
        cert_sshd.replace(load("configure-nodes.py").JUMP_CERT, command)
        .replace("AuthorizedKeysCommandUser nobody", f"AuthorizedKeysCommandUser {getpass.getuser()}")
        .replace("Match User ca", f"Match User {getpass.getuser()}")
    )
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    # sshd keeps the first value it reads, as in /etc/ssh/sshd_config.d: the drop-ins come first,
    # through Include as in production, so a Match block ends with its file.
    (tmp / "jump.conf").write_text(jump_sshd)
    (tmp / "certs.conf").write_text(cert_sshd)
    config = tmp / "sshd_config"
    config.write_text(
        f"Include {tmp / 'certs.conf'}\nInclude {tmp / 'jump.conf'}\n"
        f"Port {port}\nListenAddress 127.0.0.1\nHostKey {tmp / 'host'}\nPidFile {tmp / 'sshd.pid'}\n"
        "UsePAM no\nStrictModes no\n"
    )
    check = subprocess.run([SSHD, "-t", "-f", config], capture_output=True, text=True, check=False)
    if "Bad configuration option" in check.stderr or "Unsupported option" in check.stderr:
        pytest.skip("this sshd is older than the production one: " + check.stderr.strip()[:200])
    assert check.returncode == 0, check.stderr
    server = subprocess.Popen([SSHD, "-D", "-e", "-f", config], stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("sshd did not start")
        yield tmp, port
    finally:
        server.terminate()
        server.wait(timeout=10)


def forward(jump, identity, target):
    """ssh -W through the jump host: (refused by permitopen, authenticated)."""
    tmp, port = jump
    args = [
        "ssh",
        "-F",
        "/dev/null",
        "-p",
        str(port),
        "-i",
        tmp / identity,
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=2",
        "-W",
        target,
        f"{getpass.getuser()}@127.0.0.1",
    ]
    try:
        err = subprocess.run(
            args, capture_output=True, text=True, timeout=5, check=False, stdin=subprocess.DEVNULL
        ).stderr
    except subprocess.TimeoutExpired as e:
        # The jump host let it through and is still dialing a machine that is not here.
        err = (e.stderr or b"").decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
    return "administratively prohibited" in err, "Permission denied" not in err


def test_a_certificate_reaches_the_owners_machine_and_no_other_tenants(jump):
    # sshd offers id-cert.pub with the key id; alice's principal opens only her machine.
    assert forward(jump, "id", OWNER) == (False, True)
    assert forward(jump, "id", OTHER) == (True, True)


def test_a_key_still_works_on_the_jump_user(jump):
    assert forward(jump, "key", OWNER) == (False, True)
    assert forward(jump, "key", OTHER) == (True, True)


def test_a_key_the_jump_host_does_not_know_is_refused(jump):
    tmp, _ = jump
    keygen(tmp / "stranger")
    assert forward(jump, "stranger", OWNER)[1] is False


def test_the_match_block_does_not_leak_into_later_files(tmp_path):
    # Production reads the drop-in first; a setting read after it must stay global.
    cert_sshd = load("configure-nodes.py").JUMP_CERT_SSHD
    assert "Match User ca" in cert_sshd
    keys = load("bootstrap-platform.py").JUMP_SSHD
    keygen(tmp_path / "host")
    (tmp_path / "certs.conf").write_text(cert_sshd)
    (tmp_path / "jump.conf").write_text(keys)
    config = tmp_path / "sshd_config"
    config.write_text(
        f"Include {tmp_path / 'certs.conf'}\nInclude {tmp_path / 'jump.conf'}\n"
        f"HostKey {tmp_path / 'host'}\nPermitEmptyPasswords no\n"
    )

    def effective(user):
        out = subprocess.run(
            [SSHD, "-T", "-f", config, "-C", f"user={user},host=h,addr=10.0.0.1"],
            capture_output=True, text=True, check=True,
        ).stdout
        return dict(line.split(" ", 1) for line in out.splitlines())

    ca, jump_user = effective("ca"), effective("jump")
    assert ca["authorizedkeyscommand"].startswith(load("configure-nodes.py").JUMP_CERT)
    assert jump_user["authorizedkeyscommand"] == "none"
    for user in (ca, jump_user):
        assert user["authorizedkeysfile"] == ".ssh/authorized_keys /etc/carrel-jump/%u"
        assert user["allowtcpforwarding"] == "local"
        assert user["permitemptypasswords"] == "no"
