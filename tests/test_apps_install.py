"""The app install script takes the agent token on standard input (issue #33)."""

import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "internal" / "carrel" / "apps_install.sh"
ARGS = ["--app", "site", "--port", "8000", "--user", "alice", "--start", "./run"]
TOKEN = "cdt_SwNyheRXIUqrM1h0_rbnnuZsVwFKYVYGGuZpgJ7F1zU"


def run(tmp_path, stdin, env=None):
    # Stubs: root, a known user, and a download that fails right after the
    # checks, so nothing is installed.
    bin = tmp_path / "bin"
    bin.mkdir(exist_ok=True)
    (bin / "id").write_text('#!/bin/sh\n[ "$1" = -u ] && echo 0; exit 0\n')
    (bin / "curl").write_text("#!/bin/sh\necho curl-reached >&2; exit 7\n")
    for f in bin.iterdir():
        f.chmod(0o755)
    path = f"{bin}:/usr/bin:/bin"
    return subprocess.run(
        ["sh", str(SCRIPT), *ARGS],
        input=stdin,
        capture_output=True,
        text=True,
        env={"PATH": path, **(env or {})},
        check=False,
    )


def test_the_agent_token_comes_on_standard_input(tmp_path):
    # Issue #33: not on the command line, where ps shows it.
    p = run(tmp_path, TOKEN + "\n")
    assert "curl-reached" in p.stderr and "token" not in p.stderr


def test_a_missing_or_malformed_token_stops_before_anything_is_installed(tmp_path):
    for stdin in ("", "\n", 'cdt_x", "app": "other\n', "notatoken\n"):
        p = run(tmp_path, stdin)
        assert p.returncode == 1 and "agent token (cdt_...) is" in p.stderr and "curl-reached" not in p.stderr


def test_a_token_pasted_from_windows_or_with_a_second_line_is_handled(tmp_path):
    # CR is dropped; read takes one line, so a second line cannot reach the JSON.
    assert "curl-reached" in run(tmp_path, TOKEN + "\r\n").stderr
    assert "curl-reached" in run(tmp_path, TOKEN + '\n","origin":"http://evil\n').stderr
    p = run(tmp_path, "", {"CARREL_APP_TOKEN": TOKEN + '\n","origin":"http://evil'})
    assert p.returncode == 1 and "malformed" in p.stderr


def test_older_install_lines_still_pass_the_token_in_the_environment(tmp_path):
    p = run(tmp_path, "", {"CARREL_APP_TOKEN": TOKEN})
    assert "curl-reached" in p.stderr
