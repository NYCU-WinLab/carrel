"""scripts/check-skills.py: one passing and one failing case per rule (issue #852)."""

import importlib.util
import json
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check-skills.py"
spec = importlib.util.spec_from_file_location("check_skills", SCRIPT)
check_skills = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_skills)


def skill(version="1.0.0", description="Use when needed.", tools="[machine_get]", name="demo"):
    return (
        f"---\nname: {name}\ndescription: {description}\nversion: {version}\n"
        f"requires_tools: {tools}\nverified:\n---\n\nBody.\n"
    )


def repo(tmp_path, text):
    (tmp_path / "internal" / "carrel").mkdir(parents=True)
    (tmp_path / "internal" / "carrel" / "contract.json").write_text(
        json.dumps({"tools": [{"name": "machine_get"}]})
    )
    (tmp_path / "skills" / "demo").mkdir(parents=True)
    (tmp_path / "skills" / "demo" / "SKILL.md").write_text(text)
    return tmp_path


def run(root, capsys, *extra):
    code = check_skills.main(["--root", str(root), *extra])
    return code, capsys.readouterr().err


def test_valid_skill_passes(tmp_path, capsys):
    assert run(repo(tmp_path, skill()), capsys) == (0, "")


def test_missing_frontmatter_fails(tmp_path, capsys):
    code, err = run(repo(tmp_path, "no frontmatter\n"), capsys)
    assert code == 1 and "must start with ---" in err


def test_unknown_field_fails(tmp_path, capsys):
    code, err = run(repo(tmp_path, skill().replace("verified:", "bogus: 1")), capsys)
    assert code == 1 and "unknown or malformed" in err


def test_known_tool_passes_unknown_tool_fails(tmp_path, capsys):
    code, err = run(repo(tmp_path, skill(tools="[machine_get, nope]")), capsys)
    assert code == 1 and "'nope'" in err


def test_description_limit(tmp_path, capsys):
    root = repo(tmp_path, skill(description="x" * 300))
    assert run(root, capsys)[0] == 0
    (root / "skills" / "demo" / "SKILL.md").write_text(skill(description="x" * 301))
    code, err = run(root, capsys)
    assert code == 1 and "301 characters" in err


def git(root, *args):
    subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@t", *args],
        check=True,
        capture_output=True,
    )


def test_version_bump_rule(tmp_path, capsys):
    root = repo(tmp_path, skill())
    git(root, "init", "-q", "-b", "main")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "base")
    path = root / "skills" / "demo" / "SKILL.md"
    assert run(root, capsys, "--base", "main") == (0, "")  # unchanged
    path.write_text(skill(description="Changed."))
    code, err = run(root, capsys, "--base", "main")
    assert code == 1 and "not higher" in err
    path.write_text(skill(version="1.0.1", description="Changed."))
    assert run(root, capsys, "--base", "main") == (0, "")
