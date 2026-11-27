"""Site values the installer reads from the site file, not from its code (#569)."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
B09 = json.loads((ROOT / "sites/b09/cluster.json").read_text())


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_jump_exemption_comes_from_the_site_file():
    bootstrap = load("bootstrap-platform.py")
    assert "PerSourcePenaltyExemptList 140.113.0.0/16\n" in bootstrap.jump_sshd(B09)
    other = {k: v for k, v in B09.items() if k != "jump_exempt_sources"}
    assert "PerSourcePenaltyExemptList" not in bootstrap.jump_sshd(other)
    assert "PerSourcePenaltyExemptList 10.0.0.0/8,192.0.2.0/24\n" in bootstrap.jump_sshd(
        {"jump_exempt_sources": ["10.0.0.0/8", "192.0.2.0/24"]})
    with pytest.raises(SystemExit):
        bootstrap.jump_sshd({"jump_exempt_sources": "140.113.0.0/16"})


def test_agent_certificate_domain_comes_from_the_site_file():
    nodes = load("configure-nodes.py")
    assert nodes.agent_certificate_name(B09, "carrel02") == "carrel02.b09.agent.carrel.winlab.tw"
    staging = {"site": "stg", "agent_identity": {"domain": "agent.stg.example.org"}}
    assert nodes.agent_certificate_name(staging, "n1") == "n1.stg.agent.stg.example.org"


def test_scripts_name_no_site():
    # A site is described by its files under sites/, not by the installer.
    for script in (ROOT / "scripts").glob("*.py"):
        text = script.read_text()
        for name in ("140.113.", "carrel01", "sites/b09", "rs822"):
            assert name not in text, f"{script.name} names {name}"


def test_agent_identity_domain_is_checked():
    nodes = load("configure-nodes.py")
    site = dict(B09, agent_identity=dict(B09["agent_identity"], domain="Not A Name"))
    with pytest.raises(SystemExit):
        nodes.agent_identity(site, [n["name"] for n in B09["nodes"]], set(B09["agent_nodes"]))
    assert nodes.agent_identity(B09, [n["name"] for n in B09["nodes"]], set(B09["agent_nodes"]))["domain"] == "agent.carrel.winlab.tw"
