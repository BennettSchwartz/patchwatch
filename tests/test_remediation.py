import csv
import shutil
import subprocess

import pytest
from conftest import install_fixture

from patchwatch import inventory, remediation, scanner


def action_for(environment, tiny_catalog):
    site, _ = environment
    inv = inventory.discover([site.parents[2]], homebrew=False, tools=False)
    report = scanner.scan(inv, tiny_catalog, "digest")
    return remediation.plan(report)[0]


def test_manual_command_never_executed(environment, tiny_catalog):
    t = tiny_catalog["advisories"][0]["affected"][0]
    t["command"] = ["sh", "-c", "touch /tmp/should-not-exist"]
    t["fixed"] = None
    action = action_for(environment, tiny_catalog)
    assert action["commands"] and not action["supported"]


def test_record_path_traversal_rejected(environment, tmp_path):
    site, dist = environment
    outside = tmp_path / "private"
    outside.write_text("important")
    with (dist / "RECORD").open("a") as f:
        csv.writer(f).writerow([str(outside), "", ""])
    with pytest.raises(ValueError, match="outside"):
        remediation.distribution_files(dist, site, site.parents[2] / "bin/python", "demo")


def test_record_symlink_rejected(environment, tmp_path):
    site, dist = environment
    target = tmp_path / "private"
    target.write_text("important")
    file = site / "demo/__init__.py"
    file.unlink()
    file.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        remediation.distribution_files(dist, site, site.parents[2] / "bin/python", "demo")


def fake_update(environment):
    site, dist = environment

    def run(command, **kwargs):
        if "install" in command:
            shutil.rmtree(dist)
            install_fixture(site.parents[2], "2.0")
        return subprocess.CompletedProcess(command, 0, "success", "")

    return run


def test_apply_verify_and_exact_rollback(environment, tiny_catalog, tmp_path, monkeypatch):
    action = action_for(environment, tiny_catalog)
    assert action["supported"]
    monkeypatch.setattr(remediation.shutil, "which", lambda _: "/trusted/uv")
    receipt = remediation.apply(action, tmp_path / "state", run=fake_update(environment))
    assert receipt["status"] == "verified-version"
    assert receipt["dependency_check"]["returncode"] == 0
    assert receipt["after_version"] == "2.0"
    rolled = remediation.rollback(receipt["id"], tmp_path / "state")
    assert rolled["status"] == "rolled-back"
    site, dist = environment
    assert "Version: 1.0" in (dist / "METADATA").read_text()
    assert not (site / "demo-2.0.dist-info").exists()


def test_rollback_refuses_concurrent_edit(environment, tiny_catalog, tmp_path, monkeypatch):
    monkeypatch.setattr(remediation.shutil, "which", lambda _: "/trusted/uv")
    receipt = remediation.apply(
        action_for(environment, tiny_catalog), tmp_path / "state", run=fake_update(environment)
    )
    file = environment[0] / "demo/__init__.py"
    file.write_text("user edit")
    with pytest.raises(ValueError, match="changed"):
        remediation.rollback(receipt["id"], tmp_path / "state")
    assert file.read_text() == "user edit"


def test_stale_plan_never_runs(environment, tiny_catalog, tmp_path):
    action = action_for(environment, tiny_catalog)
    (environment[1] / "METADATA").write_text("Name: demo\nVersion: 1.5\n")

    def run(*a, **k):
        pytest.fail("stale plan executed")

    receipt = remediation.apply(action, tmp_path / "state", run=run)
    assert receipt["status"] == "failed" and "changed since" in receipt["error"]


def test_artifact_mismatch_never_runs(environment, tiny_catalog, tmp_path, monkeypatch):
    action = action_for(environment, tiny_catalog)
    action["artifact"] = {"url": "https://example.com/demo.whl", "filename": "demo.whl", "sha256": "0" * 64}
    monkeypatch.setattr(remediation, "read_url", lambda *a, **k: b"wrong")

    def run(*a, **k):
        pytest.fail("unverified artifact executed")

    receipt = remediation.apply(action, tmp_path / "state", run=run)
    assert receipt["status"] == "failed" and "SHA-256" in receipt["error"]


def test_base_python_is_manual(environment, tiny_catalog):
    environment[0].parents[2].joinpath("pyvenv.cfg").unlink()
    action = action_for(environment, tiny_catalog)
    assert not action["supported"]


def test_osv_findings_never_auto_fix(environment, tiny_catalog):
    site, _ = environment
    inv = inventory.discover([site.parents[2]], homebrew=False, tools=False)
    report = scanner.scan(inv, tiny_catalog, "digest")
    report["findings"][0]["source"] = "osv"
    assert not remediation.plan(report)[0]["supported"]


def test_fix_cannot_move_into_another_affected_range(environment, tiny_catalog):
    tiny_catalog["advisories"][0]["affected"].append(
        {"ecosystem": "PyPI", "package": "demo", "versions": ">=2.0,<3.0", "fixed": "3.0"}
    )
    action = action_for(environment, tiny_catalog)
    assert not action["supported"]
    assert "common fixed" in action["reason"]
