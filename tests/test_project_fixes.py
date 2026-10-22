import json
import subprocess
from pathlib import Path

import pytest

from patchwatch import inventory, project_fixes, remediation, scanner


def npm_lock(version):
    return json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "dependencies": {"demo": "^1.0.0"}},
                "node_modules/demo": {"version": version},
            },
        }
    )


@pytest.fixture
def project(tmp_path, tiny_catalog, monkeypatch):
    root = tmp_path / "app"
    root.mkdir()
    (root / "package.json").write_text('{"name":"app","dependencies":{"demo":"^1.0.0"}}')
    (root / "package-lock.json").write_text(npm_lock("1.0.0"))
    tiny_catalog["advisories"][0]["affected"][0]["ecosystem"] = "npm"
    monkeypatch.setattr(project_fixes.shutil, "which", lambda name: "/trusted/" + name)
    inv = inventory.discover([root], homebrew=False, tools=False)
    report = scanner.scan(inv, tiny_catalog, "hash")
    return root, remediation.plan(report)[0], tmp_path / "state"


def update(command, cwd, **kwargs):
    (cwd / "package-lock.json").write_text(npm_lock("2.0.0"))
    return subprocess.CompletedProcess(command, 0, "updated", "")


def test_staged_update_and_rollback(project):
    root, action, state = project
    original = (root / "package-lock.json").read_bytes()

    def execute(command, cwd, **kwargs):
        assert Path(cwd) != root
        assert (root / "package-lock.json").read_bytes() == original
        assert "--ignore-scripts" in command
        return update(command, cwd, **kwargs)

    receipt = remediation.apply(action, state, run=execute)
    assert receipt["status"] == "verified-version"
    assert receipt["resolved_packages"][0]["version"] == "2.0.0"
    assert not (state / "runs" / receipt["id"] / "work").exists()
    remediation.rollback(receipt["id"], state)
    assert (root / "package-lock.json").read_bytes() == original


def test_unfixed_update_keeps_original(project):
    root, action, state = project
    original = (root / "package-lock.json").read_bytes()
    receipt = remediation.apply(
        action, state, run=lambda command, **kw: subprocess.CompletedProcess(command, 0, "", "")
    )
    assert receipt["status"] == "failed"
    assert "still have advisories" in receipt["error"]
    assert (root / "package-lock.json").read_bytes() == original


def test_stale_plan_and_concurrent_edit(project):
    root, action, state = project

    def concurrent(command, cwd, **kwargs):
        (root / "package.json").write_text('{"user":"change"}')
        return update(command, cwd, **kwargs)

    receipt = remediation.apply(action, state, run=concurrent)
    assert receipt["status"] == "failed"
    assert "changed while resolving" in receipt["error"]
    assert "1.0.0" in (root / "package-lock.json").read_text()

    def fail(*a, **k):
        pytest.fail("Stale action executed")

    receipt = remediation.apply(action, state, run=fail)
    assert "changed since planning" in receipt["error"]


def test_rollback_preserves_later_edits(project):
    root, action, state = project
    receipt = remediation.apply(action, state, run=update)
    (root / "package-lock.json").write_text("user edit")
    with pytest.raises(ValueError, match="changed since update"):
        remediation.rollback(receipt["id"], state)
    assert (root / "package-lock.json").read_text() == "user edit"


def test_osv_verification_failure_preserves_original(project, monkeypatch):
    root, action, state = project
    action["online"] = True

    def offline(*args):
        raise OSError("offline")

    monkeypatch.setattr(scanner, "osv_query", offline)
    receipt = remediation.apply(action, state, run=update)
    assert receipt["status"] == "failed"
    assert "Verification incomplete" in receipt["error"]
    assert "1.0.0" in (root / "package-lock.json").read_text()


def test_new_transitive_vulnerability_blocks_publish(project, monkeypatch):
    root, action, state = project
    action["online"] = True
    monkeypatch.setattr(
        scanner, "osv_query", lambda *args: [{"id": "NEW"}] if args[1] == "transitive" else []
    )

    def introduces(command, cwd, **kwargs):
        data = json.loads(npm_lock("2.0.0"))
        data["packages"]["node_modules/transitive"] = {"version": "1.0.0"}
        (cwd / "package-lock.json").write_text(json.dumps(data))
        return subprocess.CompletedProcess(command, 0, "", "")

    receipt = remediation.apply(action, state, run=introduces)
    assert "introduces advisory" in receipt["error"]
    assert "1.0.0" in (root / "package-lock.json").read_text()


def test_additional_manifest_changes_block_publish(project):
    root, action, state = project
    (root / "other.toml").write_text("user data")

    def edits(command, cwd, **kwargs):
        (cwd / "other.toml").write_text("modified")
        return update(command, cwd, **kwargs)

    receipt = remediation.apply(action, state, run=edits)
    assert "additional project file" in receipt["error"]
    assert (root / "other.toml").read_text() == "user data"


def test_symlinked_project_source_blocks_update(project):
    root, action, state = project
    (root / "link").symlink_to(root / "package.json")
    receipt = remediation.apply(action, state, run=update)
    assert "symlink" in receipt["error"]


@pytest.mark.parametrize("filename", project_fixes.ADAPTERS)
def test_adapter_configuration(filename, tmp_path, monkeypatch):
    manager, _, files = project_fixes.ADAPTERS[filename]
    for name in files:
        (tmp_path / name).write_text("{}")
    monkeypatch.setattr(project_fixes.shutil, "which", lambda n: "/trusted/" + n)
    pkg = inventory.package(
        "npm", "demo", "1.0", "lock", "lockfile", lockfile=str(tmp_path / filename), project=str(tmp_path)
    )
    action = {"package": pkg}
    project_fixes.configure(action, {"findings": []})
    assert action["supported"] and action["manager"] == manager
    assert action["commands"][0][0] == "/trusted/" + manager
    assert any("demo" in argument for argument in action["commands"][0])


def test_grouped_updates_share_one_transaction(project):
    _, action, _ = project
    import copy

    second = copy.deepcopy(action)
    second["package"]["name"] = "other"
    second["commands"] = [["/trusted/npm", "update", "other"]]
    grouped = project_fixes.group([action, second])
    assert len(grouped) == 1
    assert len(grouped[0]["commands"]) == 2
    assert len(grouped[0]["packages"]) == 2


def test_missing_manager_explained(project, monkeypatch):
    _, action, _ = project
    monkeypatch.setattr(project_fixes.shutil, "which", lambda _: None)
    bare = {"package": action["package"], "supported": False}
    project_fixes.configure(bare, {"findings": []})
    assert not bare["supported"]
    assert "Install npm" in bare["reason"]


def test_yarn_generated_state_is_excluded_from_staging(tmp_path):
    root = tmp_path / "root"
    (root / ".yarn").mkdir(parents=True)
    (root / ".yarn/install-state.gz").write_bytes(b"generated")
    (root / "package.json").write_text("{}")
    stage = tmp_path / "stage"
    copied = project_fixes.copy_project(root, stage)
    assert copied.keys() == {"package.json"}
    assert not (stage / ".yarn/install-state.gz").exists()
