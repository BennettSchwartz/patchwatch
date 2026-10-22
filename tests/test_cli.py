import json

from patchwatch import cli


def test_scan_exit_codes(environment, tiny_catalog, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PATCHWATCH_STATE_DIR", str(tmp_path / "state"))
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps(tiny_catalog))
    args = [
        "scan",
        "--root",
        str(environment[0].parents[2]),
        "--catalog",
        str(catalog),
        "--no-tools",
        "--no-homebrew",
        "--json",
    ]
    assert cli.main(args) == 1
    assert len(json.loads(capsys.readouterr().out)["findings"]) == 1
    assert cli.main(["scan", "--root", str(tmp_path / "absent"), "--no-tools", "--no-homebrew"]) == 2


def test_fix_default_is_plan_only(environment, tiny_catalog, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PATCHWATCH_STATE_DIR", str(tmp_path / "state"))
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(tiny_catalog))
    assert (
        cli.main(
            [
                "fix",
                "--root",
                str(environment[0].parents[2]),
                "--catalog",
                str(path),
                "--no-tools",
                "--no-homebrew",
            ]
        )
        == 1
    )
    assert "READY" in capsys.readouterr().out
    assert not (tmp_path / "state/runs").exists()


def test_monitor_once_saves_report(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHWATCH_STATE_DIR", str(tmp_path / "state"))
    root = tmp_path / "empty"
    root.mkdir()
    assert cli.main(["watch", "--once", "--root", str(root), "--no-tools", "--no-homebrew"]) == 0
    assert (tmp_path / "state/last-report.json").exists()


def test_overlapping_mutations_locked(tmp_path):
    import pytest

    with cli.RunLock(tmp_path):
        with pytest.raises(ValueError, match="Another"):
            with cli.RunLock(tmp_path):
                pass


def test_unknown_fix_id_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHWATCH_STATE_DIR", str(tmp_path / "state"))
    root = tmp_path / "empty"
    root.mkdir()
    assert cli.main(["fix", "--root", str(root), "--only", "missing", "--no-tools", "--no-homebrew"]) == 2
