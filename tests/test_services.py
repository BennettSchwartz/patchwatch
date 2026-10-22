import json
from types import SimpleNamespace

import pytest

from patchwatch import cli, inventory


@pytest.mark.parametrize(
    ("binary", "stdout", "stderr", "name", "version"),
    [
        ("nginx", "", "nginx version: nginx/1.20.0", "nginx", "1.20.0"),
        ("apache2", "Server version: Apache/2.4.49 (Unix)", "", "httpd", "2.4.49"),
        ("mysqld", "mysqld Ver 10.11.6-MariaDB for Linux", "", "mariadb", "10.11.6"),
        ("postgres", "postgres (PostgreSQL) 16.4", "", "postgresql", "16.4"),
    ],
)
def test_service_identity(tmp_path, monkeypatch, binary, stdout, stderr, name, version):
    monkeypatch.setattr(inventory.shutil, "which", lambda x: "/bin/" + x if x == binary else None)
    monkeypatch.setattr(
        inventory.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=stdout, stderr=stderr)
    )
    result = inventory.discover([tmp_path], homebrew=False)
    assert not result["warnings"]
    assert [(p["ecosystem"], p["name"], p["version"]) for p in result["packages"]] == [
        ("Service", name, version)
    ]


def test_declared_service_matches_catalog(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PATCHWATCH_STATE_DIR", str(tmp_path / "state"))
    assert (
        cli.main(
            [
                "scan",
                "--root",
                str(tmp_path),
                "--service",
                "httpd=2.4.49",
                "--no-tools",
                "--no-homebrew",
                "--json",
            ]
        )
        == 1
    )
    report = json.loads(capsys.readouterr().out)
    assert {f["advisory"] for f in report["findings"]} == {"CVE-2021-41773", "CVE-2021-42013"}
    assert report["packages"][0]["kind"] == "declared-service"
    assert not report["warnings"]
