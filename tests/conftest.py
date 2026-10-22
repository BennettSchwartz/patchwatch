import csv
from pathlib import Path

import pytest


@pytest.fixture
def tiny_catalog():
    return {
        "schema_version": 1,
        "updated": "2026-10-22T00:00:00Z",
        "advisories": [
            {
                "id": "TEST-1",
                "summary": "Test advisory",
                "severity": "high",
                "references": ["https://example.com/advisory"],
                "affected": [{"ecosystem": "PyPI", "package": "demo", "versions": "<2.0", "fixed": "2.0"}],
            }
        ],
    }


def install_fixture(root, version="1.0", name="demo"):
    site = Path(root) / "lib/python3.13/site-packages"
    site.mkdir(parents=True, exist_ok=True)
    (Path(root) / "bin").mkdir(exist_ok=True)
    (Path(root) / "bin/python").write_text("#!/bin/sh\nexit 0\n")
    (Path(root) / "bin/python").chmod(0o755)
    (Path(root) / "pyvenv.cfg").write_text("home = /example\n")
    dist = site / f"{name}-{version}.dist-info"
    dist.mkdir(exist_ok=True)
    package = site / name
    package.mkdir(exist_ok=True)
    (package / "__init__.py").write_text(f"VERSION = '{version}'\n")
    (dist / "METADATA").write_text(f"Name: {name}\nVersion: {version}\n")
    record = dist / "RECORD"
    with record.open("w") as f:
        writer = csv.writer(f)
        for path in [package / "__init__.py", dist / "METADATA", record]:
            writer.writerow([str(path.relative_to(site)), "", ""])
    return site, dist


@pytest.fixture
def environment(tmp_path):
    return install_fixture(tmp_path / "venv")
