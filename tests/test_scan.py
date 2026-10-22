import json

import pytest

from patchwatch import inventory, scanner


def test_inventory_does_not_run_discovered_interpreter(environment, monkeypatch):
    site, _ = environment

    def fail(*args, **kwargs):
        raise AssertionError("Must not execute interpreter during inventory")

    monkeypatch.setattr(inventory.subprocess, "run", fail)
    result = inventory.discover([site.parents[2]], homebrew=False, tools=False)
    assert result["packages"][0]["name"] == "demo"
    assert result["packages"][0]["venv"] is True


@pytest.mark.parametrize(
    "version,affected", [("1.0", True), ("2.0", False), ("3.0", False), ("1.9rc1", True)]
)
def test_version_boundaries(tiny_catalog, version, affected):
    inv = {
        "packages": [inventory.package("PyPI", "demo", version, "/test", "python")],
        "warnings": [],
        "coverage": {},
    }
    result = scanner.scan(inv, tiny_catalog, "digest")
    assert bool(result["findings"]) == affected


def test_unknown_version_is_not_clean(tiny_catalog):
    inv = {
        "packages": [inventory.package("PyPI", "demo", "not-a-version", "/test", "python")],
        "warnings": [],
        "coverage": {},
    }
    assert scanner.scan(inv, tiny_catalog, "digest")["warnings"]


def test_npm_lockfile_v3(tmp_path):
    path = tmp_path / "package-lock.json"
    path.write_text(
        json.dumps(
            {"lockfileVersion": 3, "packages": {"": {}, "node_modules/@org/test": {"version": "1.2.3"}}}
        )
    )
    found = inventory.discover([tmp_path], homebrew=False, tools=False)
    assert found["packages"][0]["name"] == "@org/test"


def test_directory_limit_reports_incomplete(tmp_path):
    (tmp_path / "nested").mkdir()
    found = inventory.discover([tmp_path], homebrew=False, tools=False, max_dirs=1)
    assert "incomplete" in found["warnings"][0]


def test_missing_root_reports_warning(tmp_path):
    assert inventory.discover([tmp_path / "missing"], homebrew=False, tools=False)["warnings"]


def test_osv_deduplicates_queries_and_expands_locations(monkeypatch):
    calls = []

    def query(*args):
        calls.append(args)
        return [{"id": "OSV-TEST", "summary": "bad", "affected": [], "references": []}]

    monkeypatch.setattr(scanner, "osv_query", query)
    pkgs = [inventory.package("PyPI", "demo", "1.0", p, "python") for p in ["/a", "/b"]]
    findings, warnings = scanner.scan_osv(pkgs)
    assert len(calls) == 1 and len(findings) == 2 and not warnings


def test_osv_failure_not_silently_clean(monkeypatch):
    def fail(*a):
        raise OSError("offline")

    monkeypatch.setattr(scanner, "osv_query", fail)
    findings, warnings = scanner.scan_osv([inventory.package("PyPI", "demo", "1.0", "/a", "python")])
    assert warnings and not findings


def test_certifi_first_patched_release_is_not_vulnerable():
    from patchwatch.catalog import load

    data, digest = load()
    inv = {
        "packages": [inventory.package("PyPI", "certifi", "2026.10.18", "/test", "python")],
        "warnings": [],
        "coverage": {},
    }
    assert not scanner.scan(inv, data, digest)["findings"]
