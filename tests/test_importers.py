import json

import pytest

from patchwatch import importers


def test_github_string_fixed_version_and_medium_severity(monkeypatch):
    data = {
        "ghsa_id": "GHSA-9wx4-h78v-vm56",
        "summary": "Requests TLS issue",
        "severity": "medium",
        "html_url": "https://github.com/advisories/GHSA-9wx4-h78v-vm56",
        "references": [],
        "identifiers": [],
        "vulnerabilities": [
            {
                "package": {"ecosystem": "pip", "name": "requests"},
                "vulnerable_version_range": "< 2.32.0",
                "first_patched_version": "2.32.0",
            }
        ],
    }
    monkeypatch.setattr(importers, "read_url", lambda _: json.dumps(data).encode())
    entry = importers.from_github(data["ghsa_id"])
    assert entry["severity"] == "moderate"
    assert entry["affected"][0]["fixed"] == "2.32.0"
    importers.merge({"schema_version": 1, "advisories": []}, entry)


def test_cve_requires_explicit_mapping():
    with pytest.raises(ValueError, match="require"):
        importers.from_cve("CVE-2021-41773", ecosystem=None, package=None, versions=None)


def test_rejected_cve_cannot_be_imported(monkeypatch):
    monkeypatch.setattr(importers, "read_url", lambda _: b'{"cveMetadata":{"state":"REJECTED"}}')
    with pytest.raises(ValueError, match="published"):
        importers.from_cve("CVE-2021-41773", ecosystem="Service", package="httpd", versions="==2.4.49")


def test_osv_preserves_branches_and_malware_recovery():
    data = {
        "id": "GHSA-example",
        "summary": "Compromised package",
        "database_specific": {"severity": "CRITICAL", "cwe_ids": ["CWE-506"]},
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "demo"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "1.0.1"},
                            {"introduced": "2.0.0"},
                            {"fixed": "2.0.1"},
                        ],
                    }
                ],
            }
        ],
    }
    entry = importers.from_osv(data)
    assert [t["versions"] for t in entry["affected"]] == [">=1.0.0,<1.0.1", ">=2.0.0,<2.0.1"]
    assert "Rotate credentials" in entry["affected"][0]["instructions"]


def test_import_atomic_validation_preserves_original(tiny_catalog):
    original = json.dumps(tiny_catalog)
    bad = {
        **tiny_catalog["advisories"][0],
        "affected": [{"ecosystem": "PyPI", "package": "demo", "versions": "<2", "fixed": "1"}],
    }
    with pytest.raises(ValueError):
        importers.merge(tiny_catalog, bad)
    assert json.dumps(tiny_catalog) == original
