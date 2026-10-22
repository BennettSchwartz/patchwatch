import json

import pytest

from patchwatch import intelligence


def report():
    return {
        "findings": [
            {"advisory": "GHSA-example", "aliases": ["CVE-2021-42013"], "severity": "high"},
            {"advisory": "CVE-2021-41773", "severity": "critical"},
            {"advisory": "CVE-2020-1234", "severity": "low"},
        ],
        "warnings": [],
    }


def feed(url, **kwargs):
    if url == intelligence.KEV_URL:
        return json.dumps(
            {
                "dateReleased": "2026-10-22",
                "vulnerabilities": [{"cveID": "CVE-2021-42013", "dateAdded": "2021-11-03"}],
            }
        ).encode()
    return json.dumps(
        {
            "status": "OK",
            "total": 2,
            "data": [
                {"cve": "CVE-2021-41773", "epss": "0.9", "percentile": "0.99", "date": "2026-10-22"},
                {"cve": "CVE-2021-42013", "epss": "0.1", "percentile": "0.5", "date": "2026-10-22"},
            ],
        }
    ).encode()


def test_kev_precedes_probability_and_aliases_match(monkeypatch):
    monkeypatch.setattr(intelligence, "read_url", feed)
    result = intelligence.enrich(report())
    assert result["findings"][0]["advisory"] == "GHSA-example"
    assert result["findings"][0]["exploitation"]["kev_status"] == "listed"
    assert result["findings"][1]["exploitation"]["epss"]["CVE-2021-41773"]["probability"] == 0.9
    assert result["findings"][2]["exploitation"]["epss"] == {}
    assert not result["warnings"]


def test_feed_failure_is_unknown_not_negative(monkeypatch):
    def fail(*a, **k):
        raise OSError("offline")

    monkeypatch.setattr(intelligence, "read_url", fail)
    result = intelligence.enrich(report())
    assert len(result["warnings"]) == 2
    assert all(f["exploitation"]["kev_status"] == "unknown" for f in result["findings"])


def test_out_of_range_epss_is_rejected(monkeypatch):
    def bad(url, **kwargs):
        if url == intelligence.KEV_URL:
            return feed(url)
        return json.dumps(
            {
                "status": "OK",
                "data": [{"cve": "CVE-2021-41773", "epss": "1.1", "percentile": "0.9", "date": "2026-10-22"}],
            }
        ).encode()

    monkeypatch.setattr(intelligence, "read_url", bad)
    result = intelligence.enrich(report())
    assert result["warnings"]
    assert all(f["exploitation"]["epss"] == {} for f in result["findings"])


def test_no_cve_no_network(monkeypatch):
    def fail(*a, **k):
        pytest.fail("unnecessary network request")

    monkeypatch.setattr(intelligence, "read_url", fail)
    result = intelligence.enrich({"findings": [], "warnings": []})
    assert not result["warnings"]
