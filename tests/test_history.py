import pytest

from patchwatch import catalog, inventory, scanner


@pytest.mark.parametrize(
    "advisory,ecosystem,name,affected,patched",
    [
        ("GHSA-fxpg-gg9g-76gj", "PyPI", "django", "1.2.1", "1.2.2"),
        ("GHSA-5j2h-h5hg-3wf8", "PyPI", "django", "1.1.3", "1.1.4"),
        ("GHSA-wqjj-hx84-v449", "PyPI", "django", "1.6.2", "1.6.3"),
        ("GHSA-x84v-xcm2-53pg", "PyPI", "requests", "2.19.1", "2.20.0"),
        ("GHSA-9wx4-h78v-vm56", "PyPI", "requests", "2.31.0", "2.32.0"),
        ("GHSA-rprw-h62v-c2w7", "PyPI", "pyyaml", "3.13", "5.1"),
        ("GHSA-8q59-q68h-6hv4", "PyPI", "pyyaml", "5.3.1", "5.4"),
        ("GHSA-mh6f-8j2x-4483", "npm", "event-stream", "3.3.6", "4.0.0"),
        ("GHSA-pjwm-rvh2-c87w", "npm", "ua-parser-js", "0.7.29", "0.7.30"),
        ("GHSA-pjwm-rvh2-c87w", "npm", "ua-parser-js", "0.8.0", "0.8.1"),
        ("GHSA-pjwm-rvh2-c87w", "npm", "ua-parser-js", "1.0.0", "1.0.1"),
        ("GHSA-73qr-pfmq-6rp8", "npm", "coa", "2.0.3", "2.0.2"),
        ("GHSA-g2q5-5433-rhrf", "npm", "rc", "1.2.9", "1.2.8"),
        ("GHSA-97m3-w2cp-4xx6", "npm", "node-ipc", "10.1.1", "10.1.3"),
        ("CVE-2013-2028", "Service", "nginx", "1.4.0", "1.4.1"),
        ("CVE-2021-23017", "Service", "nginx", "1.20.0", "1.20.1"),
        ("CVE-2021-41773", "Service", "httpd", "2.4.49", "2.4.50"),
        ("CVE-2021-42013", "Service", "httpd", "2.4.50", "2.4.51"),
    ],
)
def test_historical_boundaries(advisory, ecosystem, name, affected, patched):
    data, digest = catalog.load()

    def matches(v):
        inv = {
            "packages": [inventory.package(ecosystem, name, v, "/fixture", "declared")],
            "warnings": [],
            "coverage": {},
        }
        return any(f["advisory"] == advisory for f in scanner.scan(inv, data, digest)["findings"])

    assert matches(affected)
    assert not matches(patched)


def test_osv_alias_dedup_preserves_curated_fix(tiny_catalog, monkeypatch):
    tiny_catalog["advisories"][0]["aliases"] = ["CVE-2020-1234"]
    pkg = inventory.package("PyPI", "demo", "1.0", "/fixture", "declared")
    inv = {"packages": [pkg], "warnings": [], "coverage": {}}
    extra = {
        "advisory": "OTHER-ID",
        "aliases": ["CVE-2020-1234"],
        "package": pkg,
        "references": [],
        "source": "osv",
    }
    monkeypatch.setattr(scanner, "scan_osv", lambda _: ([extra], []))
    report = scanner.scan(inv, tiny_catalog, "digest", osv=True)
    assert len(report["findings"]) == 1
    assert report["findings"][0]["target"]["fixed"] == "2.0"
    assert report["findings"][0]["sources"] == ["catalog", "osv"]
