import json
import urllib.request
from datetime import UTC, datetime

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion

from .catalog import canonical, version


def scan(inventory, catalog, digest, *, osv=False):
    findings, warnings = [], list(inventory["warnings"])
    for pkg in inventory["packages"]:
        for advisory in catalog["advisories"]:
            for target in advisory["affected"]:
                if pkg["ecosystem"] != target["ecosystem"]:
                    continue
                if canonical(pkg["name"]) != canonical(target["package"]):
                    continue
                try:
                    affected = SpecifierSet(target["versions"]).contains(
                        version(pkg["version"], pkg["ecosystem"]), prereleases=True
                    )
                except InvalidVersion:
                    warnings.append(
                        f"Uncomparable version: {pkg['name']} {pkg['version']} at {pkg['location']}"
                    )
                    continue
                if affected:
                    findings.append(
                        dict(
                            id=f"{advisory['id']}:{pkg['id']}",
                            advisory=advisory["id"],
                            aliases=advisory.get("aliases", []),
                            summary=advisory["summary"],
                            severity=advisory["severity"],
                            package=pkg,
                            target=target,
                            references=advisory["references"],
                            source="catalog",
                        )
                    )
    if osv:
        extra, errors = scan_osv(inventory["packages"])
        for additional in extra:
            ids = {additional["advisory"], *additional.get("aliases", [])}
            existing = next(
                (
                    f
                    for f in findings
                    if f["package"]["id"] == additional["package"]["id"]
                    and ids.intersection({f["advisory"], *f.get("aliases", [])})
                ),
                None,
            )
            if existing:
                existing["aliases"] = sorted(({*existing.get("aliases", []), *ids}) - {existing["advisory"]})
                existing["references"] = list(
                    dict.fromkeys([*existing["references"], *additional["references"]])
                )
                existing["sources"] = list(dict.fromkeys([existing["source"], "osv"]))
            else:
                findings.append(additional)
        warnings.extend(errors)
    return dict(
        schema_version=1,
        generated=datetime.now(UTC).isoformat(),
        catalog_sha256=digest,
        catalog_updated=catalog["updated"],
        catalog_rules=catalog["advisories"],
        packages=inventory["packages"],
        findings=findings,
        warnings=warnings,
        coverage=inventory["coverage"],
    )


def osv_query(ecosystem, name, ver):
    payload = json.dumps({"package": {"ecosystem": ecosystem, "name": name}, "version": ver}).encode()
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "patchwatch/0.1"},
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        raw = response.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("OSV response exceeds size limit")
    data = json.loads(raw)
    if data.get("next_page_token"):
        raise ValueError("OSV paginated response: incomplete results; use OSV-Scanner for this package")
    return data.get("vulns", [])


def scan_osv(packages):
    from concurrent.futures import ThreadPoolExecutor

    groups = {}
    for p in packages:
        if p["ecosystem"] in {"PyPI", "npm"}:
            groups.setdefault((p["ecosystem"], p["name"], p["version"]), []).append(p)

    def query(key):
        try:
            return key, osv_query(*key), None
        except Exception as exc:
            return key, [], str(exc)

    findings, warnings = [], []
    with ThreadPoolExecutor(max_workers=4) as executor:
        for key, vulns, error in executor.map(query, groups):
            if error:
                warnings.append(f"OSV {key}: {error}")
            for vuln in vulns:
                if vuln.get("withdrawn"):
                    continue
                # OSV fixes are advisory only: ecosystems can have disjoint release branches.
                fixes = set()
                for affected in vuln.get("affected", []):
                    package = affected.get("package", {})
                    if package.get("ecosystem") == key[0] and canonical(package.get("name", "")) == canonical(
                        key[1]
                    ):
                        for range_ in affected.get("ranges", []):
                            for event in range_.get("events", []):
                                if "fixed" in event:
                                    fixes.add(event["fixed"])
                for pkg in groups[key]:
                    findings.append(
                        dict(
                            id=f"{vuln['id']}:{pkg['id']}",
                            advisory=vuln["id"],
                            aliases=vuln.get("aliases", []),
                            summary=vuln.get("summary", vuln["id"]),
                            severity="unknown",
                            package=pkg,
                            target={
                                "ecosystem": key[0],
                                "package": key[1],
                                "versions": "",
                                "fixed": None,
                                "instructions": "Review upstream fixed branches: "
                                + (", ".join(sorted(fixes)) or "no published fix"),
                            },
                            references=[r["url"] for r in vuln.get("references", [])],
                            source="osv",
                        )
                    )
    return findings, warnings
