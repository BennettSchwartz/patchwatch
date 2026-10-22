"""Explicit advisory imports produce catalog entries for review."""

import json
import re
from datetime import UTC, datetime

from .catalog import read_url, validate


def from_osv(record):
    if record.get("withdrawn"):
        raise ValueError("Advisory has been withdrawn")
    targets = []
    malicious = "CWE-506" in record.get("database_specific", {}).get("cwe_ids", [])
    for affected in record.get("affected", []):
        package = affected["package"]
        if package["ecosystem"] not in {"PyPI", "npm"}:
            raise ValueError("Advisory ecosystem requires an explicit mapping")
        base = {"ecosystem": package["ecosystem"], "package": package["name"]}
        if malicious:
            base["instructions"] = (
                "Remove the compromised release and rebuild the environment from reviewed dependencies. Rotate credentials accessible during its execution and investigate the affected host."
            )
        ranges = affected.get("ranges", [])
        if not ranges:
            for v in affected.get("versions", []):
                targets.append({**base, "versions": "==" + v, "fixed": None})
        for interval in ranges:
            if interval["type"] not in {"ECOSYSTEM", "SEMVER"}:
                raise ValueError("Unsupported advisory range type")
            lower = None
            for event in interval["events"]:
                if "introduced" in event:
                    lower = event["introduced"]
                else:
                    if lower is None:
                        raise ValueError("Range end has no start")
                    if "fixed" in event:
                        end, fixed = "<" + event["fixed"], event["fixed"]
                    elif "last_affected" in event:
                        end, fixed = "<=" + event["last_affected"], None
                    elif "limit" in event:
                        end, fixed = "<" + event["limit"], None
                    else:
                        raise ValueError("Unsupported version event")
                    parts = ([">=" + lower] if lower != "0" else []) + [end]
                    targets.append({**base, "versions": ",".join(parts), "fixed": fixed})
                    lower = None
            if lower is not None:
                targets.append({**base, "versions": ">=" + lower, "fixed": None})
    refs = [r["url"] for r in record.get("references", []) if r["url"].startswith("https://")]
    source = "https://osv.dev/vulnerability/" + record["id"]
    return {
        "id": record["id"],
        "aliases": record.get("aliases", []),
        "summary": record.get("summary", record["id"]),
        "severity": record.get("database_specific", {}).get("severity", "unknown").lower(),
        "references": list(dict.fromkeys([source, *refs])),
        "affected": targets,
    }


def from_github(advisory_id):
    if not re.fullmatch(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", advisory_id):
        raise ValueError("Expected a GHSA identifier")
    source = "https://api.github.com/advisories/" + advisory_id
    data = json.loads(read_url(source))
    if data.get("withdrawn_at"):
        raise ValueError("Advisory has been withdrawn")
    targets = []
    for vuln in data["vulnerabilities"]:
        ecosystem = {"pip": "PyPI", "npm": "npm"}.get(vuln["package"]["ecosystem"])
        if not ecosystem:
            raise ValueError("Use a CVE import with an explicit product mapping for this ecosystem")
        patched = vuln.get("first_patched_version")
        fixed = patched.get("identifier") if isinstance(patched, dict) else patched
        # GitHub's API returns comma-delimited comparators; preserve disjoint branches.
        for branch in vuln["vulnerable_version_range"].split("||"):
            spec = re.sub(r"(?<![<>=!~])=(?!=)", "==", branch.strip())
            targets.append(
                {"ecosystem": ecosystem, "package": vuln["package"]["name"], "versions": spec, "fixed": fixed}
            )
    return {
        "id": data["ghsa_id"],
        "aliases": [i["value"] for i in data.get("identifiers", []) if i["value"] != advisory_id],
        "summary": data["summary"],
        "severity": {"medium": "moderate"}.get(data.get("severity"), data.get("severity", "unknown")),
        "references": list(
            dict.fromkeys(
                [
                    data["html_url"],
                    source,
                    *[r for r in data.get("references", []) if r.startswith("https://")],
                ]
            )
        ),
        "affected": targets,
    }


def from_cve(cve_id, *, ecosystem, package, versions, fixed=None, instructions=None):
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        raise ValueError("Expected a CVE identifier")
    if not all([ecosystem, package, versions]):
        raise ValueError("CVE imports require --ecosystem, --package and --versions from the vendor advisory")
    source = "https://cveawg.mitre.org/api/cve/" + cve_id
    data = json.loads(read_url(source))
    if data["cveMetadata"]["state"] != "PUBLISHED":
        raise ValueError("CVE record must be published")
    cna = data["containers"]["cna"]
    severity = "unknown"
    for metric in cna.get("metrics", []):
        for name, value in metric.items():
            if name.startswith("cvssV") and isinstance(value, dict) and value.get("baseSeverity"):
                severity = value["baseSeverity"].lower()
                if severity == "medium":
                    severity = "moderate"
    target = {"ecosystem": ecosystem, "package": package, "versions": versions, "fixed": fixed}
    if instructions:
        target["instructions"] = instructions
    return {
        "id": cve_id,
        "summary": cna.get("title", cve_id),
        "severity": severity,
        "references": [
            source,
            *[r["url"] for r in cna.get("references", []) if r["url"].startswith("https://")],
        ],
        "affected": [target],
    }


def merge(catalog, advisory):
    data = {
        **catalog,
        "updated": datetime.now(UTC).isoformat(),
        "advisories": [a for a in catalog["advisories"] if a["id"] != advisory["id"]] + [advisory],
    }
    return validate(data)
