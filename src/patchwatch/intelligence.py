"""CISA KEV and FIRST EPSS enrich CVE findings with dated prioritization evidence."""

import json
import re
from datetime import UTC, datetime
from urllib.parse import urlencode

from .catalog import read_url

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def enrich(report):
    cves = set()
    for finding in report["findings"]:
        ids = [finding["advisory"], *finding.get("aliases", [])]
        finding["cves"] = sorted({v for v in ids if re.fullmatch(r"CVE-\d{4}-\d{4,}", v)})
        cves.update(finding["cves"])
    evidence = {"checked_at": datetime.now(UTC).isoformat(), "sources": {}, "errors": []}
    kev, scores = {}, {}
    if cves:
        try:
            data = json.loads(read_url(KEV_URL))
            if not isinstance(data.get("vulnerabilities"), list) or not data.get("dateReleased"):
                raise ValueError("Invalid KEV response")
            kev = {v["cveID"]: v for v in data["vulnerabilities"]}
            evidence["sources"]["kev"] = {"url": KEV_URL, "released": data["dateReleased"], "count": len(kev)}
        except Exception as exc:
            evidence["errors"].append("CISA KEV: " + str(exc))
        try:
            ordered = sorted(cves)
            for start in range(0, len(ordered), 100):
                url = (
                    EPSS_URL + "?" + urlencode({"cve": ",".join(ordered[start : start + 100]), "limit": 100})
                )
                data = json.loads(read_url(url))
                if data.get("status") != "OK" or not isinstance(data.get("data"), list):
                    raise ValueError("Invalid EPSS response")
                if int(data.get("total", len(data["data"]))) > len(data["data"]):
                    raise ValueError("Incomplete EPSS response")
                for row in data["data"]:
                    probability, percentile = float(row["epss"]), float(row["percentile"])
                    if not 0 <= probability <= 1 or not 0 <= percentile <= 1:
                        raise ValueError("EPSS probability outside [0, 1]")
                    scores[row["cve"]] = {
                        "probability": probability,
                        "percentile": percentile,
                        "date": row["date"],
                    }
            evidence["sources"]["epss"] = {"url": EPSS_URL, "matched": len(scores)}
        except Exception as exc:
            scores = {}
            evidence["errors"].append("FIRST EPSS: " + str(exc))
    for finding in report["findings"]:
        matches = [kev[c] for c in finding["cves"] if c in kev]
        finding["exploitation"] = {
            "kev_status": ("listed" if matches else "not-listed")
            if "kev" in evidence["sources"]
            else "unknown",
            "kev": matches,
            "epss": {c: scores[c] for c in finding["cves"] if c in scores},
        }
    severity = {"critical": 4, "high": 3, "moderate": 2, "low": 1, "unknown": 0}

    def priority(finding):
        exp = finding["exploitation"]
        return (
            exp["kev_status"] == "listed",
            max((s["probability"] for s in exp["epss"].values()), default=-1),
            severity.get(finding["severity"], 0),
        )

    report["findings"].sort(key=priority, reverse=True)
    report["warnings"].extend(evidence["errors"])
    report["intelligence"] = evidence
    return report
