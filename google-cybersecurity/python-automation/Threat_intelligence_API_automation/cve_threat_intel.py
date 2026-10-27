"""Query the NVD CVE API and return vulnerabilities with a high CVSS severity."""

import json
from http.client import HTTPException, HTTPSConnection
from urllib.parse import urlencode

API_HOST = "services.nvd.nist.gov"
API_PATH = "/rest/json/cves/2.0"
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _cvss_details(cve):
    metrics = cve.get("metrics", {})
    for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_name, [])
        if not entries:
            continue
        details = entries[0].get("cvssData", {})
        severity = details.get("baseSeverity") or entries[0].get("baseSeverity")
        score = details.get("baseScore")
        if severity:
            return severity.upper(), score
    return None, None


def fetch_critical_cves(keyword, max_results=20, min_severity="HIGH", timeout=15):
    """Return matching CVEs at or above min_severity; raise RuntimeError on API errors."""
    if not keyword.strip():
        raise ValueError("keyword must not be empty")
    if not 1 <= max_results <= 2000:
        raise ValueError("max_results must be between 1 and 2000")
    minimum = min_severity.upper()
    if minimum not in SEVERITY_RANK:
        raise ValueError("min_severity must be LOW, MEDIUM, HIGH, or CRITICAL")

    query = urlencode({"keywordSearch": keyword, "resultsPerPage": max_results})
    # HTTPSConnection fixes the scheme and host; user input is confined to the encoded path query.
    connection = HTTPSConnection(API_HOST, timeout=timeout)
    try:
        connection.request(
            "GET",
            f"{API_PATH}?{query}",
            headers={"User-Agent": "CybersecurityPortfolio/1.0"},
        )
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError(f"NVD query failed: HTTP {response.status}")
        data = json.loads(response.read().decode("utf-8"))
    except (HTTPException, OSError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"NVD query failed: {exc}") from exc
    finally:
        connection.close()

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        severity, score = _cvss_details(cve)
        if severity not in SEVERITY_RANK or SEVERITY_RANK[severity] < SEVERITY_RANK[minimum]:
            continue
        description = next(
            (entry.get("value", "") for entry in cve.get("descriptions", []) if entry.get("lang") == "en"),
            "No English description available.",
        )
        cve_id = cve.get("id")
        results.append({
            "id": cve_id,
            "severity": severity,
            "score": score,
            "description": description,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })
    return results


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("keyword", help="Keyword to search in NVD")
    parser.add_argument("--max-results", type=int, default=20)
    parser.add_argument("--min-severity", choices=SEVERITY_RANK, default="HIGH")
    args = parser.parse_args()
    for cve in fetch_critical_cves(args.keyword, args.max_results, args.min_severity):
        print(f"{cve['id']} [{cve['severity']} {cve['score']}]: {cve['description'][:240]}")
        print(cve["url"])


if __name__ == "__main__":
    main()
