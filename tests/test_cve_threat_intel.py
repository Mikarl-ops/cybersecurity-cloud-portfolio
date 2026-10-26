import json
import unittest
from io import BytesIO
from unittest.mock import patch

from _loader import load_module

MODULE = load_module(
    "cve_threat_intel",
    "google-cybersecurity/python-automation/Threat_intelligence_API_automation/cve_threat_intel.py",
)


class CveThreatIntelTests(unittest.TestCase):
    def test_url_encodes_keyword_filters_and_extracts_cvss(self):
        payload = {
            "vulnerabilities": [
                {"cve": {
                    "id": "CVE-2026-0001",
                    "descriptions": [{"lang": "en", "value": "Example issue"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL", "baseScore": 9.8}}]},
                }},
                {"cve": {
                    "id": "CVE-2026-0002",
                    "descriptions": [{"lang": "en", "value": "Lower severity"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "MEDIUM", "baseScore": 5.0}}]},
                }},
            ]
        }
        response = BytesIO(json.dumps(payload).encode("utf-8"))
        with patch.object(MODULE, "urlopen", return_value=response) as urlopen:
            results = MODULE.fetch_critical_cves("Apache Tomcat / security", max_results=5)
        self.assertEqual([result["id"] for result in results], ["CVE-2026-0001"])
        request = urlopen.call_args.args[0]
        self.assertIn("keywordSearch=Apache+Tomcat+%2F+security", request.full_url)
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 15)

    def test_rejects_invalid_severity(self):
        with self.assertRaises(ValueError):
            MODULE.fetch_critical_cves("nginx", min_severity="urgent")


if __name__ == "__main__":
    unittest.main()
