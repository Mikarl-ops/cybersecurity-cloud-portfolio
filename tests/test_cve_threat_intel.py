import json
import unittest
from unittest.mock import patch

from _loader import load_module

MODULE = load_module(
    "cve_threat_intel",
    "google-cybersecurity/python-automation/Threat_intelligence_API_automation/cve_threat_intel.py",
)


class CveThreatIntelTests(unittest.TestCase):
    def test_https_request_encodes_keyword_filters_and_extracts_cvss(self):
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
        connection = patch.object(MODULE, "HTTPSConnection").start()
        self.addCleanup(patch.stopall)
        response = connection.return_value.getresponse.return_value
        response.status = 200
        response.read.return_value = json.dumps(payload).encode("utf-8")

        results = MODULE.fetch_critical_cves("Apache Tomcat / security", max_results=5)

        self.assertEqual([result["id"] for result in results], ["CVE-2026-0001"])
        connection.assert_called_once_with("services.nvd.nist.gov", timeout=15)
        connection.return_value.request.assert_called_once()
        method, path = connection.return_value.request.call_args.args[:2]
        self.assertEqual(method, "GET")
        self.assertIn("keywordSearch=Apache+Tomcat+%2F+security", path)
        self.assertTrue(path.startswith("/rest/json/cves/2.0?"))
        connection.return_value.close.assert_called_once()

    def test_rejects_non_success_http_status(self):
        with patch.object(MODULE, "HTTPSConnection") as connection:
            connection.return_value.getresponse.return_value.status = 503
            with self.assertRaisesRegex(RuntimeError, "HTTP 503"):
                MODULE.fetch_critical_cves("nginx")
            connection.return_value.close.assert_called_once()

    def test_rejects_invalid_severity(self):
        with self.assertRaises(ValueError):
            MODULE.fetch_critical_cves("nginx", min_severity="urgent")

    def test_rejects_blank_keyword(self):
        with self.assertRaises(ValueError):
            MODULE.fetch_critical_cves("   ")


if __name__ == "__main__":
    unittest.main()
