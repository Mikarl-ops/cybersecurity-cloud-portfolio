import json
import tempfile
import unittest
from pathlib import Path

from _loader import load_module

MODULE = load_module(
    "cloudtrail_evasion_detector",
    "google-cybersecurity/python-automation/evasion-detector/cloudtrail_evasion_detector.py",
)


class CloudTrailDetectorTests(unittest.TestCase):
    def test_returns_normalized_cloudtrail_findings(self):
        payload = {
            "Records": [
                {
                    "eventTime": "2026-01-01T00:00:00Z",
                    "eventSource": "cloudtrail.amazonaws.com",
                    "eventName": "StopLogging",
                    "userIdentity": {"arn": "arn:aws:iam::123456789012:user/demo"},
                    "sourceIPAddress": "203.0.113.9",
                },
                {"eventSource": "ec2.amazonaws.com", "eventName": "DescribeInstances"},
            ]
        }
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path = Path(directory) / "events.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            findings = MODULE.analyze_cloudtrail_log(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["event_name"], "StopLogging")
        self.assertEqual(findings[0]["source_ip"], "203.0.113.9")

    def test_invalid_json_returns_no_findings(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path = Path(directory) / "events.json"
            path.write_text("{broken", encoding="utf-8")
            self.assertEqual(MODULE.analyze_cloudtrail_log(path), [])


if __name__ == "__main__":
    unittest.main()
