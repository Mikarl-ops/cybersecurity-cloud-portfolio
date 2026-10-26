import tempfile
import unittest
from pathlib import Path

from _loader import load_module

MODULE = load_module(
    "failed_login_detector",
    "google-cybersecurity/python-automation/brute_force_detector/failed_login_detector.py",
)


class BruteForceDetectorTests(unittest.TestCase):
    def test_reports_threshold_within_window_and_ignores_invalid_ip(self):
        lines = [
            "2026-07-18 14:00:00 WARN Failed login attempt from 203.0.113.5 - bad password",
            "2026-07-18 14:00:30 WARN Failed login attempt from 203.0.113.5 - bad password",
            "2026-07-18 14:01:00 WARN Failed login attempt from 203.0.113.5 - bad password",
            "2026-07-18 14:01:30 WARN Failed login attempt from 203.0.113.5 - bad password",
            "2026-07-18 14:02:00 WARN Failed login attempt from 203.0.113.5 - bad password",
            "2026-07-18 14:02:10 WARN Failed login attempt from 999.999.999.999 - bad password",
        ]
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            log = Path(directory) / "auth.log"
            log.write_text(chr(10).join(lines), encoding="utf-8")
            self.assertEqual(MODULE.detect_brute_force(log), {"203.0.113.5": 5})

    def test_does_not_combine_failures_outside_window(self):
        lines = [
            "2026-07-18 14:00:00 WARN Failed login attempt from 203.0.113.5 - bad password",
            "2026-07-18 14:10:00 WARN Failed login attempt from 203.0.113.5 - bad password",
        ]
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            log = Path(directory) / "auth.log"
            log.write_text(chr(10).join(lines), encoding="utf-8")
            self.assertEqual(MODULE.detect_brute_force(log, threshold=2), {})


if __name__ == "__main__":
    unittest.main()
