import tempfile
import unittest
from pathlib import Path

from _loader import load_module

MODULE = load_module(
    "firewall_rule_generator",
    "google-cybersecurity/python-automation/active_threat_mitigation/firewall_rule_generator.py",
)


class FirewallRuleGeneratorTests(unittest.TestCase):
    def test_validates_deduplicates_and_writes_without_executing(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            feed = Path(directory) / "feed.txt"
            output = Path(directory) / "rules.sh"
            feed.write_text(chr(10).join(["203.0.113.5", "2001:db8::1", "203.0.113.5"]), encoding="utf-8")
            addresses = MODULE.generate_firewall_rules(feed, output)
            self.assertEqual(addresses, ["203.0.113.5", "2001:db8::1"])
            script = output.read_text(encoding="utf-8")
            self.assertIn("iptables -A INPUT -s 203.0.113.5 -j DROP", script)
            self.assertIn("ip6tables -A INPUT -s 2001:db8::1 -j DROP", script)

    def test_invalid_feed_does_not_replace_existing_output(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            feed = Path(directory) / "feed.txt"
            output = Path(directory) / "rules.sh"
            feed.write_text(chr(10).join(["203.0.113.5", "not-an-ip"]), encoding="utf-8")
            output.write_text("previous content", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "line 2"):
                MODULE.generate_firewall_rules(feed, output)
            self.assertEqual(output.read_text(encoding="utf-8"), "previous content")


if __name__ == "__main__":
    unittest.main()
