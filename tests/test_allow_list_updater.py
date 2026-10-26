import tempfile
import unittest
from pathlib import Path

from _loader import load_module

MODULE = load_module(
    "allow_list_updater",
    "google-cybersecurity/python-automation/Automated Log File Access/allow_list_updater.py",
)


class AllowListUpdaterTests(unittest.TestCase):
    def test_writes_filtered_copy_and_preserves_source(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            source = Path(directory) / "allow.txt"
            output = Path(directory) / "filtered.txt"
            original = chr(10).join(["192.0.2.1", "198.51.100.5", "192.0.2.1"]) + chr(10)
            source.write_text(original, encoding="utf-8")
            removed = MODULE.update_allow_list(source, ["192.0.2.1"], output)
            self.assertEqual(removed, ["192.0.2.1", "192.0.2.1"])
            self.assertEqual(source.read_text(encoding="utf-8"), original)
            self.assertEqual(output.read_text(encoding="utf-8"), "198.51.100.5" + chr(10))


if __name__ == "__main__":
    unittest.main()
