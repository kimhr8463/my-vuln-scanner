import tempfile
import unittest

from pathlib import Path

from scanner.semgrep_runner import SemgrepRunner


class TestSemgrepRunner(unittest.TestCase):

    def setUp(self):
        self.project_root = Path(__file__).resolve().parents[2]

        self.runner = SemgrepRunner(
            rules_dir=self.project_root / "rules"
        )

    def test_build_config(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "combined.yml"

            rule_ids = self.runner.build_config(config_path)

            self.assertTrue(config_path.exists())
            self.assertEqual(len(rule_ids), 9)

    def test_scan(self):
        target = self.project_root / "rules" / "python"

        report = self.runner.scan(target)

        self.assertIn("results", report)
        self.assertIn("errors", report)
        self.assertIn("scanner_metadata", report)

        self.assertGreater(
            len(report["results"]), 0
        )

    def test_invalid_target(self):
        with self.assertRaises(FileNotFoundError):
            self.runner.scan(
                self.project_root / "does-not-exist"
            )


if __name__ == "__main__":
    unittest.main()
