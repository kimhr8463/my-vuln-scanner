import unittest
from pathlib import Path

from scanner.rule_loader import RuleLoader


class TestRuleLoader(unittest.TestCase):

    def setUp(self):
        self.project_root = Path(__file__).resolve().parents[2]
        self.rules_dir = self.project_root / "rules"
        self.loader = RuleLoader(self.rules_dir)

    def test_discover_rules(self):
        files = self.loader.discover()

        self.assertGreaterEqual(len(files), 4)

        for file_path in files:
            self.assertTrue(file_path.exists())
            self.assertIn(file_path.suffix, (".yml", ".yaml"))

    def test_load_rules(self):
        rules = self.loader.load_rules()

        rule_ids = {
            rule_id
            for rule in rules
            for rule_id in rule.rule_ids
        }

        expected_ids = {
            "python-command-injection-taint",
            "python-sql-injection-taint",
            "python-path-traversal-taint",
            "python-ssrf-taint",
        }

        self.assertTrue(expected_ids.issubset(rule_ids))

    def test_rule_languages(self):
        rules = self.loader.load_rules()

        for rule in rules:
            self.assertIn(rule.file_path.parent.name, rule.languages)


if __name__ == "__main__":
    unittest.main()
