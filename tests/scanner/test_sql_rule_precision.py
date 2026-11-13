"""JavaScript SQL Rule의 오탐 회귀와 실제 Semgrep Rule 테스트."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.result_parser import ResultParser
from scanner.semgrep_runner import SemgrepRunner
from tests.scanner.test_javascript_rules import ROOT, semgrep_environment


RULE = "javascript-sql-injection-taint"
RULES = ROOT / "rules" / "javascript"


class SqlRulePrecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="scanner-sql-precision-")
        cls.addClassCleanup(temporary.cleanup)
        cls.environment = semgrep_environment(Path(temporary.name))
        with patch.dict("os.environ", cls.environment, clear=True):
            raw = SemgrepRunner(RULES).scan(ROOT / "tests" / "javascript" / "nosql" / "safe")
        if raw["errors"]:
            raise AssertionError(raw["errors"])
        cls.safe_findings = ResultParser(raw["scanner_metadata"]["rules"]).parse(raw)

    def test_semgrep_annotated_rule_cases(self):
        process = subprocess.run(
            [str(ROOT / ".venv" / "bin" / "semgrep"), "test", "--config",
             str(RULES / "sql_injection.yml"), str(RULES / "sql_injection.js"), "--json"],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
        checks = json.loads(process.stdout)["results"][str(RULES / "sql_injection.yml")]["checks"]
        self.assertTrue(checks[RULE]["passed"])

    def test_ordinary_query_and_nosql_safe_fixture_have_no_findings(self):
        self.assertEqual(self.safe_findings, [])


if __name__ == "__main__":
    unittest.main()
