"""MongoDB Rule의 실제 Semgrep 테스트와 고정 NodeGoat 통합 검증."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.result_parser import ResultParser
from scanner.rule_loader import RuleLoader
from scanner.semgrep_runner import SemgrepRunner
from tests.scanner.test_javascript_rules import ROOT, semgrep_environment
from validation.quality import load_targets, verify_target


RULES = ROOT / "rules" / "javascript"
FIXTURES = ROOT / "tests" / "javascript" / "nosql"
TAINT = "javascript-mongodb-nosql-injection-taint"
CANDIDATE = "javascript-mongodb-dynamic-where-candidate"


class NoSqlRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="scanner-nosql-")
        cls.addClassCleanup(temporary.cleanup)
        cls.environment = semgrep_environment(Path(temporary.name))
        cls.findings = {}
        with patch.dict("os.environ", cls.environment, clear=True):
            for case in ("vulnerable", "safe", "cross_file"):
                raw = SemgrepRunner(RULES).scan(FIXTURES / case)
                if raw["errors"]:
                    raise AssertionError(raw["errors"])
                cls.findings[case] = ResultParser(raw["scanner_metadata"]["rules"]).parse(raw)

    def test_semgrep_rule_fixture(self):
        process = subprocess.run(
            [str(ROOT / ".venv" / "bin" / "semgrep"), "test", "--config",
             str(RULES / "nosql_injection.yml"), str(RULES / "nosql_injection.js"), "--json"],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
        checks = json.loads(process.stdout)["results"][str(RULES / "nosql_injection.yml")]["checks"]
        self.assertTrue(checks[TAINT]["passed"])
        self.assertTrue(checks[CANDIDATE]["passed"])

    def test_rule_loader_discovers_nosql_separately_from_sql(self):
        ids = {rule_id for info in RuleLoader(ROOT / "rules").load_rules() for rule_id in info.rule_ids}
        self.assertEqual(len(ids), 9)
        self.assertTrue({TAINT, CANDIDATE, "javascript-sql-injection-taint"} <= ids)

    def test_vulnerable_sources_and_intermediate_flow(self):
        by_rule = {rule: {item.start_line for item in self.findings["vulnerable"] if item.rule_id == rule}
                   for rule in (TAINT, CANDIDATE)}
        self.assertEqual(by_rule[TAINT], {2, 7, 12, 17})
        self.assertEqual(by_rule[CANDIDATE], {21})
        self.assertTrue(all(item.cwe == "CWE-943" and item.vulnerability == "MongoDB NoSQL Injection"
                            for item in self.findings["vulnerable"]))

    def test_fixed_and_numeric_queries_and_ordinary_query_are_safe(self):
        self.assertEqual(self.findings["safe"], [])

    def test_cross_file_flow_is_candidate_not_confirmed_taint(self):
        findings = self.findings["cross_file"]
        self.assertEqual([(item.rule_id, Path(item.file_path).name, item.start_line) for item in findings],
                         [(CANDIDATE, "dao.js", 2)])
        self.assertFalse(any(item.rule_id == TAINT for item in findings))


class NodeGoatNoSqlIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="scanner-nodegoat-nosql-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.environment = semgrep_environment(self.base)
        self.target = load_targets()["nodegoat"]
        verify_target(self.target)

    def test_pinned_nodegoat_and_cli_reports(self):
        output = self.base / "reports"
        process = subprocess.run(
            [sys.executable, "-m", "scanner.main", "scan", str(self.target.path), "--output", str(output)],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=90,
        )
        self.assertEqual(process.returncode, 2, process.stderr)
        payload = json.loads((output / "nodegoat-scan.json").read_text(encoding="utf-8"))
        markdown = (output / "nodegoat-scan.md").read_text(encoding="utf-8")
        self.assertEqual(payload["total_findings"], 1)
        self.assertEqual(payload["by_cwe"], {"CWE-943": 1})
        finding = payload["findings"][0]
        self.assertEqual(finding["rule_id"], CANDIDATE)
        self.assertEqual(finding["confidence"], "MEDIUM")
        self.assertEqual(finding["start_line"], 77)
        self.assertEqual(Path(finding["file_path"]).name, "allocations-dao.js")
        self.assertIn("javascript-mongodb-dynamic-where-candidate", markdown)
        self.assertIn("CWE-943", markdown)
        self.assertIn("보고서 저장:", process.stdout)
        verify_target(self.target)


if __name__ == "__main__":
    unittest.main()
