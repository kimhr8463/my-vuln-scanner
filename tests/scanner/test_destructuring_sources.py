"""JavaScript Rule의 Express 구조 분해 Source 인식 범위를 검증한다."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.result_parser import ResultParser
from scanner.semgrep_runner import SemgrepRunner
from tests.scanner.test_javascript_rules import ROOT, semgrep_environment


FIXTURES = ROOT / "tests" / "javascript" / "destructuring"
RULES = ROOT / "rules" / "javascript"
NOSQL_TAINT = "javascript-mongodb-nosql-injection-taint"
NOSQL_CANDIDATE = "javascript-mongodb-dynamic-where-candidate"
COMMAND_TAINT = "javascript-command-injection-taint"


class DestructuringSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="scanner-destructuring-")
        cls.addClassCleanup(temporary.cleanup)
        environment = semgrep_environment(Path(temporary.name))
        with patch.dict("os.environ", environment, clear=True):
            raw = SemgrepRunner(RULES).scan(FIXTURES)
        if raw["errors"]:
            raise AssertionError(raw["errors"])
        cls.engine_requested = raw.get("engine_requested")
        cls.engine_kinds = {result["extra"].get("engine_kind") for result in raw["results"]}
        findings = ResultParser(raw["scanner_metadata"]["rules"]).parse(raw)
        cls.by_file = {}
        for finding in findings:
            relative = Path(finding.file_path).relative_to(FIXTURES).as_posix()
            cls.by_file.setdefault(relative, []).append((finding.rule_id, finding.start_line))

    def assert_findings(self, filename, expected):
        self.assertCountEqual(self.by_file.get(filename, []), expected)

    def test_community_engine(self):
        self.assertEqual(self.engine_requested, "OSS")
        self.assertEqual(self.engine_kinds, {"OSS"})

    def test_query_destructuring_matches_broad_nosql_source(self):
        self.assert_findings("query_direct.js", [(NOSQL_TAINT, 3)])
        self.assert_findings("query_destructured.js", [(NOSQL_TAINT, 3)])
        self.assert_findings("query_multiline.js", [(NOSQL_TAINT, 5)])

    def test_query_alias_destructuring_matches(self):
        self.assert_findings("alias_destructured.js", [(NOSQL_TAINT, 3)])

    def test_body_destructuring_is_now_detected_by_command_rule(self):
        self.assert_findings("body_direct.js", [(COMMAND_TAINT, 5)])
        self.assert_findings("body_destructured.js", [(COMMAND_TAINT, 5)])
        self.assert_findings("body_destructured_nosql.js", [(NOSQL_TAINT, 3)])

    def test_nested_destructuring_is_detected_only_by_command_rule(self):
        self.assert_findings("nested_destructured.js", [(COMMAND_TAINT, 5)])
        self.assert_findings("nested_destructured_nosql.js", [])

    def test_constant_input_is_not_detected(self):
        self.assert_findings("fixed.js", [])

    def test_source_without_sink_has_no_finding(self):
        self.assert_findings("source_only.js", [])

    def test_cross_file_destructured_source_is_only_structural_candidate(self):
        self.assert_findings("cross_file/route.js", [])
        self.assert_findings("cross_file/dao.js", [(NOSQL_CANDIDATE, 2)])

    def test_no_unexpected_findings(self):
        self.assertEqual(sum(map(len, self.by_file.values())), 9)


if __name__ == "__main__":
    unittest.main()
