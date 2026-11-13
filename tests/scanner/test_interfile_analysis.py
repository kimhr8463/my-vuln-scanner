"""Semgrep CE의 파일/함수 경계 결과와 구조적 후보의 차이를 고정한다."""

import tempfile
import unittest
from collections import defaultdict
from pathlib import Path
from unittest.mock import patch

from scanner.result_parser import ResultParser
from scanner.semgrep_runner import SemgrepRunner
from tests.scanner.test_javascript_rules import ROOT, semgrep_environment
from validation.quality import load_targets, verify_target


FIXTURES = ROOT / "tests" / "javascript" / "interfile"
RULES = ROOT / "rules" / "javascript"
TAINT = "javascript-mongodb-nosql-injection-taint"
CANDIDATE = "javascript-mongodb-dynamic-where-candidate"


class InterfileAnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="scanner-interfile-")
        cls.addClassCleanup(temporary.cleanup)
        environment = semgrep_environment(Path(temporary.name))
        with patch.dict("os.environ", environment, clear=True):
            raw = SemgrepRunner(RULES).scan(FIXTURES)
            target = load_targets()["nodegoat"]
            verify_target(target)
            nodegoat_raw = SemgrepRunner(RULES).scan(target.path)
            verify_target(target)

        if raw["errors"] or nodegoat_raw["errors"]:
            raise AssertionError((raw["errors"], nodegoat_raw["errors"]))
        cls.engine_requested = raw.get("engine_requested")
        cls.engine_kinds = {item["extra"].get("engine_kind") for item in raw["results"]}
        findings = ResultParser(raw["scanner_metadata"]["rules"]).parse(raw)
        cls.by_case = defaultdict(list)
        for finding in findings:
            relative = Path(finding.file_path).relative_to(FIXTURES)
            cls.by_case[relative.parts[0]].append((finding.rule_id, relative.name, finding.start_line))

        cls.nodegoat_findings = ResultParser(nodegoat_raw["scanner_metadata"]["rules"]).parse(nodegoat_raw)
        cls.nodegoat_engine = nodegoat_raw.get("engine_requested")

    def test_community_engine_used(self):
        self.assertEqual(self.engine_requested, "OSS")
        self.assertEqual(self.engine_kinds, {"OSS"})
        self.assertEqual(self.nodegoat_engine, "OSS")

    def test_same_file_local_flow(self):
        self.assertCountEqual(self.by_case["same_file"], [
            (TAINT, "direct.js", 3),
            (TAINT, "direct.js", 4),
        ])

    def test_two_file_flow_is_only_structural_candidate(self):
        self.assertEqual(self.by_case["two_file"], [(CANDIDATE, "dao.js", 2)])

    def test_three_file_flow_is_only_structural_candidate(self):
        self.assertEqual(self.by_case["three_file"], [(CANDIDATE, "dao.js", 2)])

    def test_same_file_helper_argument_is_not_proven_at_where(self):
        self.assertCountEqual(self.by_case["helper_argument"], [
            (CANDIDATE, "route.js", 2),
            (TAINT, "route.js", 7),
        ])

    def test_numeric_conversion_sanitizes_local_flow(self):
        self.assertEqual(self.by_case["sanitized_same_file"], [])

    def test_structural_candidate_cannot_see_caller_sanitization(self):
        self.assertEqual(self.by_case["sanitized_two_file"], [(CANDIDATE, "dao.js", 2)])

    def test_fixed_query_has_no_findings(self):
        self.assertEqual(self.by_case["fixed_query"], [])

    def test_pinned_nodegoat_is_structural_candidate_only(self):
        self.assertEqual(
            [(item.rule_id, Path(item.file_path).relative_to(load_targets()["nodegoat"].path).as_posix(),
              item.start_line) for item in self.nodegoat_findings],
            [(CANDIDATE, "app/data/allocations-dao.js", 77)],
        )


if __name__ == "__main__":
    unittest.main()
