"""엔진 비교 프로젝트 및 결과 매핑의 회귀 테스트."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.result_parser import ResultParser
from scanner.semgrep_runner import SemgrepRunner
from tests.scanner.test_javascript_rules import ROOT, semgrep_environment
from validation.engine_comparison.run_comparison import (
    CASES, PROJECT, RULE_ID, build_cases, sarif_locations,
)


class EngineComparisonTests(unittest.TestCase):
    def test_cases_have_real_sinks(self):
        self.assertEqual(len(CASES), 9)
        for path, _ in CASES.values():
            self.assertTrue((PROJECT / path).is_file(), path)

    def test_result_mapping_keeps_missing_and_safe_cases(self):
        rows = build_cases(
            [{"path": "safe_numeric.js", "line": 4, "rule_id": RULE_ID}],
            [{"path": "two_file/dao.js", "line": 3, "rule_id": "example"}],
        )
        by_case = {row["case"]: row for row in rows}
        self.assertTrue(by_case["safe_numeric"]["semgrep_detected"])
        self.assertFalse(by_case["safe_numeric"]["codeql_detected"])
        self.assertFalse(by_case["two_file"]["semgrep_detected"])
        self.assertTrue(by_case["two_file"]["codeql_detected"])
        self.assertFalse(by_case["safe_fixed"]["semgrep_detected"])

    def test_sarif_location_extraction(self):
        payload = {"runs": [{"results": [{
            "ruleId": "example",
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "two_file/dao.js"},
                "region": {"startLine": 3},
            }}],
        }]}]}
        self.assertEqual(sarif_locations(payload), [
            {"path": "two_file/dao.js", "line": 3, "rule_id": "example"}
        ])

    def test_observed_results_cover_every_case(self):
        recorded = ROOT / "validation" / "engine_comparison" / "observed-results.json"
        payload = json.loads(recorded.read_text(encoding="utf-8"))
        self.assertEqual({row["case"] for row in payload["cases"]}, set(CASES))
        self.assertEqual(len(payload["cases"]), len(CASES))
        self.assertTrue(all(value > 0 for value in payload["seconds"].values()))

    def test_existing_semgrep_rule_on_shared_project(self):
        with tempfile.TemporaryDirectory(prefix="scanner-engine-test-") as temporary:
            environment = semgrep_environment(Path(temporary))
            with patch.dict("os.environ", environment, clear=True):
                raw = SemgrepRunner(ROOT / "rules" / "javascript").scan(PROJECT)
        self.assertEqual(raw["errors"], [])
        self.assertEqual(raw.get("engine_requested"), "OSS")
        findings = ResultParser(raw["scanner_metadata"]["rules"]).parse(raw)
        paths = {Path(item.file_path).relative_to(PROJECT).as_posix()
                 for item in findings if item.rule_id == RULE_ID}
        self.assertEqual(paths, {
            "same_direct.js", "same_intermediate.js", "destructured.js",
            "nested_destructured.js", "safe_numeric.js",
        })
        self.assertTrue(all(item.rule_id == RULE_ID for item in findings))


if __name__ == "__main__":
    unittest.main()
