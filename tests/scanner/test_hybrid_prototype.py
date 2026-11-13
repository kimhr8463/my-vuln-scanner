"""독립 하이브리드 프로토타입의 모델·오류·보고서 테스트."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.main import EXIT_ERROR, EXIT_FINDINGS, EXIT_SUCCESS
from validation.hybrid.engines import (
    QUERIES, CodeQLAdapter, SemgrepAdapter, parse_sarif, parse_semgrep,
)
from validation.hybrid.main import HybridApplication
from validation.hybrid.model import (
    EngineResult, FindingGrouper, HybridFinding, Location, finding_id,
)
from validation.hybrid.report import HybridReporter


def sample_finding(engine="semgrep_ce", start=3, end=None, index=0):
    sink = Location("same_direct.js", start, start if end is None else end)
    return HybridFinding(
        finding_id(engine, "command-rule", sink, index), engine, "command-rule",
        "Command Injection", "CWE-78", "WARNING", "MEDIUM", "UNREVIEWED",
        None, sink, (), "Source unavailable", "Command reaches exec",
        f"raw/{engine}.json", index,
    )


class HybridPrototypeTests(unittest.TestCase):
    def test_sarif_path_preserves_source_sink_and_steps(self):
        physical = lambda line: {
            "artifactLocation": {"uri": "same_direct.js"},
            "region": {"startLine": line},
        }
        payload = {"runs": [{"results": [{
            "ruleId": QUERIES["command"].query_id,
            "message": {"text": "Command flow"},
            "locations": [{"physicalLocation": physical(3)}],
            "codeFlows": [{"threadFlows": [{"locations": [
                {"location": {"physicalLocation": physical(2)}},
                {"location": {"physicalLocation": physical(3)}},
            ]}]}],
        }]}]}
        findings = parse_sarif(payload, Path("/tmp/project"), QUERIES["command"],
                               "raw/codeql.sarif")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].source.start_line, 2)
        self.assertEqual(findings[0].sink.start_line, 3)
        self.assertEqual(len(findings[0].flow_evidence), 2)
        self.assertEqual(findings[0].raw_result_index, 0)

    def test_sarif_missing_path_does_not_invent_source(self):
        payload = {"runs": [{"results": [{
            "ruleId": QUERIES["command"].query_id,
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "same_direct.js"},
                "region": {"startLine": 3},
            }}],
        }]}]}
        finding = parse_sarif(payload, Path("/tmp/project"), QUERIES["command"],
                              "raw/codeql.sarif")[0]
        self.assertIsNone(finding.source)
        self.assertEqual(finding.flow_evidence, ())

    def test_multiple_sarif_paths_are_not_concatenated(self):
        def location(line):
            return {"location": {"physicalLocation": {
                "artifactLocation": {"uri": "same_direct.js"},
                "region": {"startLine": line},
            }}}

        payload = {"runs": [{"results": [{
            "ruleId": QUERIES["command"].query_id,
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "same_direct.js"},
                "region": {"startLine": 3},
            }}],
            "codeFlows": [
                {"threadFlows": [{"locations": [location(1), location(3)]}]},
                {"threadFlows": [{"locations": [location(2), location(3)]}]},
            ],
        }]}]}
        finding = parse_sarif(payload, Path("/tmp/project"), QUERIES["command"],
                              "raw/codeql.sarif")[0]
        self.assertEqual([step.start_line for step in finding.flow_evidence], [1, 3])
        self.assertIn("2개 경로", finding.evidence_note)

    def test_semgrep_conversion_preserves_raw_index(self):
        raw = {
            "scanner_metadata": {"rules": ["javascript-command-injection-taint"]},
            "results": [{
                "check_id": "temp.javascript-command-injection-taint",
                "path": "/tmp/project/same_direct.js",
                "start": {"line": 3}, "end": {"line": 3},
                "extra": {"severity": "ERROR", "message": "Command flow",
                          "metadata": {"vulnerability": "Command Injection",
                                       "cwe": "CWE-78", "confidence": "HIGH"}},
            }],
        }
        finding = parse_semgrep(raw, Path("/tmp/project"), "raw/semgrep.json")[0]
        self.assertEqual(finding.engine, "semgrep_ce")
        self.assertEqual(finding.sink.path, "same_direct.js")
        self.assertEqual(finding.raw_result_index, 0)
        self.assertIsNone(finding.source)

    def test_cross_engine_overlap_groups_without_deleting_originals(self):
        semgrep = sample_finding(start=77, end=79)
        codeql = sample_finding("codeql", start=78)
        groups = FindingGrouper().group([semgrep, codeql])
        self.assertEqual(len(groups), 1)
        self.assertEqual(set(groups[0].member_ids), {semgrep.finding_id, codeql.finding_id})
        self.assertEqual(groups[0].engines, ("codeql", "semgrep_ce"))

    def test_different_cwe_or_nonoverlap_not_grouped(self):
        first = sample_finding(start=3)
        second = sample_finding("codeql", start=5)
        self.assertEqual(len(FindingGrouper().group([first, second])), 2)

    def test_codeql_missing_is_unavailable(self):
        with tempfile.TemporaryDirectory() as temporary, patch(
            "validation.hybrid.engines.shutil.which", return_value=None
        ):
            result = CodeQLAdapter(QUERIES["command"]).run(
                Path(temporary), Path(temporary))
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.error_stage, "availability")

    def test_codeql_failure_is_separate_from_semgrep(self):
        with tempfile.TemporaryDirectory() as temporary, patch(
            "validation.hybrid.engines.shutil.which", return_value="/bin/false"
        ), patch.object(CodeQLAdapter, "_execute", side_effect=RuntimeError("failed")):
            result = CodeQLAdapter(QUERIES["command"]).run(
                Path(temporary), Path(temporary))
        self.assertEqual(result.status, "error")
        self.assertEqual(result.error_stage, "database_create")

    def test_semgrep_failure_is_engine_scoped(self):
        with tempfile.TemporaryDirectory() as temporary, patch(
            "validation.hybrid.engines.SemgrepRunner.scan", side_effect=RuntimeError("broken")
        ):
            result = SemgrepAdapter(Path(temporary)).run(Path(temporary), Path(temporary))
        self.assertEqual(result.status, "error")
        self.assertIn("broken", result.error_message)

    def test_both_report_preserves_each_engine_and_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            target.mkdir()
            semgrep = EngineResult("semgrep_ce", "success", 1.0,
                                   [sample_finding()], "raw/semgrep.json")
            codeql = EngineResult("codeql", "success", 2.0,
                                 [sample_finding("codeql")], "raw/codeql.sarif")
            with patch.object(SemgrepAdapter, "run", return_value=semgrep), patch.object(
                CodeQLAdapter, "run", return_value=codeql
            ):
                outcome = HybridApplication().scan(target, output_dir=Path(temporary) / "out")
            report = json.loads(outcome.report_paths[0].read_text(encoding="utf-8"))
            markdown = outcome.report_paths[1].read_text(encoding="utf-8")
            self.assertEqual(outcome.exit_code, EXIT_FINDINGS)
            self.assertEqual(report["summary"]["total_findings"], 2)
            self.assertEqual(report["summary"]["cross_engine_groups"], 1)
            self.assertEqual(len(report["findings"]), 2)
            self.assertEqual(len(report["groups"][0]["member_ids"]), 2)
            self.assertIn("개별 Finding", markdown)
            self.assertIn("semgrep_ce", markdown)
            self.assertIn("codeql", markdown)

    def test_missing_codeql_does_not_stop_semgrep_or_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            target.mkdir()
            semgrep = EngineResult("semgrep_ce", "success", 1.0,
                                   [sample_finding()], "raw/semgrep.json")
            unavailable = EngineResult("codeql", "unavailable", 0.0,
                                       error_stage="availability", error_message="missing")
            with patch.object(SemgrepAdapter, "run", return_value=semgrep), patch.object(
                CodeQLAdapter, "run", return_value=unavailable
            ):
                outcome = HybridApplication().scan(target, output_dir=Path(temporary) / "out")
            self.assertEqual(outcome.exit_code, EXIT_ERROR)
            self.assertEqual(outcome.total_findings, 1)
            self.assertTrue(all(path.exists() for path in outcome.report_paths))

    def test_semgrep_error_does_not_stop_codeql_or_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            target.mkdir()
            semgrep_error = EngineResult("semgrep_ce", "error", 0.1,
                                         error_stage="scan_or_parse", error_message="bad rules")
            codeql = EngineResult("codeql", "success", 1.0,
                                  [sample_finding("codeql")], "raw/codeql.sarif")
            with patch.object(SemgrepAdapter, "run", return_value=semgrep_error), patch.object(
                CodeQLAdapter, "run", return_value=codeql
            ):
                outcome = HybridApplication().scan(target, output_dir=Path(temporary) / "out")
            report = json.loads(outcome.report_paths[0].read_text(encoding="utf-8"))
            self.assertEqual(outcome.exit_code, EXIT_ERROR)
            self.assertEqual(report["summary"]["total_findings"], 1)
            self.assertEqual(report["engines"][0]["status"], "error")
            self.assertEqual(report["engines"][1]["status"], "success")

    def test_zero_findings_success_and_original_exit_policy(self):
        report = HybridReporter().build("example", Path("/tmp/example"), "run-1",
                                        [EngineResult("semgrep_ce", "success", 0.1)], [])
        self.assertEqual(report["summary"]["total_findings"], 0)
        self.assertEqual((EXIT_SUCCESS, EXIT_ERROR, EXIT_FINDINGS), (0, 1, 2))

    def test_invalid_target_rejected_before_engine_execution(self):
        with self.assertRaisesRegex(ValueError, "existing directory"):
            HybridApplication().scan("/tmp/hybrid-target-that-does-not-exist")


if __name__ == "__main__":
    unittest.main()
