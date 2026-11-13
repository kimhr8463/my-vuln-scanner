"""JavaScript CodeQL 배치 실행·부분 실패·보고서 회귀 테스트."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.main import EXIT_ERROR, EXIT_FINDINGS
from validation.hybrid.check_javascript_queries import compare, expected_locations
from validation.hybrid.engines import (
    BATCH_QUERIES, JAVASCRIPT_QUERY_KEYS, QUERIES, CodeQLBatchAdapter,
)
from validation.hybrid.main import HybridApplication, build_parser
from validation.hybrid.model import EngineResult, HybridFinding, Location, finding_id


def sample_sarif(rule_id: str) -> dict:
    physical = {"artifactLocation": {"uri": "sample.js"},
                "region": {"startLine": 5}}
    return {"runs": [{"results": [{
        "ruleId": rule_id,
        "message": {"text": "test flow"},
        "locations": [{"physicalLocation": physical}],
        "codeFlows": [{"threadFlows": [{"locations": [
            {"location": {"physicalLocation": physical}},
        ]}]}],
    }]}]}


class FakeCodeQL:
    def __init__(self, failing_query: str | None = None):
        self.calls: list[list[str]] = []
        self.failing_query = failing_query

    def __call__(self, command: list[str], log: Path, stage: str) -> None:
        self.calls.append(command)
        if stage == "database_create":
            return
        query_path = Path(command[4])
        if query_path.stem == self.failing_query:
            raise RuntimeError("simulated JavaScript query failure")
        spec = next(query for query in QUERIES.values() if query.file_path == query_path)
        destination = Path(next(arg.partition("=")[2] for arg in command
                                if arg.startswith("--output=")))
        destination.write_text(json.dumps(sample_sarif(spec.query_id)), encoding="utf-8")


class JavaScriptBatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.target.mkdir()
        (self.target / "sample.js").write_text("// fixture\n" * 5, encoding="utf-8")

    def test_javascript_all_contains_only_supported_queries(self):
        self.assertEqual(BATCH_QUERIES["javascript-all"], ("command", "nosql"))
        self.assertEqual(JAVASCRIPT_QUERY_KEYS, ("command", "nosql"))
        self.assertEqual({QUERIES[key].language for key in JAVASCRIPT_QUERY_KEYS},
                         {"javascript"})
        parser = build_parser()
        self.assertEqual(parser.parse_args(["scan", str(self.target), "--query",
                                            "javascript-all"]).query, "javascript-all")
        self.assertEqual(parser.parse_args(["scan", str(self.target)]).query, "command")

    def test_fixture_matrix_separates_vulnerable_and_safe_cases(self):
        expected = expected_locations()
        self.assertEqual({key: len(value) for key, value in expected.items()},
                         {QUERIES["command"].query_id: 4, QUERIES["nosql"].query_id: 4})
        fixtures = Path(__file__).resolve().parents[2] / "validation" / "hybrid" / "javascript_fixtures"
        for name in ("command", "nosql"):
            with self.subTest(query=name):
                vulnerable = (fixtures / f"{name}_vulnerable.js").read_text(encoding="utf-8")
                safe = (fixtures / f"{name}_safe.js").read_text(encoding="utf-8")
                self.assertIn("// vulnerable:", vulnerable)
                self.assertNotIn("// safe:", vulnerable)
                self.assertIn("// safe:", safe)
                self.assertNotIn("// vulnerable:", safe)
        empty = compare([{"runs": [{"results": []}]}])
        self.assertTrue(all(len(item["missed"]) == 4 for item in empty.values()))

    def test_one_javascript_database_two_queries_and_individual_sarif(self):
        fake = FakeCodeQL()
        raw_dir = self.root / "raw"
        raw_dir.mkdir()
        adapter = CodeQLBatchAdapter(tuple(QUERIES[key] for key in JAVASCRIPT_QUERY_KEYS),
                                     codeql="/bin/true", cache_dir=self.root / "cache")
        with patch("validation.hybrid.engines.shutil.which", return_value="/bin/true"), patch.object(
            CodeQLBatchAdapter, "_execute", side_effect=fake
        ):
            result = adapter.run(self.target, raw_dir)
        create = [call for call in fake.calls if call[1:3] == ["database", "create"]]
        analyze = [call for call in fake.calls if call[1:3] == ["database", "analyze"]]
        self.assertEqual(len(create), 1)
        self.assertIn("--language=javascript", create[0])
        self.assertEqual(len(analyze), 2)
        self.assertEqual(result.status, "success")
        self.assertEqual(len(result.findings), 2)
        self.assertEqual([item.status for item in result.queries], ["success", "success"])
        self.assertEqual([item.finding_count for item in result.queries], [1, 1])
        self.assertTrue(all((self.root / item.raw_report).is_file()
                            for item in result.queries))

    def test_one_query_failure_preserves_other_and_returns_error(self):
        fake = FakeCodeQL(failing_query="NodeGoatThresholdToWherePath")
        with patch("validation.hybrid.engines.shutil.which", return_value="/bin/true"), patch.object(
            CodeQLBatchAdapter, "_execute", side_effect=fake
        ):
            outcome = HybridApplication().scan(
                self.target, engines="codeql", query="javascript-all",
                codeql="/bin/true", output_dir=self.root / "reports",
            )
        result = outcome.engines[0]
        self.assertEqual(outcome.exit_code, EXIT_ERROR)
        self.assertEqual(result.status, "partial_error")
        self.assertEqual(len(result.findings), 1)
        self.assertEqual([item.status for item in result.queries], ["success", "error"])
        self.assertEqual(result.queries[1].error_stage, "query_analyze")
        self.assertTrue((outcome.report_dir / "raw/codeql-command.sarif").is_file())
        report = json.loads(outcome.report_paths[0].read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["by_query"]["nosql"]["status"], "error")
        self.assertIn("CodeQL Query별 실행 결과",
                      outcome.report_paths[1].read_text(encoding="utf-8"))

    def test_semgrep_codeql_grouping_preserves_originals(self):
        fake = FakeCodeQL()
        sink = Location("sample.js", 5, 5)
        semgrep_finding = HybridFinding(
            finding_id("semgrep_ce", "javascript-command-injection-taint", sink, 0),
            "semgrep_ce", "javascript-command-injection-taint", "Command Injection",
            "CWE-78", "ERROR", "HIGH", "UNREVIEWED", None, sink, (),
            "source unknown", "test", "raw/semgrep.json", 0,
        )
        semgrep_result = EngineResult("semgrep_ce", "success", 0.1,
                                      [semgrep_finding], "raw/semgrep.json")
        with patch("validation.hybrid.engines.shutil.which", return_value="/bin/true"), patch.object(
            CodeQLBatchAdapter, "_execute", side_effect=fake
        ), patch("validation.hybrid.main.SemgrepAdapter.run", return_value=semgrep_result):
            outcome = HybridApplication().scan(
                self.target, engines="both", query="javascript-all",
                codeql="/bin/true", output_dir=self.root / "reports",
            )
        report = json.loads(outcome.report_paths[0].read_text(encoding="utf-8"))
        self.assertEqual(outcome.exit_code, EXIT_FINDINGS)
        self.assertEqual(outcome.total_findings, 3)
        self.assertEqual(outcome.cross_engine_groups, 1)
        self.assertEqual(len(report["findings"]), 3)
        self.assertTrue(all(path.is_file() for path in outcome.report_paths))


if __name__ == "__main__":
    unittest.main()
