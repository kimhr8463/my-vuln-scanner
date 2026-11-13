"""Python CodeQL 4종의 단일 DB·부분 실패·보고서 통합 테스트."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.main import EXIT_ERROR, EXIT_FINDINGS
from validation.hybrid.engines import (
    PYTHON_QUERY_KEYS, QUERIES, CodeQLBatchAdapter,
)
from validation.hybrid.main import HybridApplication, build_parser
from validation.hybrid.model import EngineResult, HybridFinding, Location, finding_id


def sarif_for(query_id: str, line: int) -> dict:
    physical = lambda number: {
        "artifactLocation": {"uri": "sample.py"},
        "region": {"startLine": number},
    }
    return {"runs": [{"results": [{
        "ruleId": query_id,
        "message": {"text": "test flow"},
        "locations": [{"physicalLocation": physical(line)}],
        "codeFlows": [{"threadFlows": [{"locations": [
            {"location": {"physicalLocation": physical(1)}},
            {"location": {"physicalLocation": physical(line)}},
        ]}]}],
    }]}]}


class FakeCodeQL:
    def __init__(self, failing_query: str | None = None, empty: bool = False):
        self.calls: list[list[str]] = []
        self.failing_query = failing_query
        self.empty = empty

    def __call__(self, command: list[str], log: Path, stage: str) -> None:
        self.calls.append(command)
        if stage == "database_create":
            return
        query_path = Path(command[4])
        if query_path.stem == self.failing_query:
            raise RuntimeError("simulated query failure")
        spec = next(query for query in QUERIES.values() if query.file_path == query_path)
        destination = Path(next(arg.partition("=")[2] for arg in command
                                if arg.startswith("--output=")))
        payload = {"runs": [{"results": []}]} if self.empty else sarif_for(spec.query_id, 10)
        destination.write_text(json.dumps(payload), encoding="utf-8")


class PythonBatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.target.mkdir()
        (self.target / "sample.py").write_text("# fixture\n" * 10, encoding="utf-8")

    def batch(self) -> CodeQLBatchAdapter:
        return CodeQLBatchAdapter(tuple(QUERIES[key] for key in PYTHON_QUERY_KEYS),
                                  codeql="/bin/true", cache_dir=self.root / "cache")

    def test_one_database_four_queries_and_individual_sarif(self):
        fake = FakeCodeQL()
        raw_dir = self.root / "raw"
        raw_dir.mkdir()
        with patch("validation.hybrid.engines.shutil.which", return_value="/bin/true"), patch.object(
            CodeQLBatchAdapter, "_execute", side_effect=fake
        ):
            result = self.batch().run(self.target, raw_dir)
        self.assertEqual([call[1:3] for call in fake.calls].count(["database", "create"]), 1)
        self.assertEqual([call[1:3] for call in fake.calls].count(["database", "analyze"]), 4)
        self.assertEqual(result.status, "success")
        self.assertEqual(len(result.findings), 4)
        self.assertEqual(len(result.queries), 4)
        self.assertTrue(all(item.status == "success" and item.finding_count == 1
                            for item in result.queries))
        self.assertEqual({item.cwe for item in result.findings},
                         {"CWE-78", "CWE-89", "CWE-22", "CWE-918"})
        self.assertTrue(all((self.root / item.raw_report).is_file()
                            for item in result.queries))
        self.assertTrue(all(item.source is not None for item in result.findings))

    def test_one_query_failure_keeps_other_results_and_exit_code_one(self):
        fake = FakeCodeQL(failing_query="SqlInjectionPath")
        with patch("validation.hybrid.engines.shutil.which", return_value="/bin/true"), patch.object(
            CodeQLBatchAdapter, "_execute", side_effect=fake
        ):
            outcome = HybridApplication().scan(
                self.target, engines="codeql", query="python-all",
                codeql="/bin/true", output_dir=self.root / "reports",
            )
        result = outcome.engines[0]
        self.assertEqual(outcome.exit_code, EXIT_ERROR)
        self.assertEqual(result.status, "partial_error")
        self.assertEqual(len(result.findings), 3)
        self.assertEqual([item.status for item in result.queries],
                         ["success", "error", "success", "success"])
        self.assertEqual(result.queries[1].error_stage, "query_analyze")
        self.assertEqual([call[1:3] for call in fake.calls].count(["database", "create"]), 1)
        self.assertEqual([call[1:3] for call in fake.calls].count(["database", "analyze"]), 4)
        report = json.loads(outcome.report_paths[0].read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["total_findings"], 3)
        self.assertEqual(report["summary"]["by_query"]["python-sql"]["status"], "error")
        self.assertIn("python-sql", outcome.report_paths[1].read_text(encoding="utf-8"))
        self.assertTrue((outcome.report_dir / "raw/codeql-python-ssrf.sarif").is_file())

    def test_database_failure_skips_queries_without_losing_error(self):
        calls = []

        def fail_create(command, log, stage):
            calls.append(stage)
            raise RuntimeError("database creation failed")

        raw_dir = self.root / "raw"
        raw_dir.mkdir()
        with patch("validation.hybrid.engines.shutil.which", return_value="/bin/true"), patch.object(
            CodeQLBatchAdapter, "_execute", side_effect=fail_create
        ):
            result = self.batch().run(self.target, raw_dir)
        self.assertEqual(calls, ["database_create"])
        self.assertEqual(result.status, "error")
        self.assertEqual(result.error_stage, "database_create")
        self.assertEqual([item.status for item in result.queries], ["skipped"] * 4)
        self.assertEqual(result.findings, [])

    def test_semgrep_findings_grouped_and_reports_saved(self):
        fake = FakeCodeQL()
        sink = Location("sample.py", 10, 10)
        semgrep_finding = HybridFinding(
            finding_id("semgrep_ce", "python-command-injection-taint", sink, 0),
            "semgrep_ce", "python-command-injection-taint", "Command Injection",
            "CWE-78", "ERROR", "HIGH", "UNREVIEWED", None, sink, (),
            "source unknown", "test", "raw/semgrep.json", 0,
        )
        semgrep_result = EngineResult("semgrep_ce", "success", 0.1,
                                      [semgrep_finding], "raw/semgrep.json")
        with patch("validation.hybrid.engines.shutil.which", return_value="/bin/true"), patch.object(
            CodeQLBatchAdapter, "_execute", side_effect=fake
        ), patch("validation.hybrid.main.SemgrepAdapter.run", return_value=semgrep_result):
            outcome = HybridApplication().scan(
                self.target, engines="both", query="python-all",
                codeql="/bin/true", output_dir=self.root / "reports",
            )
        report = json.loads(outcome.report_paths[0].read_text(encoding="utf-8"))
        markdown = outcome.report_paths[1].read_text(encoding="utf-8")
        self.assertEqual(outcome.exit_code, EXIT_FINDINGS)
        self.assertEqual(report["summary"]["total_findings"], 5)
        self.assertEqual(report["summary"]["cross_engine_groups"], 1)
        self.assertEqual(len(report["findings"]), 5)
        self.assertEqual(len(report["summary"]["by_query"]), 4)
        self.assertIn("CodeQL Query별 실행 결과", markdown)
        self.assertIn("CodeQL DB 생성 시간", markdown)

    def test_zero_findings_returns_success_with_four_sarif_reports(self):
        fake = FakeCodeQL(empty=True)
        with patch("validation.hybrid.engines.shutil.which", return_value="/bin/true"), patch.object(
            CodeQLBatchAdapter, "_execute", side_effect=fake
        ):
            outcome = HybridApplication().scan(
                self.target, engines="codeql", query="python-all",
                codeql="/bin/true", output_dir=self.root / "reports",
            )
        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(outcome.total_findings, 0)
        self.assertEqual(len(outcome.engines[0].queries), 4)
        self.assertTrue(all(item.status == "success" and item.finding_count == 0
                            for item in outcome.engines[0].queries))
        self.assertTrue(all((outcome.report_dir / item.raw_report).is_file()
                            for item in outcome.engines[0].queries))

    def test_cli_accepts_python_all_without_changing_single_query_default(self):
        parser = build_parser()
        batch = parser.parse_args(["scan", str(self.target), "--query", "python-all"])
        default = parser.parse_args(["scan", str(self.target)])
        self.assertEqual(batch.query, "python-all")
        self.assertEqual(default.query, "command")


if __name__ == "__main__":
    unittest.main()
