"""Python CodeQL query 등록 및 공통 결과 변환 회귀 테스트."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from validation.hybrid.engines import QUERIES, CodeQLAdapter, parse_sarif
from validation.hybrid.check_python_queries import compare, expected_locations
from validation.hybrid.main import HybridApplication
from validation.hybrid.model import EngineResult, FindingGrouper, HybridFinding, Location, finding_id


class PythonCodeQLIntegrationTests(unittest.TestCase):
    def test_fixture_matrix_has_four_vulnerable_cases_per_query(self):
        expected = expected_locations()
        self.assertEqual({key: len(value) for key, value in expected.items()},
                         {query.query_id: 4 for query in (
                             QUERIES["python-command"], QUERIES["python-sql"],
                             QUERIES["python-path"], QUERIES["python-ssrf"],
                         )})
        fixtures = Path(__file__).resolve().parents[2] / "validation" / "hybrid" / "python_fixtures"
        for name in ("command", "sql", "path", "ssrf"):
            with self.subTest(fixture=name):
                vulnerable = (fixtures / f"{name}.py").read_text(encoding="utf-8")
                safe = (fixtures / f"{name}_safe.py").read_text(encoding="utf-8")
                self.assertIn("# vulnerable:", vulnerable)
                self.assertNotIn("# safe:", vulnerable)
                self.assertIn("# safe:", safe)
                self.assertNotIn("# vulnerable:", safe)

    def test_sarif_comparison_flags_missing_and_unexpected_locations(self):
        summary = compare({"runs": [{"results": []}]})
        self.assertTrue(all(len(case["missed"]) == 4 for case in summary.values()))
        self.assertTrue(all(not case["unexpected"] for case in summary.values()))

    def test_four_python_queries_registered_independently(self):
        expected = {
            "python-command": "CWE-78",
            "python-sql": "CWE-89",
            "python-path": "CWE-22",
            "python-ssrf": "CWE-918",
        }
        for key, cwe in expected.items():
            with self.subTest(query=key):
                spec = QUERIES[key]
                self.assertEqual(spec.language, "python")
                self.assertEqual(spec.cwe, cwe)
                self.assertTrue(spec.file_path.is_file())
                self.assertIn(spec.query_id, spec.file_path.read_text(encoding="utf-8"))
        self.assertEqual(QUERIES["command"].language, "javascript")
        self.assertEqual(QUERIES["nosql"].language, "javascript")

    def test_python_sarif_maps_source_sink_and_raw_reference(self):
        spec = QUERIES["python-command"]

        def physical(path, line):
            return {"artifactLocation": {"uri": path}, "region": {"startLine": line}}

        payload = {"runs": [{"results": [{
            "ruleId": spec.query_id,
            "message": {"text": "Command flow"},
            "locations": [{"physicalLocation": physical("command_service.py", 5)}],
            "codeFlows": [{"threadFlows": [{"locations": [
                {"location": {"physicalLocation": physical("command.py", 28)}},
                {"location": {"physicalLocation": physical("command_service.py", 5)}},
            ]}]}],
        }]}]}
        finding = parse_sarif(payload, Path("/tmp/python-project"), spec,
                              "raw/codeql.sarif")[0]
        self.assertEqual(finding.cwe, "CWE-78")
        self.assertEqual(finding.source.path, "command.py")
        self.assertEqual(finding.sink.path, "command_service.py")
        self.assertEqual(finding.raw_report, "raw/codeql.sarif")
        self.assertEqual(finding.raw_result_index, 0)

    def test_python_sarif_without_codeflow_leaves_source_unknown(self):
        spec = QUERIES["python-sql"]
        payload = {"runs": [{"results": [{
            "ruleId": spec.query_id,
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "sql.py"},
                "region": {"startLine": 10},
            }}],
        }]}]}
        finding = parse_sarif(payload, Path("/tmp/python-project"), spec,
                              "raw/codeql.sarif")[0]
        self.assertIsNone(finding.source)
        self.assertEqual(finding.flow_evidence, ())

    def test_python_and_semgrep_findings_group_without_loss(self):
        sink = Location("command.py", 10, 10)
        findings = [HybridFinding(
            finding_id(engine, rule, sink, i), engine, rule, "Command Injection",
            "CWE-78", "ERROR", "HIGH", "UNREVIEWED", None, sink, (), "note",
            "message", f"raw/{engine}.json", i,
        ) for i, (engine, rule) in enumerate([
            ("semgrep_ce", "python-command-injection-taint"),
            ("codeql", QUERIES["python-command"].query_id),
        ])]
        groups = FindingGrouper().group(findings)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0].member_ids), 2)

    def test_missing_python_query_does_not_prevent_semgrep(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            target.mkdir()
            # A missing CodeQL query is an engine-scoped configuration error.
            missing = QUERIES["python-command"].__class__(
                "missing", Path(temporary) / "missing.ql", "missing/id",
                "Command Injection", "CWE-78", language="python",
            )
            with patch("validation.hybrid.engines.shutil.which", return_value="/bin/true"):
                result = CodeQLAdapter(missing).run(target, target)
            self.assertEqual(result.status, "error")
            self.assertEqual(result.error_stage, "configuration")

    def test_semgrep_only_works_without_python_query_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            target.mkdir()
            with patch("validation.hybrid.main.SemgrepAdapter.run", return_value=EngineResult(
                "semgrep_ce", "success", 0.1, [], "raw/semgrep.json"
            )), patch("validation.hybrid.main.CodeQLAdapter.run", side_effect=AssertionError(
                "CodeQL must not run"
            )):
                outcome = HybridApplication().scan(
                    target, engines="semgrep", query="python-command",
                    output_dir=Path(temporary) / "reports",
                )
            self.assertEqual(outcome.total_findings, 0)
            self.assertTrue(all(path.is_file() for path in outcome.report_paths))


if __name__ == "__main__":
    unittest.main()
