import json
import tempfile
import unittest
from pathlib import Path

from scanner.reporter import Reporter
from scanner.result_parser import Finding, ResultParser
from scanner.semgrep_runner import SemgrepRunner


class TestReporter(unittest.TestCase):
    def setUp(self):
        self.reporter = Reporter("예제 프로젝트", "targets/example", 1.25)
        self.findings = [
            Finding("cmd-rule", "Command Injection", "CWE-78", "ERROR", "HIGH", "a.py", 10, 12, "명령 실행 위험"),
            Finding("cmd-rule", "Command Injection", "CWE-78", "ERROR", "MEDIUM", "b.py", 20, 20, "두 번째 위험"),
            Finding("sql-rule", "SQL Injection", "CWE-89", "WARNING", "HIGH", "db.py", 5, 6, "SQL 위험"),
        ]

    def test_normal_finding_report(self):
        markdown = self.reporter.generate(self.findings)
        self.assertIn("예제 프로젝트", markdown)
        self.assertIn("targets/example", markdown)
        self.assertIn("1.250초", markdown)
        self.assertIn("전체 Finding 수: 3", markdown)
        self.assertIn("Rule ID: cmd-rule", markdown)
        self.assertIn("Confidence: MEDIUM", markdown)
        self.assertIn("시작 줄 번호: 10", markdown)
        self.assertIn("종료 줄 번호: 12", markdown)
        self.assertIn("명령 실행 위험", markdown)

    def test_empty_finding_report(self):
        markdown = self.reporter.generate([])
        payload = json.loads(self.reporter.generate([], "json"))
        self.assertIn("탐지된 Finding이 없습니다.", markdown)
        self.assertEqual(payload["total_findings"], 0)
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["by_vulnerability"], {})
        self.assertEqual(payload["by_severity"], {})
        self.assertEqual(payload["by_cwe"], {})

    def test_save_markdown_creates_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            destination = Path(temp_dir) / "nested" / "scan.md"
            self.assertEqual(self.reporter.save(self.findings, destination), destination)
            self.assertEqual(destination.read_text(encoding="utf-8"), self.reporter.generate(self.findings))

    def test_save_json_creates_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            destination = Path(temp_dir) / "nested" / "scan.json"
            self.reporter.save(self.findings, destination, "json")
            payload = json.loads(destination.read_text(encoding="utf-8"))
            self.assertEqual(payload["project_name"], "예제 프로젝트")
            self.assertEqual(payload["findings"][0]["rule_id"], "cmd-rule")

    def test_vulnerability_counts(self):
        self.assertEqual(self.reporter.build_report(self.findings)["by_vulnerability"], {
            "Command Injection": 2, "SQL Injection": 1,
        })

    def test_severity_counts(self):
        self.assertEqual(self.reporter.build_report(self.findings)["by_severity"], {
            "ERROR": 2, "WARNING": 1,
        })

    def test_cwe_counts(self):
        self.assertEqual(self.reporter.build_report(self.findings)["by_cwe"], {
            "CWE-78": 2, "CWE-89": 1,
        })

    def test_invalid_data(self):
        with self.assertRaises(ValueError):
            Reporter("", "targets/example", 1.0)
        with self.assertRaises(ValueError):
            Reporter("project", "targets/example", float("nan"))
        with self.assertRaises(TypeError):
            self.reporter.generate([{"rule_id": "bad"}])
        with self.assertRaises(ValueError):
            self.reporter.generate([Finding("id", "SQL", "CWE-89", "ERROR", "HIGH", "a.py", 0, 1, "bad")])
        with self.assertRaises(ValueError):
            self.reporter.generate(self.findings, "html")

    def test_markdown_escapes_dynamic_values(self):
        finding = Finding("rule|id", "SQL", "CWE-89", "ERROR", "HIGH", "a.py", 1, 1, "line one\nline two")
        markdown = self.reporter.generate([finding])
        self.assertIn("rule\\|id", markdown)
        self.assertIn("line one<br>line two", markdown)


class TestReporterIntegration(unittest.TestCase):
    def test_real_semgrep_result_to_saved_reports(self):
        root = Path(__file__).resolve().parents[2]
        runner = SemgrepRunner(root / "rules")
        raw = runner.scan(root / "rules" / "python")
        self.assertEqual(raw["errors"], [])
        parser = ResultParser(raw["scanner_metadata"]["rules"])
        findings = parser.parse(raw)
        self.assertGreater(len(findings), 0)

        reporter = Reporter(
            "rule-examples",
            raw["scanner_metadata"]["target"],
            raw["scanner_metadata"]["elapsed_seconds"],
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            markdown_path = reporter.save(findings, Path(temp_dir) / "reports" / "scan.md")
            json_path = reporter.save(findings, Path(temp_dir) / "reports" / "scan.json", "json")
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["total_findings"], len(findings))
            self.assertEqual(payload["total_findings"], sum(payload["by_cwe"].values()))
            self.assertIn(findings[0].rule_id, markdown_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
