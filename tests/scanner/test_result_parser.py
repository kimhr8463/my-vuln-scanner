import unittest

from scanner.result_parser import ResultParser


class TestResultParser(unittest.TestCase):

    def setUp(self):
        self.parser = ResultParser([
            "python-command-injection-taint",
            "python-sql-injection-taint",
        ])

        self.report = {
            "results": [
                {
                    "check_id": (
                        "tmp.tmp123.python-command-injection-taint"
                    ),
                    "path": "app.py",
                    "start": {"line": 10},
                    "end": {"line": 10},
                    "extra": {
                        "message": "Potential command injection.",
                        "severity": "ERROR",
                        "metadata": {
                            "vulnerability": "Command Injection",
                            "cwe": "CWE-78",
                            "confidence": "HIGH",
                        },
                    },
                },
                {
                    "check_id": (
                        "tmp.tmp123.python-sql-injection-taint"
                    ),
                    "path": "database.py",
                    "start": {"line": 25},
                    "end": {"line": 25},
                    "extra": {
                        "message": "Potential SQL injection.",
                        "severity": "WARNING",
                        "metadata": {
                            "vulnerability": "SQL Injection",
                            "cwe": "CWE-89",
                            "confidence": "HIGH",
                        },
                    },
                },
            ]
        }

    def test_parse_findings(self):
        findings = self.parser.parse(self.report)

        self.assertEqual(len(findings), 2)

    def test_extract_rule_id(self):
        findings = self.parser.parse(self.report)

        self.assertEqual(
            findings[0].rule_id,
            "python-command-injection-taint",
        )

    def test_extract_metadata(self):
        findings = self.parser.parse(self.report)

        finding = findings[0]

        self.assertEqual(
            finding.vulnerability, "Command Injection"
        )
        self.assertEqual(finding.cwe, "CWE-78")
        self.assertEqual(finding.severity, "ERROR")
        self.assertEqual(finding.confidence, "HIGH")

    def test_summarize(self):
        findings = self.parser.parse(self.report)
        summary = self.parser.summarize(findings)

        self.assertEqual(summary["total_findings"], 2)
        self.assertEqual(
            summary["by_vulnerability"]["Command Injection"], 1
        )
        self.assertEqual(
            summary["by_vulnerability"]["SQL Injection"], 1
        )

    def test_remove_duplicates(self):
        report = {
            "results": [
                self.report["results"][0],
                self.report["results"][0],
            ]
        }

        findings = self.parser.parse(report)

        self.assertEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()
