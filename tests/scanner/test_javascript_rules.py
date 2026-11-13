"""실제 Semgrep으로 JavaScript Rule과 CLI의 전체 흐름을 검증한다."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.result_parser import ResultParser
from scanner.rule_loader import RuleLoader
from scanner.semgrep_runner import SemgrepRunner


ROOT = Path(__file__).resolve().parents[2]
JAVASCRIPT_RULES = {
    "javascript-command-injection-taint": ("Command Injection", "CWE-78"),
    "javascript-sql-injection-taint": ("SQL Injection", "CWE-89"),
    "javascript-dom-xss-taint": ("Cross-Site Scripting (XSS)", "CWE-79"),
}


def semgrep_environment(temporary: Path) -> dict[str, str]:
    environment = dict(os.environ)
    environment.update({
        "XDG_CONFIG_HOME": str(temporary),
        "XDG_CACHE_HOME": str(temporary),
        "SEMGREP_SETTINGS_FILE": str(temporary / "settings.yml"),
        "SEMGREP_LOG_FILE": str(temporary / "semgrep.log"),
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "PATH": f"{ROOT / '.venv' / 'bin'}:{environment.get('PATH', '')}",
    })
    return environment


class TestJavascriptRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="scanner-js-rules-")
        cls.addClassCleanup(temporary.cleanup)
        environment = semgrep_environment(Path(temporary.name))
        runner = SemgrepRunner(ROOT / "rules" / "javascript")
        with patch.dict(os.environ, environment, clear=True):
            vulnerable = runner.scan(ROOT / "tests" / "javascript" / "vulnerable")
            safe = runner.scan(ROOT / "tests" / "javascript" / "safe")
        cls.vulnerable_errors = vulnerable["errors"]
        cls.safe_errors = safe["errors"]
        cls.known_ids = vulnerable["scanner_metadata"]["rules"]
        cls.vulnerable_findings = ResultParser(cls.known_ids).parse(vulnerable)
        cls.safe_findings = ResultParser(cls.known_ids).parse(safe)

    def test_loader_discovers_javascript_rules(self):
        all_rules = RuleLoader(ROOT / "rules").load_rules()
        rule_ids = {rule_id for info in all_rules for rule_id in info.rule_ids}
        self.assertEqual(len(rule_ids), 9)
        self.assertTrue(JAVASCRIPT_RULES.keys() <= rule_ids)
        self.assertIn("javascript-mongodb-nosql-injection-taint", rule_ids)
        self.assertIn("javascript-mongodb-dynamic-where-candidate", rule_ids)
        for info in all_rules:
            if any(rule_id in JAVASCRIPT_RULES for rule_id in info.rule_ids):
                self.assertIn("javascript", info.languages)

    def assert_rule_findings(self, rule_id: str, expected_lines: set[int], filename: str):
        self.assertEqual(self.vulnerable_errors, [])
        self.assertEqual(self.safe_errors, [])
        findings = [item for item in self.vulnerable_findings if item.rule_id == rule_id]
        self.assertEqual({item.start_line for item in findings}, expected_lines)
        self.assertEqual(len(findings), len(expected_lines))
        self.assertTrue(all(Path(item.file_path).name == filename for item in findings))
        self.assertTrue(all(item.vulnerability == JAVASCRIPT_RULES[rule_id][0] for item in findings))
        self.assertTrue(all(item.cwe == JAVASCRIPT_RULES[rule_id][1] for item in findings))
        self.assertFalse(any(item.rule_id == rule_id for item in self.safe_findings))

    def test_command_injection_taint(self):
        self.assert_rule_findings(
            "javascript-command-injection-taint", {5, 10, 14}, "command_injection.js"
        )

    def test_sql_injection_taint(self):
        self.assert_rule_findings(
            "javascript-sql-injection-taint", {3, 8}, "sql_injection.js"
        )

    def test_dom_xss_taint(self):
        self.assert_rule_findings("javascript-dom-xss-taint", {3, 8, 13}, "xss.js")

    def test_safe_examples_have_no_findings(self):
        self.assertEqual(self.safe_findings, [])
        self.assertEqual(len(self.vulnerable_findings), 8)


class TestJavascriptCliIntegration(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="scanner-js-cli-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.environment = semgrep_environment(self.base)

    def run_cli(self, target: str) -> tuple[subprocess.CompletedProcess[str], dict, str]:
        output = self.base / f"reports-{target}"
        process = subprocess.run(
            [
                sys.executable, "-m", "scanner.main", "scan",
                str(ROOT / "tests" / "javascript" / target),
                "--output", str(output),
            ],
            cwd=ROOT,
            env=self.environment,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        payload = json.loads((output / f"{target}-scan.json").read_text(encoding="utf-8"))
        markdown = (output / f"{target}-scan.md").read_text(encoding="utf-8")
        return process, payload, markdown

    def test_default_rules_detect_javascript_and_write_reports(self):
        process, payload, markdown = self.run_cli("vulnerable")
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertEqual(payload["total_findings"], 8)
        self.assertEqual(payload["by_vulnerability"], {
            "Command Injection": 3,
            "Cross-Site Scripting (XSS)": 3,
            "SQL Injection": 2,
        })
        self.assertEqual(payload["by_cwe"], {"CWE-78": 3, "CWE-79": 3, "CWE-89": 2})
        self.assertEqual({item["rule_id"] for item in payload["findings"]}, set(JAVASCRIPT_RULES))
        self.assertIn("javascript-dom-xss-taint", markdown)
        self.assertIn("CWE-79", markdown)

    def test_safe_javascript_project_writes_empty_reports(self):
        process, payload, markdown = self.run_cli("safe")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(payload["total_findings"], 0)
        self.assertEqual(payload["findings"], [])
        self.assertIn("탐지된 Finding이 없습니다.", markdown)
