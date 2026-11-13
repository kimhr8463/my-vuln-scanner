import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scanner.main import main, project_version
from scanner.reporter import Reporter


ROOT = Path(__file__).resolve().parents[2]


class TestCli(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.target = self.base / "sample-project"
        self.target.mkdir()
        self.output = self.base / "reports"

    def invoke(self, *arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["scan", str(self.target), "--output", str(self.output), *arguments])
        return code, stdout.getvalue(), stderr.getvalue()

    def fake_scan(self, findings=True):
        results = []
        if findings:
            results.append({
                "check_id": "tmp.python-command-injection-taint",
                "path": str(self.target / "app.py"),
                "start": {"line": 2},
                "end": {"line": 2},
                "extra": {
                    "severity": "ERROR", "message": "Potential command injection",
                    "metadata": {
                        "vulnerability": "Command Injection", "cwe": "CWE-78",
                        "confidence": "HIGH",
                    },
                },
            })
        return {
            "results": results,
            "errors": [],
            "scanner_metadata": {
                "target": str(self.target),
                "rules": ["python-command-injection-taint"],
                "elapsed_seconds": 0.25,
            },
        }

    def test_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "scanner.main", "scan", "--help"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0)
        for option in ("--rules", "--output", "--format", "--timeout"):
            self.assertIn(option, result.stdout)

    def test_version(self):
        result = subprocess.run(
            [sys.executable, "-m", "scanner.main", "--version"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn(project_version(), result.stdout)

    def test_normal_scan_and_both_formats(self):
        with patch("scanner.main.SemgrepRunner.scan", return_value=self.fake_scan()):
            code, stdout, stderr = self.invoke()
        self.assertEqual((code, stderr), (2, ""))
        self.assertIn("전체 Finding 수: 1", stdout)
        self.assertIn("Command Injection: 1", stdout)
        self.assertIn("ERROR: 1", stdout)
        self.assertIn("CWE-78: 1", stdout)
        self.assertTrue((self.output / "sample-project-scan.md").is_file())
        self.assertTrue((self.output / "sample-project-scan.json").is_file())
        payload = json.loads((self.output / "sample-project-scan.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["total_findings"], 1)

    def test_invalid_target(self):
        missing = self.base / "missing"
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["scan", str(missing)])
        self.assertEqual(code, 1)
        self.assertIn("Scan target not found", stderr.getvalue())

    def test_custom_rule_path(self):
        rule_dir = self.base / "custom-rules"
        rule_dir.mkdir()
        (rule_dir / "custom.yml").write_text(
            "rules:\n  - id: custom-rule\n    languages: [python]\n"
            "    message: custom\n    severity: ERROR\n    pattern: os.system(...)\n",
            encoding="utf-8",
        )
        with patch("scanner.main.SemgrepRunner") as runner_class:
            runner_class.return_value.scan.return_value = self.fake_scan()
            code, _, stderr = self.invoke("--rules", str(rule_dir))
        self.assertEqual((code, stderr), (2, ""))
        self.assertEqual(runner_class.call_args.args[0], rule_dir.resolve())
        self.assertEqual(runner_class.return_value.scan.call_args.args[0], self.target.resolve())

    def test_custom_output_path(self):
        custom_output = self.base / "custom" / "nested"
        with patch("scanner.main.SemgrepRunner.scan", return_value=self.fake_scan()):
            code, stdout, _ = self.invoke("--output", str(custom_output))
        self.assertEqual(code, 2)
        self.assertTrue((custom_output / "sample-project-scan.md").is_file())
        self.assertIn(str(custom_output), stdout)

    def test_markdown_only(self):
        with patch("scanner.main.SemgrepRunner.scan", return_value=self.fake_scan()):
            code, _, _ = self.invoke("--format", "markdown")
        self.assertEqual(code, 2)
        self.assertTrue((self.output / "sample-project-scan.md").is_file())
        self.assertFalse((self.output / "sample-project-scan.json").exists())

    def test_json_only(self):
        with patch("scanner.main.SemgrepRunner.scan", return_value=self.fake_scan()):
            code, _, _ = self.invoke("--format", "json")
        self.assertEqual(code, 2)
        payload = json.loads((self.output / "sample-project-scan.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["total_findings"], 1)
        self.assertFalse((self.output / "sample-project-scan.md").exists())

    def test_zero_findings(self):
        with patch("scanner.main.SemgrepRunner.scan", return_value=self.fake_scan(False)):
            code, stdout, _ = self.invoke()
        self.assertEqual(code, 0)
        self.assertIn("전체 Finding 수: 0", stdout)
        self.assertIn("취약점 유형별: 없음", stdout)
        self.assertIn("탐지된 Finding이 없습니다.", (self.output / "sample-project-scan.md").read_text(encoding="utf-8"))
        self.assertEqual(json.loads((self.output / "sample-project-scan.json").read_text(encoding="utf-8"))["findings"], [])

    def test_no_rules(self):
        empty_rules = self.base / "empty-rules"
        empty_rules.mkdir()
        code, _, stderr = self.invoke("--rules", str(empty_rules))
        self.assertEqual(code, 1)
        self.assertIn("No YAML rules found", stderr)

    def test_semgrep_failure(self):
        with patch("scanner.main.SemgrepRunner.scan", side_effect=RuntimeError("Semgrep execution failed")):
            code, _, stderr = self.invoke()
        self.assertEqual(code, 1)
        self.assertIn("Semgrep execution failed", stderr)
        self.assertFalse(self.output.exists())

    def test_semgrep_reported_error(self):
        report = self.fake_scan()
        report["errors"] = [{"message": "Invalid Rule syntax"}]
        with patch("scanner.main.SemgrepRunner.scan", return_value=report):
            code, _, stderr = self.invoke()
        self.assertEqual(code, 1)
        self.assertIn("Invalid Rule syntax", stderr)
        self.assertFalse(self.output.exists())

    def test_report_save_failure(self):
        with patch("scanner.main.SemgrepRunner.scan", return_value=self.fake_scan()):
            with patch.object(Reporter, "save", side_effect=OSError("Report write failed")):
                code, stdout, stderr = self.invoke()
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("Report write failed", stderr)

    def test_timeout(self):
        with patch("scanner.main.SemgrepRunner") as runner_class:
            runner_class.return_value.scan.side_effect = TimeoutError("Semgrep scan timed out after 1s")
            code, _, stderr = self.invoke("--timeout", "1")
        self.assertEqual(runner_class.call_args.kwargs["timeout"], 1)
        self.assertEqual(code, 1)
        self.assertIn("timed out after 1s", stderr)
        self.assertFalse(self.output.exists())

    def test_invalid_timeout(self):
        result = subprocess.run(
            [sys.executable, "-m", "scanner.main", "scan", str(self.target), "--timeout", "0"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("positive integer", result.stderr)


class TestRealCliIntegration(unittest.TestCase):
    def test_python_project_scan(self):
        target = ROOT / "targets" / "my-project"
        temporary = tempfile.TemporaryDirectory(prefix="scanner-cli-test-")
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name)
        environment = dict(os.environ)
        environment.update({
            "XDG_CONFIG_HOME": "/tmp",
            "XDG_CACHE_HOME": "/tmp",
            "SEMGREP_SETTINGS_FILE": "/tmp/my-vuln-scanner-semgrep-settings.yml",
            "SEMGREP_LOG_FILE": "/tmp/my-vuln-scanner-semgrep.log",
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
            "PATH": f"{ROOT / '.venv' / 'bin'}:{environment.get('PATH', '')}",
        })
        result = subprocess.run(
            [sys.executable, "-m", "scanner.main", "scan", str(target), "--output", str(output)],
            cwd=ROOT, env=environment, capture_output=True, text=True,
            timeout=60, check=False,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        payload = json.loads((output / "my-project-scan.json").read_text(encoding="utf-8"))
        self.assertGreater(payload["total_findings"], 0)
        self.assertEqual(payload["total_findings"], sum(payload["by_cwe"].values()))
        self.assertIn("Rule ID:", (output / "my-project-scan.md").read_text(encoding="utf-8"))

    def test_clean_python_project_scan(self):
        temporary = tempfile.TemporaryDirectory(prefix="scanner-clean-test-")
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        target = base / "clean-project"
        target.mkdir()
        (target / "app.py").write_text("print('safe')\n", encoding="utf-8")
        output = base / "reports"
        environment = dict(os.environ)
        environment.update({
            "XDG_CONFIG_HOME": "/tmp",
            "XDG_CACHE_HOME": "/tmp",
            "SEMGREP_SETTINGS_FILE": "/tmp/my-vuln-scanner-semgrep-settings.yml",
            "SEMGREP_LOG_FILE": "/tmp/my-vuln-scanner-semgrep.log",
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
            "PATH": f"{ROOT / '.venv' / 'bin'}:{environment.get('PATH', '')}",
        })
        result = subprocess.run(
            [sys.executable, "-m", "scanner.main", "scan", str(target), "--output", str(output)],
            cwd=ROOT, env=environment, capture_output=True, text=True,
            timeout=60, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads((output / "clean-project-scan.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["total_findings"], 0)
        self.assertIn("탐지된 Finding이 없습니다.", (output / "clean-project-scan.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
