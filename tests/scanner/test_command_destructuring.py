"""Command Injection Rule의 좁은 구조 분해 Source와 안전 사례 검증."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.result_parser import ResultParser
from scanner.semgrep_runner import SemgrepRunner
from tests.scanner.test_javascript_rules import ROOT, semgrep_environment


FIXTURES = ROOT / "tests" / "javascript" / "command_destructuring"
RULE_ID = "javascript-command-injection-taint"


class CommandDestructuringRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="scanner-command-destructuring-")
        cls.addClassCleanup(temporary.cleanup)
        environment = semgrep_environment(Path(temporary.name))
        runner = SemgrepRunner(ROOT / "rules" / "javascript")
        with patch.dict("os.environ", environment, clear=True):
            vulnerable = runner.scan(FIXTURES / "vulnerable")
            safe = runner.scan(FIXTURES / "safe")
        if vulnerable["errors"] or safe["errors"]:
            raise AssertionError((vulnerable["errors"], safe["errors"]))
        cls.engine_requested = (vulnerable.get("engine_requested"), safe.get("engine_requested"))
        cls.engine_kinds = {result["extra"].get("engine_kind")
                            for result in vulnerable["results"] + safe["results"]}
        cls.vulnerable = ResultParser(vulnerable["scanner_metadata"]["rules"]).parse(vulnerable)
        cls.safe = ResultParser(safe["scanner_metadata"]["rules"]).parse(safe)

    def test_community_engine(self):
        self.assertEqual(self.engine_requested, ("OSS", "OSS"))
        self.assertEqual(self.engine_kinds, {"OSS"})

    def test_existing_direct_body_and_query_sources(self):
        actual = {(Path(item.file_path).name, item.start_line) for item in self.vulnerable}
        self.assertTrue({("body_direct.js", 4), ("query_direct.js", 4)} <= actual)

    def test_body_and_nested_destructuring_with_aliases(self):
        actual = {(Path(item.file_path).name, item.start_line) for item in self.vulnerable}
        self.assertTrue({("body_destructured.js", 4), ("body_alias.js", 4),
                         ("body_nested.js", 4), ("nested_alias.js", 3),
                         ("intermediate.js", 5)} <= actual)

    def test_arrow_request_handlers(self):
        actual = {(Path(item.file_path).name, item.start_line) for item in self.vulnerable}
        self.assertTrue({("arrow_body.js", 4), ("arrow_nested_alias.js", 5)} <= actual)

    def test_no_unexpected_vulnerable_findings(self):
        self.assertEqual(len(self.vulnerable), 9)
        self.assertTrue(all(item.rule_id == RULE_ID and item.cwe == "CWE-78"
                            for item in self.vulnerable))

    def test_safe_examples_have_no_findings(self):
        self.assertEqual(self.safe, [])


if __name__ == "__main__":
    unittest.main()
