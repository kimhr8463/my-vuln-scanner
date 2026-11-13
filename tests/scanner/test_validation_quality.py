import json
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from validation import quality


class TestValidationQuality(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.checkout = self.root / "targets" / "opensource" / "python" / "sample"
        self.checkout.mkdir(parents=True)
        self.target = quality.Target(
            id="sample",
            language="python",
            repository="https://example.org/sample",
            version="commit-snapshot",
            commit_sha="a" * 40,
            commit_date="2026-01-01T00:00:00Z",
            license="MIT",
            license_file="LICENSE",
            checkout="targets/opensource/python/sample",
        )

    def test_manifest_has_pinned_repositories(self):
        targets = quality.load_targets()
        self.assertEqual(set(targets), {"pygoat", "nodegoat"})
        for target in targets.values():
            self.assertRegex(target.commit_sha, r"^[0-9a-f]{40}$")
            self.assertTrue(target.license_file)

    def test_verify_rejects_wrong_commit_and_dirty_checkout(self):
        (self.checkout / "LICENSE").write_text("MIT License\n", encoding="utf-8")
        (self.checkout / "app.py").write_text("print('hello')\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=self.checkout, check=True)
        subprocess.run(["git", "add", "LICENSE", "app.py"], cwd=self.checkout, check=True)
        subprocess.run(
            ["git", "-c", "user.name=Test", "-c", "user.email=test@example.org", "commit", "-qm", "snapshot"],
            cwd=self.checkout, check=True,
        )
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.checkout,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        with patch.object(quality, "PROJECT_ROOT", self.root):
            quality.verify_target(replace(self.target, commit_sha=sha))
            with self.assertRaisesRegex(ValueError, "Commit mismatch"):
                quality.verify_target(self.target)
            (self.checkout / "app.py").write_text("print('changed')\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "local changes"):
                quality.verify_target(replace(self.target, commit_sha=sha))

    def test_review_queue_preserves_existing_judgments(self):
        source = self.checkout / "app.py"
        source.write_text("print('sample')\n", encoding="utf-8")
        report = {"findings": [{
            "rule_id": "python-command-injection-taint",
            "vulnerability": "Command Injection",
            "cwe": "CWE-78",
            "file_path": str(source),
            "start_line": 1,
            "end_line": 1,
        }]}
        with patch.object(quality, "PROJECT_ROOT", self.root), patch.object(quality, "REVIEWS", self.root / "reviews"):
            path = quality.make_review_queue(self.target, "b" * 64, report)
            queue = json.loads(path.read_text(encoding="utf-8"))
            row = queue["findings"][0]
            self.assertEqual(row["file_path"], "app.py")
            self.assertEqual(row["commit_sha"], self.target.commit_sha)
            self.assertIsNone(row["classification"])
            row["classification"] = "TP"
            row["evidence"] = "Local code review"
            path.write_text(json.dumps(queue), encoding="utf-8")
            self.assertEqual(quality.make_review_queue(self.target, "b" * 64, report), path)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["findings"][0]["classification"], "TP")

    def test_precision_and_recall_require_review_scope(self):
        queue = {
            "target_id": "sample",
            "ground_truth_complete": True,
            "findings": [
                {"finding_id": "one", "classification": "TP", "evidence": "source-to-sink"},
                {"finding_id": "two", "classification": "FP", "evidence": "validated input"},
            ],
            "missed_findings": [
                {"finding_id": "fn-one", "classification": "FN", "evidence": "manual source review"},
            ],
        }
        metrics = quality.quality_metrics(queue)
        self.assertEqual((metrics["TP"], metrics["FP"], metrics["FN"]), (1, 1, 1))
        self.assertEqual((metrics["precision"], metrics["recall"]), (0.5, 0.5))

        queue["ground_truth_complete"] = False
        self.assertIsNone(quality.quality_metrics(queue)["recall"])
        queue["findings"][1] = {"finding_id": "two", "classification": None, "evidence": ""}
        self.assertIsNone(quality.quality_metrics(queue)["precision"])

    def test_metrics_rejects_unsupported_labels(self):
        queue = {
            "target_id": "sample",
            "ground_truth_complete": False,
            "findings": [{"finding_id": "one", "classification": "FN", "evidence": "wrong category"}],
            "missed_findings": [],
        }
        with self.assertRaisesRegex(ValueError, "reported Finding"):
            quality.quality_metrics(queue)


if __name__ == "__main__":
    unittest.main()
