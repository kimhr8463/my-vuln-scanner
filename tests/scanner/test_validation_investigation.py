import copy
import json
import tempfile
import unittest
from pathlib import Path

from validation import investigation
from validation.quality import load_targets, review_path


def sample():
    review = {
        "target_id": "sample", "repository": "https://example.org/sample", "commit_sha": "a" * 40,
        "rule_set_sha256": "b" * 64, "ground_truth_complete": False,
        "findings": [
            {"finding_id": "detected", "rule_id": "sample-rule", "classification": "TP", "evidence": "Static flow reviewed"}
        ], "missed_findings": [],
    }
    audit = {
        "schema_version": 1, "target_id": "sample", "repository": review["repository"],
        "commit_sha": review["commit_sha"], "rule_set_sha256": review["rule_set_sha256"],
        "coverage": {
            "Command Injection": {"complete": True, "reason": "Bounded exhaustive audit"},
            "NoSQL Injection": {"complete": False, "reason": "Outside rule scope"},
        },
        "candidates": [{
            "finding_id": "detected", "review_finding_id": "detected", "rule_id": "sample-rule",
            "repository": review["repository"], "commit_sha": review["commit_sha"],
            "file_path": "app.py", "line": 3, "vulnerability": "Command Injection", "cwe": "CWE-78",
            "source": "request.form", "sink": "Popen(shell=True)", "data_flow": "Input reaches shell",
            "scanner_detected": True, "classification": "TP", "evidence": "Unvalidated input",
            "code_evidence": ["app.py:1-3"],
        }],
    }
    return audit, review


class InvestigationTests(unittest.TestCase):
    def test_type_recall_only_for_completed_scope(self):
        audit, review = sample()
        result = investigation.evaluate(audit, review)
        self.assertEqual(result["by_vulnerability"]["Command Injection"]["recall"], 1.0)
        self.assertIsNone(result["by_vulnerability"]["NoSQL Injection"]["recall"])
        self.assertIsNone(result["overall"]["recall"])

    def test_confirmed_fn_matches_review_and_changes_recall(self):
        audit, review = sample()
        audit["coverage"].pop("NoSQL Injection")
        missed = copy.deepcopy(audit["candidates"][0])
        missed.update(finding_id="missed", review_finding_id=None, scanner_detected=False, classification="FN")
        audit["candidates"].append(missed)
        review["missed_findings"].append({"finding_id": "missed", "classification": "FN", "evidence": "Manual flow"})
        result = investigation.evaluate(audit, review)
        self.assertEqual(result["by_vulnerability"]["Command Injection"]["recall"], 0.5)
        self.assertEqual(result["overall"]["recall"], 0.5)

    def test_unconfirmed_suppresses_recall(self):
        audit, review = sample()
        audit["coverage"].pop("NoSQL Injection")
        candidate = copy.deepcopy(audit["candidates"][0])
        candidate.update(finding_id="maybe", review_finding_id=None, scanner_detected=False, classification="UNCONFIRMED")
        audit["candidates"].append(candidate)
        self.assertIsNone(investigation.evaluate(audit, review)["overall"]["recall"])

    def test_rejects_duplicate_and_mismatched_labels(self):
        audit, review = sample()
        audit["candidates"].append(copy.deepcopy(audit["candidates"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            investigation.evaluate(audit, review)
        audit["candidates"].pop()
        audit["candidates"][0]["scanner_detected"] = False
        with self.assertRaisesRegex(ValueError, "mismatch"):
            investigation.evaluate(audit, review)

    def test_rejects_review_or_rule_set_mismatch(self):
        audit, review = sample()
        audit["rule_set_sha256"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "rule_set_sha256"):
            investigation.evaluate(audit, review)

    def test_pinned_investigations_are_consistent_with_existing_reviews(self):
        for target in load_targets().values():
            with self.subTest(target=target.id):
                audit = json.loads((investigation.INVESTIGATIONS / f"{target.id}.json").read_text(encoding="utf-8"))
                review = json.loads(review_path(target, audit["rule_set_sha256"]).read_text(encoding="utf-8"))
                result = investigation.evaluate(audit, review)
                investigation.check_code_evidence(audit, target.path)
                self.assertEqual(result["target_id"], target.id)
                self.assertIsNone(result["overall"]["recall"])

    def test_code_evidence_rejects_missing_or_outside_lines(self):
        audit, _ = sample()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("one\ntwo\nthree\n", encoding="utf-8")
            investigation.check_code_evidence(audit, root)
            audit["candidates"][0]["code_evidence"] = ["app.py:1-4"]
            with self.assertRaisesRegex(ValueError, "outside source file"):
                investigation.check_code_evidence(audit, root)
            audit["candidates"][0]["code_evidence"] = ["../outside.py:1"]
            with self.assertRaisesRegex(ValueError, "outside checkout"):
                investigation.check_code_evidence(audit, root)


if __name__ == "__main__":
    unittest.main()
