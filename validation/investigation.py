"""독립 소스 조사 기록을 검증하고 유형별 품질 지표를 계산한다."""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from validation.quality import load_targets, quality_metrics, review_path, verify_target


INVESTIGATIONS = Path(__file__).with_name("investigations")
LABELS = ("TP", "FP", "FN", "OUT_OF_SCOPE", "UNCONFIRMED")
EVIDENCE_REF = re.compile(r"(?P<path>[^:]+):(?P<start>[1-9][0-9]*)(?:-(?P<end>[1-9][0-9]*))?\Z")


def check_code_evidence(investigation: dict[str, Any], checkout: Path) -> None:
    """기록된 증거가 고정 체크아웃의 실제 파일과 줄을 가리키는지 확인한다."""
    root = checkout.resolve()
    for row in investigation["candidates"]:
        primary = (root / row["file_path"]).resolve()
        if not primary.is_relative_to(root) or not primary.is_file():
            raise ValueError(f"Candidate path is outside checkout or missing: {row['finding_id']}")
        if row["line"] > len(primary.read_text(encoding="utf-8", errors="replace").splitlines()):
            raise ValueError(f"Candidate line is outside source file: {row['finding_id']}")
        for reference in row["code_evidence"]:
            match = EVIDENCE_REF.fullmatch(reference)
            if not match:
                raise ValueError(f"Invalid code evidence reference: {reference}")
            source = (root / match["path"]).resolve()
            if not source.is_relative_to(root) or not source.is_file():
                raise ValueError(f"Code evidence path is outside checkout or missing: {reference}")
            start = int(match["start"])
            end = int(match["end"] or start)
            if end < start or end > len(source.read_text(encoding="utf-8", errors="replace").splitlines()):
                raise ValueError(f"Code evidence line is outside source file: {reference}")


def evaluate(investigation: dict[str, Any], review: dict[str, Any]) -> dict[str, Any]:
    """미완료 조사나 미확정 후보에서 Recall을 추정하지 않는다."""
    if investigation.get("schema_version") != 1:
        raise ValueError("Unsupported investigation schema.")
    for key in ("target_id", "repository", "commit_sha", "rule_set_sha256"):
        if investigation.get(key) != review.get(key):
            raise ValueError(f"Investigation/review mismatch: {key}")
    coverage = investigation.get("coverage")
    candidates = investigation.get("candidates")
    if not isinstance(coverage, dict) or not coverage or not isinstance(candidates, list):
        raise ValueError("Investigation needs coverage and candidates.")
    review_rows = {row["finding_id"]: row for row in review["findings"]}
    if len(review_rows) != len(review["findings"]):
        raise ValueError("Duplicate review Finding ID.")
    seen_ids = set()
    linked_ids = set()
    by_type = {}
    for name, entry in coverage.items():
        if not isinstance(name, str) or not name or not isinstance(entry, dict):
            raise ValueError("Invalid coverage entry.")
        if type(entry.get("complete")) is not bool or not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            raise ValueError(f"Coverage requires a boolean and reason: {name}")
        by_type[name] = {label: 0 for label in LABELS}
    for row in candidates:
        candidate_id = row.get("finding_id")
        if not isinstance(candidate_id, str) or not candidate_id or candidate_id in seen_ids:
            raise ValueError("Invalid or duplicate candidate Finding ID.")
        seen_ids.add(candidate_id)
        if row.get("repository") != review["repository"] or row.get("commit_sha") != review["commit_sha"]:
            raise ValueError(f"Candidate target mismatch: {candidate_id}")
        name = row.get("vulnerability")
        label = row.get("classification")
        if name not in by_type or label not in LABELS:
            raise ValueError(f"Invalid vulnerability or classification: {candidate_id}")
        for key in ("file_path", "cwe", "source", "sink", "data_flow", "evidence"):
            if not isinstance(row.get(key), str) or not row[key].strip():
                raise ValueError(f"Candidate needs {key}: {candidate_id}")
        if type(row.get("line")) is not int or row["line"] < 1:
            raise ValueError(f"Candidate needs a positive line: {candidate_id}")
        code_evidence = row.get("code_evidence")
        if not isinstance(code_evidence, list) or not code_evidence or not all(
            isinstance(item, str) and item.strip() for item in code_evidence
        ):
            raise ValueError(f"Candidate needs code evidence: {candidate_id}")
        detected = row.get("scanner_detected")
        if type(detected) is not bool or (label in ("TP", "FP") and not detected) or (label == "FN" and detected):
            raise ValueError(f"Classification/detection mismatch: {candidate_id}")
        linked = row.get("review_finding_id")
        if linked is not None:
            if (linked in linked_ids or linked not in review_rows
                    or review_rows[linked]["classification"] != label
                    or review_rows[linked].get("rule_id") != row.get("rule_id")):
                raise ValueError(f"Review linkage mismatch: {candidate_id}")
            linked_ids.add(linked)
        elif label in ("TP", "FP"):
            raise ValueError(f"Detected classification needs a review link: {candidate_id}")
        by_type[name][label] += 1
    reviewed = quality_metrics(review)
    if {row["finding_id"] for row in review["findings"] if row["classification"] in ("TP", "FP")} != linked_ids:
        raise ValueError("Every reviewed Scanner Finding must be linked exactly once.")
    if {row["finding_id"] for row in review["missed_findings"]} != {
        row["finding_id"] for row in candidates if row["classification"] == "FN"
    }:
        raise ValueError("Confirmed FN candidates must match the review missed_findings list.")
    result = {}
    for name, stats in by_type.items():
        complete = coverage[name]["complete"] and stats["UNCONFIRMED"] == 0
        denominator = stats["TP"] + stats["FN"]
        result[name] = {
            **stats,
            "coverage_complete": complete,
            "precision": stats["TP"] / (stats["TP"] + stats["FP"]) if stats["TP"] + stats["FP"] else None,
            "recall": stats["TP"] / denominator if complete and denominator else None,
        }
    all_complete = all(row["coverage_complete"] for row in result.values())
    denominator = reviewed["TP"] + reviewed["FN"]
    return {
        "target_id": investigation["target_id"],
        "by_vulnerability": result,
        "overall": {
            "TP": reviewed["TP"], "FP": reviewed["FP"], "FN": reviewed["FN"],
            "OUT_OF_SCOPE": sum(row["OUT_OF_SCOPE"] for row in result.values()),
            "UNCONFIRMED": sum(row["UNCONFIRMED"] for row in result.values()),
            "precision": reviewed["precision"],
            "recall": reviewed["TP"] / denominator if all_complete and denominator else None,
            "coverage_complete": all_complete,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="독립 소스 조사 결과와 유형별 품질 지표")
    parser.add_argument("--target", help="대상 ID; 생략하면 모든 대상")
    args = parser.parse_args(argv)
    try:
        targets = load_targets()
        if args.target and args.target not in targets:
            raise ValueError(f"Unknown target ID: {args.target}")
        for target in ([targets[args.target]] if args.target else targets.values()):
            verify_target(target)
            investigation = json.loads((INVESTIGATIONS / f"{target.id}.json").read_text(encoding="utf-8"))
            review = json.loads(review_path(target, investigation["rule_set_sha256"]).read_text(encoding="utf-8"))
            check_code_evidence(investigation, target.path)
            print(json.dumps(evaluate(investigation, review), indent=2, ensure_ascii=False))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Investigation error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
