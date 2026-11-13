"""고정 오픈소스 대상의 스캔, 판정 대기열, 품질 지표를 관리한다."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.main import PROJECT_ROOT, ScanApplication, project_version
from scanner.rule_loader import RuleLoader


MANIFEST = Path(__file__).with_name("targets.json")
REPORTS = PROJECT_ROOT / "reports" / "validation"
REVIEWS = Path(__file__).with_name("reviews")
SHA_PATTERN = re.compile(r"[0-9a-f]{40}\Z")


@dataclass(frozen=True)
class Target:
    id: str
    language: str
    repository: str
    version: str
    commit_sha: str
    commit_date: str
    license: str
    license_file: str
    checkout: str

    @property
    def path(self) -> Path:
        return (PROJECT_ROOT / self.checkout).resolve()


def load_targets() -> dict[str, Target]:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or not isinstance(data.get("targets"), list):
        raise ValueError("Invalid target manifest schema.")
    targets = {}
    for entry in data["targets"]:
        target = Target(**entry)
        if not re.fullmatch(r"[a-z0-9-]+", target.id):
            raise ValueError(f"Invalid target ID: {target.id}")
        if not SHA_PATTERN.fullmatch(target.commit_sha):
            raise ValueError(f"Invalid commit SHA for {target.id}.")
        if target.id in targets:
            raise ValueError(f"Duplicate target ID: {target.id}")
        targets[target.id] = target
    return targets


def verify_target(target: Target) -> None:
    """로컬 체크아웃의 범위, 커밋, 청결 상태와 라이선스를 검사한다."""
    allowed_root = (PROJECT_ROOT / "targets" / "opensource").resolve()
    if not target.path.is_relative_to(allowed_root) or not target.path.is_dir():
        raise ValueError(f"Target checkout is missing or outside targets/opensource: {target.checkout}")
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=target.path,
        capture_output=True, text=True, check=True,
    )
    if result.stdout.strip() != target.commit_sha:
        raise ValueError(f"Commit mismatch for {target.id}: expected {target.commit_sha}, got {result.stdout.strip()}")
    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=target.path,
        capture_output=True, text=True, check=True,
    )
    if status.stdout.strip():
        raise ValueError(f"Target checkout has local changes: {target.id}")
    license_path = (target.path / target.license_file).resolve()
    if not license_path.is_relative_to(target.path) or not license_path.is_file():
        raise ValueError(f"License file missing for {target.id}: {target.license_file}")
    heading = license_path.read_text(encoding="utf-8", errors="replace")[:200].lower()
    expected = "mit license" if target.license == "MIT" else "apache license"
    if expected not in heading:
        raise ValueError(f"License file does not match recorded license for {target.id}.")


def rule_digest() -> str:
    digest = hashlib.sha256()
    for info in RuleLoader(PROJECT_ROOT / "rules").load_rules():
        name = info.file_path.relative_to(PROJECT_ROOT).as_posix()
        digest.update(name.encode("utf-8") + b"\0")
        digest.update(info.file_path.read_bytes() + b"\0")
    return digest.hexdigest()


def report_directory(target: Target, rules_sha256: str) -> Path:
    return REPORTS / target.id / target.commit_sha / rules_sha256[:12]


def review_path(target: Target, rules_sha256: str) -> Path:
    return REVIEWS / target.id / f"{target.commit_sha[:12]}-{rules_sha256[:12]}.json"


def finding_id(target: Target, finding: dict[str, Any], relative_path: str) -> str:
    key = "\0".join((
        target.repository, target.commit_sha, finding["rule_id"],
        relative_path, str(finding["start_line"]), str(finding["end_line"]),
    ))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]


def make_review_queue(target: Target, rules_sha256: str, report: dict[str, Any]) -> Path:
    """기존 판정을 보존하면서 새 스캔의 판정 대기열을 생성한다."""
    destination = review_path(target, rules_sha256)
    rows = []
    for finding in report["findings"]:
        source_path = Path(finding["file_path"]).resolve()
        if not source_path.is_relative_to(target.path):
            raise ValueError(f"Finding path is outside target: {source_path}")
        relative_path = source_path.relative_to(target.path).as_posix()
        rows.append({
            "finding_id": finding_id(target, finding, relative_path),
            "repository": target.repository,
            "commit_sha": target.commit_sha,
            "rule_id": finding["rule_id"],
            "vulnerability": finding["vulnerability"],
            "cwe": finding["cwe"],
            "file_path": relative_path,
            "start_line": finding["start_line"],
            "end_line": finding["end_line"],
            "validation_result": "unreviewed",
            "classification": None,
            "evidence": "",
        })
    if destination.exists():
        previous = json.loads(destination.read_text(encoding="utf-8"))
        old_ids = {row["finding_id"] for row in previous["findings"]}
        new_ids = {row["finding_id"] for row in rows}
        if old_ids != new_ids:
            raise ValueError(f"Review queue differs from current scan: {destination}")
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    queue = {
        "schema_version": 1,
        "target_id": target.id,
        "repository": target.repository,
        "commit_sha": target.commit_sha,
        "rule_set_sha256": rules_sha256,
        "ground_truth_complete": False,
        "findings": rows,
        "missed_findings": [],
    }
    destination.write_text(json.dumps(queue, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return destination


def scan_target(target: Target) -> dict[str, Any]:
    verify_target(target)
    rules_sha256 = rule_digest()
    semgrep_version = subprocess.run(
        ["semgrep", "--version"], capture_output=True, text=True, check=True,
    ).stdout.strip()
    output = report_directory(target, rules_sha256)
    outcome = ScanApplication().scan(target.path, output_dir=output)
    report_file = output / f"{target.path.name}-scan.json"
    report = json.loads(report_file.read_text(encoding="utf-8"))
    review = make_review_queue(target, rules_sha256, report)
    run = {
        "target_id": target.id,
        "repository": target.repository,
        "version": target.version,
        "commit_sha": target.commit_sha,
        "commit_date": target.commit_date,
        "license": target.license,
        "license_file": target.license_file,
        "rule_set_sha256": rules_sha256,
        "scanner_version": project_version(),
        "semgrep_version": semgrep_version,
        "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
        "total_findings": outcome.total_findings,
        "by_vulnerability": outcome.by_vulnerability,
        "by_cwe": outcome.by_cwe,
        "report_files": [str(path.relative_to(PROJECT_ROOT)) for path in outcome.report_paths],
        "review_file": str(review.relative_to(PROJECT_ROOT)),
    }
    (output / "run.json").write_text(json.dumps(run, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return run


def quality_metrics(queue: dict[str, Any]) -> dict[str, Any]:
    """미검토와 미완료된 근거 집합을 수치에 반영한다."""
    if type(queue["ground_truth_complete"]) is not bool:
        raise ValueError("ground_truth_complete must be a boolean.")
    findings = queue["findings"]
    missed = queue["missed_findings"]
    tp = sum(row["classification"] == "TP" for row in findings)
    fp = sum(row["classification"] == "FP" for row in findings)
    pending = sum(row["classification"] is None for row in findings)
    if any(row["classification"] not in ("TP", "FP", None) for row in findings):
        raise ValueError("A reported Finding must be TP, FP, or unreviewed.")
    if any(row["classification"] != "FN" for row in missed):
        raise ValueError("A missed Finding must be classified FN.")
    for row in [*findings, *missed]:
        if row["classification"] is not None and not row["evidence"].strip():
            raise ValueError(f"Classification requires evidence: {row['finding_id']}")
    fn = len(missed)
    precision = tp / (tp + fp) if pending == 0 and tp + fp > 0 else None
    recall = tp / (tp + fn) if queue["ground_truth_complete"] and pending == 0 and tp + fn > 0 else None
    return {
        "target_id": queue["target_id"],
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "unreviewed": pending,
        "ground_truth_complete": queue["ground_truth_complete"],
        "precision": precision,
        "recall": recall,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="고정 오픈소스 대상의 스캔과 품질 검증")
    parser.add_argument("command", choices=("verify", "scan", "metrics"))
    parser.add_argument("--target", help="대상 ID; 생략하면 모든 대상")
    args = parser.parse_args(argv)
    try:
        targets = load_targets()
        if args.target and args.target not in targets:
            raise ValueError(f"Unknown target ID: {args.target}")
        selected = [targets[args.target]] if args.target else list(targets.values())
        for target in selected:
            if args.command == "verify":
                verify_target(target)
                print(f"{target.id}: verified {target.commit_sha} ({target.license})")
            elif args.command == "scan":
                print(json.dumps(scan_target(target), ensure_ascii=False, indent=2))
            else:
                path = review_path(target, rule_digest())
                print(json.dumps(quality_metrics(json.loads(path.read_text(encoding="utf-8"))), ensure_ascii=False, indent=2))
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"Validation error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
