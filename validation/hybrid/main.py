"""기존 scanner.main을 건드리지 않는 독립형 하이브리드 분석 CLI."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence
from uuid import uuid4

from scanner.main import DEFAULT_RULES, EXIT_ERROR, EXIT_FINDINGS, EXIT_SUCCESS
from validation.hybrid.engines import (
    BATCH_QUERIES, QUERIES, CodeQLAdapter, CodeQLBatchAdapter, SemgrepAdapter,
)
from validation.hybrid.model import EngineResult, FindingGrouper
from validation.hybrid.report import HybridReporter


ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class HybridOutcome:
    report_dir: Path
    report_paths: tuple[Path, Path]
    engines: tuple[EngineResult, ...]
    total_findings: int
    cross_engine_groups: int

    @property
    def exit_code(self) -> int:
        if any(engine.status != "success" for engine in self.engines):
            return EXIT_ERROR
        return EXIT_FINDINGS if self.total_findings else EXIT_SUCCESS


class HybridApplication:
    """순차적 엔진 실행, 오류 격리, 중복 그룹 및 보고서 저장을 조정한다."""

    def scan(self, target: str | Path, *, engines: str = "both", query: str = "command",
             rules_dir: str | Path = DEFAULT_RULES, output_dir: str | Path | None = None,
             codeql: str | None = None, timeout: int = 900) -> HybridOutcome:
        target_path = Path(target).resolve()
        if not target_path.is_dir():
            raise ValueError(f"Scan target must be an existing directory: {target_path}")
        if engines not in ("semgrep", "codeql", "both"):
            raise ValueError(f"Unsupported engine selection: {engines}")
        if query not in QUERIES and query not in BATCH_QUERIES:
            raise ValueError(f"Unsupported CodeQL query: {query}")
        if type(timeout) is not int or timeout < 1:
            raise ValueError("timeout must be a positive integer")
        output_root = Path(output_dir or ROOT / "reports" / "hybrid").resolve()
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8]
        run_dir = output_root / f"{target_path.name}-{run_id}"
        raw_dir = run_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=False)
        adapters = []
        if engines in ("semgrep", "both"):
            adapters.append(SemgrepAdapter(Path(rules_dir).resolve(), timeout))
        if engines in ("codeql", "both"):
            cache_dir = output_root / ".codeql-cache"
            if query in BATCH_QUERIES:
                adapters.append(CodeQLBatchAdapter(
                    tuple(QUERIES[key] for key in BATCH_QUERIES[query]), codeql, timeout,
                    cache_dir,
                ))
            else:
                adapters.append(CodeQLAdapter(QUERIES[query], codeql, timeout, cache_dir))
        results = [adapter.run(target_path, raw_dir) for adapter in adapters]
        findings = [item for result in results for item in result.findings]
        groups = FindingGrouper().group(findings)
        reporter = HybridReporter()
        report = reporter.build(target_path.name, target_path, run_id, results, groups)
        paths = reporter.save(run_dir, report)
        return HybridOutcome(run_dir, paths, tuple(results), len(findings),
                             report["summary"]["cross_engine_groups"])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="독립형 하이브리드 분석 프로토타입")
    scan.add_argument("target", type=Path)
    scan.add_argument("--engines", choices=("semgrep", "codeql", "both"), default="both")
    scan.add_argument("--query", choices=(*QUERIES, *BATCH_QUERIES), default="command")
    scan.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    scan.add_argument("--codeql", help="CodeQL CLI 경로 (없으면 PATH에서 탐색)")
    scan.add_argument("--output", type=Path, default=ROOT / "reports" / "hybrid")
    scan.add_argument("--timeout", type=int, default=900)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        outcome = HybridApplication().scan(
            args.target, engines=args.engines, query=args.query, rules_dir=args.rules,
            output_dir=args.output, codeql=args.codeql, timeout=args.timeout,
        )
    except (OSError, ValueError, TypeError, RuntimeError) as error:
        print(f"하이브리드 실행 오류: {error}", file=sys.stderr)
        return EXIT_ERROR
    for result in outcome.engines:
        detail = f" ({result.error_stage}: {result.error_message})" if result.error_message else ""
        print(f"{result.engine}: {result.status}, Finding {len(result.findings)}건{detail}")
        for query_result in result.queries:
            query_detail = (f" ({query_result.error_stage}: {query_result.error_message})"
                            if query_result.error_message else "")
            print(f"  {query_result.query_name}: {query_result.status}, "
                  f"Finding {query_result.finding_count}건, "
                  f"{query_result.elapsed_seconds:.3f}초{query_detail}")
    print(f"통합 Finding {outcome.total_findings}건, 교차 엔진 그룹 {outcome.cross_engine_groups}개")
    for path in outcome.report_paths:
        print(f"보고서 저장: {path}")
    return outcome.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
