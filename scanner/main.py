"""Semgrep 기반 취약점 스캐너의 명령줄 진입점."""

import argparse
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from scanner.reporter import Reporter
from scanner.result_parser import ResultParser
from scanner.rule_loader import RuleLoader
from scanner.semgrep_runner import SemgrepRunner


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES = PROJECT_ROOT / "rules"
DEFAULT_OUTPUT = PROJECT_ROOT / "reports"
REPORT_FORMATS = {"markdown": ".md", "json": ".json"}
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_FINDINGS = 2


class ScannerArgumentParser(argparse.ArgumentParser):
    """잘못된 CLI 입력을 Scanner 실행 오류 코드로 반환한다."""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")


def project_version() -> str:
    """프로젝트 메타데이터에서 버전을 읽는다."""
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as file:
        return tomllib.load(file)["project"]["version"]


def positive_seconds(value: str) -> int:
    try:
        seconds = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timeout must be a positive integer") from error
    if seconds <= 0:
        raise argparse.ArgumentTypeError("timeout must be a positive integer")
    return seconds


@dataclass(frozen=True)
class ScanOutcome:
    """CLI 출력에 필요한 스캔 결과와 보고서 경로."""

    total_findings: int
    by_vulnerability: dict[str, int]
    by_severity: dict[str, int]
    by_cwe: dict[str, int]
    report_paths: tuple[Path, ...]


class ScanApplication:
    """Rule 수집, Semgrep 실행, 결과 분석, 보고서 저장을 연결한다."""

    def scan(
        self,
        target: str | Path,
        rules_dir: str | Path = DEFAULT_RULES,
        output_dir: str | Path = DEFAULT_OUTPUT,
        output_format: str = "both",
        timeout: int = 300,
    ) -> ScanOutcome:
        target_path = Path(target).resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"Scan target not found: {target_path}")
        if not target_path.is_dir():
            raise NotADirectoryError(f"Scan target must be a directory: {target_path}")
        project_name = target_path.name or "root"

        # RuleLoader의 검증을 스캔 전에 수행한다. Runner도 이 Loader를 사용한다.
        rules_path = Path(rules_dir).resolve()
        RuleLoader(rules_path).load_rules()
        runner = SemgrepRunner(rules_path, timeout=timeout)
        raw_report = runner.scan(target_path)
        if raw_report.get("errors"):
            errors = raw_report["errors"]
            first_error = errors[0] if isinstance(errors, list) else errors
            detail = first_error.get("message", first_error) if isinstance(first_error, dict) else first_error
            raise RuntimeError(f"Semgrep reported scan errors: {detail}")
        metadata = raw_report["scanner_metadata"]
        findings = ResultParser(metadata["rules"]).parse(raw_report)

        reporter = Reporter(
            project_name=project_name,
            target_path=metadata["target"],
            elapsed_seconds=metadata["elapsed_seconds"],
        )
        summary = reporter.build_report(findings)
        formats = tuple(REPORT_FORMATS) if output_format == "both" else (output_format,)
        destination = Path(output_dir).resolve()
        paths = tuple(
            reporter.save(
                findings,
                destination / f"{project_name}-scan{REPORT_FORMATS[format_name]}",
                format_name,
            )
            for format_name in formats
        )
        return ScanOutcome(
            total_findings=summary["total_findings"],
            by_vulnerability=summary["by_vulnerability"],
            by_severity=summary["by_severity"],
            by_cwe=summary["by_cwe"],
            report_paths=paths,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = ScannerArgumentParser(
        prog="python -m scanner.main",
        description="사용자 정의 Semgrep Rule로 대상 프로젝트를 스캔합니다.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {project_version()}")
    commands = parser.add_subparsers(
        dest="command", required=True, parser_class=ScannerArgumentParser
    )
    scan = commands.add_parser("scan", help="대상 디렉터리를 스캔하고 보고서를 저장합니다.")
    scan.add_argument("target", type=Path, help="분석할 디렉터리")
    scan.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="Rule 디렉터리")
    scan.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="보고서 저장 디렉터리")
    scan.add_argument(
        "--format", choices=("markdown", "json", "both"), default="both",
        help="보고서 형식 (기본값: both)",
    )
    scan.add_argument(
        "--timeout", type=positive_seconds, default=300,
        help="Semgrep 제한 시간, 초 단위 (기본값: 300)",
    )
    return parser


def _print_counts(label: str, counts: dict[str, int]) -> None:
    details = ", ".join(f"{name}: {count}" for name, count in counts.items()) or "없음"
    print(f"{label}: {details}")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        outcome = ScanApplication().scan(
            target=args.target,
            rules_dir=args.rules,
            output_dir=args.output,
            output_format=args.format,
            timeout=args.timeout,
        )
    except (OSError, ValueError, TypeError, RuntimeError, TimeoutError, KeyError) as error:
        print(f"오류: {error}", file=sys.stderr)
        return EXIT_ERROR

    print(f"전체 Finding 수: {outcome.total_findings}")
    _print_counts("취약점 유형별", outcome.by_vulnerability)
    _print_counts("심각도별", outcome.by_severity)
    _print_counts("CWE별", outcome.by_cwe)
    for path in outcome.report_paths:
        print(f"보고서 저장: {path}")
    return EXIT_FINDINGS if outcome.total_findings > 0 else EXIT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())
