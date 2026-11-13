"""정규화된 Finding을 Markdown 또는 JSON 보고서로 변환한다."""

import json
import math
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import asdict
from html import escape
from pathlib import Path
from typing import Any, Sequence

from scanner.result_parser import Finding


class ReportFormatter(ABC):
    """보고서 출력 형식의 확장 지점."""

    @abstractmethod
    def render(self, report: dict[str, Any]) -> str:
        """구조화된 보고서를 문자열로 변환한다."""


class MarkdownFormatter(ReportFormatter):
    """사람이 읽기 쉬운 Markdown 보고서를 생성한다."""

    @staticmethod
    def _value(value: Any) -> str:
        # 동적 값이 표나 목록의 Markdown 구조를 깨지 않도록 이스케이프한다.
        text = escape(str(value), quote=False)
        for character in ("\\", "|", "`", "*", "_", "[", "]"):
            text = text.replace(character, "\\" + character)
        return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>")

    def _statistics(self, title: str, counts: dict[str, int]) -> list[str]:
        lines = [f"## {title}", "", "| 항목 | 건수 |", "| --- | ---: |"]
        lines.extend(
            f"| {self._value(name)} | {count} |"
            for name, count in counts.items()
        )
        if not counts:
            lines.append("| 없음 | 0 |")
        return lines

    def render(self, report: dict[str, Any]) -> str:
        lines = [
            f"# {self._value(report['project_name'])} 취약점 스캔 보고서",
            "",
            f"- 분석 대상 경로: {self._value(report['target_path'])}",
            f"- 스캔 실행 시간: {report['elapsed_seconds']:.3f}초",
            f"- 전체 Finding 수: {report['total_findings']}",
            "",
        ]
        for title, key in (
            ("취약점 유형별 통계", "by_vulnerability"),
            ("심각도별 통계", "by_severity"),
            ("CWE별 통계", "by_cwe"),
        ):
            lines.extend(self._statistics(title, report[key]))
            lines.append("")

        lines.extend(["## Finding 상세 정보", ""])
        if not report["findings"]:
            lines.append("탐지된 Finding이 없습니다.")
        for index, finding in enumerate(report["findings"], start=1):
            lines.extend([
                f"### Finding {index}",
                "",
                f"- Rule ID: {self._value(finding['rule_id'])}",
                f"- 취약점 유형: {self._value(finding['vulnerability'])}",
                f"- CWE: {self._value(finding['cwe'])}",
                f"- Severity: {self._value(finding['severity'])}",
                f"- Confidence: {self._value(finding['confidence'])}",
                f"- 파일 경로: {self._value(finding['file_path'])}",
                f"- 시작 줄 번호: {finding['start_line']}",
                f"- 종료 줄 번호: {finding['end_line']}",
                f"- 탐지 메시지: {self._value(finding['message'])}",
                "",
            ])
        return "\n".join(lines).rstrip() + "\n"


class JsonFormatter(ReportFormatter):
    """기계가 소비할 수 있는 JSON 보고서를 생성한다."""

    def render(self, report: dict[str, Any]) -> str:
        return json.dumps(report, ensure_ascii=False, indent=2) + "\n"


class Reporter:
    """Finding 검증, 통계 집계, 형식 선택 및 파일 저장을 담당한다."""

    def __init__(
        self,
        project_name: str,
        target_path: str | Path,
        elapsed_seconds: float,
    ) -> None:
        if not isinstance(project_name, str) or not project_name.strip():
            raise ValueError("project_name must be a non-empty string.")
        if not isinstance(target_path, (str, Path)) or not str(target_path).strip():
            raise ValueError("target_path must be a non-empty path.")
        if (
            isinstance(elapsed_seconds, bool)
            or not isinstance(elapsed_seconds, (int, float))
            or not math.isfinite(elapsed_seconds)
            or elapsed_seconds < 0
        ):
            raise ValueError("elapsed_seconds must be a finite non-negative number.")

        self.project_name = project_name
        self.target_path = str(target_path)
        self.elapsed_seconds = float(elapsed_seconds)
        self._formatters: dict[str, ReportFormatter] = {
            "markdown": MarkdownFormatter(),
            "json": JsonFormatter(),
        }

    def register_formatter(self, name: str, formatter: ReportFormatter) -> None:
        """HTML, CSV 등 새 출력 형식을 등록한다."""
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Formatter name must be a non-empty string.")
        if not isinstance(formatter, ReportFormatter):
            raise TypeError("formatter must be a ReportFormatter instance.")
        self._formatters[name] = formatter

    @staticmethod
    def _validate_finding(finding: Finding, index: int) -> None:
        if not isinstance(finding, Finding):
            raise TypeError(f"findings[{index}] must be a Finding instance.")
        for field in (
            "rule_id", "vulnerability", "cwe", "severity",
            "confidence", "file_path",
        ):
            value = getattr(finding, field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"findings[{index}].{field} must be a non-empty string.")
        if not isinstance(finding.message, str):
            raise ValueError(f"findings[{index}].message must be a string.")
        if (
            type(finding.start_line) is not int
            or type(finding.end_line) is not int
            or finding.start_line < 1
            or finding.end_line < finding.start_line
        ):
            raise ValueError(f"findings[{index}] has invalid line numbers.")

    def build_report(self, findings: Sequence[Finding]) -> dict[str, Any]:
        """Finding 목록을 검증하고 형식에 독립적인 보고서를 만든다."""
        if isinstance(findings, (str, bytes)) or not isinstance(findings, Sequence):
            raise TypeError("findings must be a sequence of Finding instances.")
        for index, finding in enumerate(findings):
            self._validate_finding(finding, index)

        def counts(field: str) -> dict[str, int]:
            return dict(sorted(Counter(getattr(item, field) for item in findings).items()))

        return {
            "project_name": self.project_name,
            "target_path": self.target_path,
            "elapsed_seconds": self.elapsed_seconds,
            "total_findings": len(findings),
            "by_vulnerability": counts("vulnerability"),
            "by_severity": counts("severity"),
            "by_cwe": counts("cwe"),
            "findings": [asdict(finding) for finding in findings],
        }

    def generate(self, findings: Sequence[Finding], format: str = "markdown") -> str:
        """선택한 형식의 보고서 문자열을 생성한다."""
        try:
            formatter = self._formatters[format]
        except (KeyError, TypeError) as error:
            raise ValueError(f"Unsupported report format: {format}") from error
        return formatter.render(self.build_report(findings))

    def save(
        self,
        findings: Sequence[Finding],
        output_path: str | Path,
        format: str = "markdown",
    ) -> Path:
        """보고서 저장 디렉터리를 만든 뒤 파일을 기록한다."""
        if not isinstance(output_path, (str, Path)) or not str(output_path).strip():
            raise ValueError("output_path must be a non-empty path.")
        content = self.generate(findings, format)
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
        return destination
