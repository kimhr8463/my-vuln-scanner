from dataclasses import dataclass
from collections import Counter
from typing import Any


@dataclass(frozen=True)
class Finding:
    """정규화된 취약점 탐지 결과."""

    rule_id: str
    vulnerability: str
    cwe: str
    severity: str
    confidence: str
    file_path: str
    start_line: int
    end_line: int
    message: str


class ResultParser:
    """Semgrep JSON 결과를 분석하고 구조화한다."""

    def __init__(self, known_rule_ids: list[str] | None = None):
        self.known_rule_ids = known_rule_ids or []

    def _extract_rule_id(self, check_id: str) -> str:
        """임시 설정 경로가 포함된 check_id에서 실제 Rule ID를 찾는다."""

        for rule_id in sorted(
            self.known_rule_ids,
            key=len,
            reverse=True,
        ):
            if check_id.endswith(rule_id):
                return rule_id

        return check_id

    def _parse_finding(self, result: dict[str, Any]) -> Finding:
        """개별 Finding을 정규화한다."""

        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        start = result.get("start") or {}
        end = result.get("end") or {}

        check_id = result.get("check_id", "unknown")

        return Finding(
            rule_id=self._extract_rule_id(check_id),
            vulnerability=metadata.get(
                "vulnerability", "Unknown"
            ),
            cwe=metadata.get("cwe", "Unknown"),
            severity=str(
                extra.get("severity", "INFO")
            ).upper(),
            confidence=metadata.get(
                "confidence", "UNKNOWN"
            ),
            file_path=result.get("path", "Unknown"),
            start_line=start.get("line", 0),
            end_line=end.get("line", 0),
            message=extra.get("message", ""),
        )

    def parse(self, report: dict[str, Any]) -> list[Finding]:
        """JSON 보고서에서 Finding을 추출하고 중복을 제거한다."""

        results = report.get("results", [])

        if not isinstance(results, list):
            raise ValueError("Invalid Semgrep results format.")

        findings = []
        seen = set()

        for result in results:
            if not isinstance(result, dict):
                continue

            finding = self._parse_finding(result)

            # 동일 Rule, 파일, 시작 위치의 중복 결과 제거
            fingerprint = (
                finding.rule_id,
                finding.file_path,
                finding.start_line,
            )

            if fingerprint in seen:
                continue

            seen.add(fingerprint)
            findings.append(finding)

        return findings

    def summarize(self, findings: list[Finding]) -> dict:
        """탐지 결과를 유형 및 심각도별로 집계한다."""

        vulnerability_counts = Counter(
            finding.vulnerability for finding in findings
        )

        severity_counts = Counter(
            finding.severity for finding in findings
        )

        cwe_counts = Counter(
            finding.cwe for finding in findings
        )

        return {
            "total_findings": len(findings),
            "by_vulnerability": dict(vulnerability_counts),
            "by_severity": dict(severity_counts),
            "by_cwe": dict(cwe_counts),
        }
