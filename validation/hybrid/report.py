"""원본 링크, 엔진별 상태와 중복 그룹을 보존하는 통합 보고서."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from html import escape
from pathlib import Path
from typing import Any

from validation.hybrid.model import EngineResult, FindingGroup, HybridFinding, Location


def _visible(value: Any) -> str:
    rendered = escape(str(value), quote=False)
    for character in ("\\", "|", "`", "*", "_", "[", "]"):
        rendered = rendered.replace(character, "\\" + character)
    return rendered.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>")


def _location(location: Location | None) -> str:
    return f"{location.path}:{location.start_line}-{location.end_line}" if location else "미확인"


class HybridReporter:
    """개별 엔진 결과를 유지하면서 JSON/Markdown 통합 뷰를 만든다."""

    def build(self, project_name: str, target: Path, run_id: str,
              engines: list[EngineResult], groups: list[FindingGroup]) -> dict[str, Any]:
        findings = [finding for engine in engines for finding in engine.findings]
        return {
            "schema_version": 1,
            "project_name": project_name,
            "target_path": str(target),
            "run_id": run_id,
            "summary": {
                "total_findings": len(findings),
                "group_count": len(groups),
                "cross_engine_groups": sum(len(group.engines) > 1 for group in groups),
                "by_engine": dict(sorted(Counter(item.engine for item in findings).items())),
                "by_vulnerability": dict(sorted(Counter(item.vulnerability for item in findings).items())),
                "by_cwe": dict(sorted(Counter(item.cwe for item in findings).items())),
                "by_query": {
                    query.query_name: {
                        "query_id": query.query_id,
                        "status": query.status,
                        "finding_count": query.finding_count,
                        "elapsed_seconds": query.elapsed_seconds,
                    }
                    for engine in engines for query in engine.queries
                },
            },
            "engines": [asdict(engine) for engine in engines],
            "findings": [asdict(finding) for finding in findings],
            "groups": [asdict(group) for group in groups],
        }

    def markdown(self, report: dict[str, Any]) -> str:
        summary = report["summary"]
        lines = [
            f"# {_visible(report['project_name'])} 하이브리드 분석 보고서", "",
            f"- 대상: {_visible(report['target_path'])}",
            f"- 실행 ID: {_visible(report['run_id'])}",
            f"- 원본 Finding: {summary['total_findings']}건",
            f"- 중복 그룹: {summary['cross_engine_groups']}개 (전체 그룹 {summary['group_count']}개)", "",
            "## 엔진 실행 상태", "",
            "| 엔진 | 상태 | 시간(초) | 원본 결과 | 오류 단계/내용 |",
            "| --- | --- | ---: | --- | --- |",
        ]
        for engine in report["engines"]:
            error = " / ".join(filter(None, (engine["error_stage"], engine["error_message"])))
            lines.append(
                f"| {_visible(engine['engine'])} | {_visible(engine['status'])} | "
                f"{engine['elapsed_seconds']:.3f} | {_visible(engine['raw_report'] or '없음')} | "
                f"{_visible(error or '없음')} |"
            )
        queries = [query for engine in report["engines"] for query in engine["queries"]]
        if queries:
            lines.extend(["", "## CodeQL Query별 실행 결과", "",
                          "| Query | Query ID | 상태 | Finding | 시간(초) | SARIF | 오류 단계/내용 |",
                          "| --- | --- | --- | ---: | ---: | --- | --- |"])
            for query in queries:
                error = " / ".join(filter(None, (query["error_stage"], query["error_message"])))
                lines.append(
                    f"| {_visible(query['query_name'])} | {_visible(query['query_id'])} | "
                    f"{_visible(query['status'])} | {query['finding_count']} | "
                    f"{query['elapsed_seconds']:.3f} | "
                    f"{_visible(query['raw_report'] or '없음')} | {_visible(error or '없음')} |"
                )
            create_times = [engine["database_create_seconds"] for engine in report["engines"]
                            if engine["database_create_seconds"] is not None]
            if create_times:
                lines.extend(["", f"- CodeQL DB 생성 시간: {create_times[0]:.3f}초"])
        lines.extend(["", "## 통계", ""])
        for title, field in (("엔진별", "by_engine"), ("취약점 유형별", "by_vulnerability"),
                             ("CWE별", "by_cwe")):
            counts = summary[field]
            detail = ", ".join(f"{name}: {count}" for name, count in counts.items()) or "없음"
            lines.append(f"- {title}: {_visible(detail)}")
        lines.extend(["", "## 중복 그룹", ""])
        if not report["groups"]:
            lines.append("Finding이 없습니다.")
        for group in report["groups"]:
            lines.append(
                f"- {_visible(group['group_id'])}: {_visible(group['cwe'])} "
                f"{_visible(group['sink_path'])}:{group['start_line']}-{group['end_line']}; "
                f"엔진 {', '.join(group['engines'])}; 원본 ID {', '.join(group['member_ids'])}"
            )
        lines.extend(["", "## 개별 Finding", ""])
        for item in report["findings"]:
            source = Location(**item["source"]) if item["source"] else None
            sink = Location(**item["sink"])
            steps = [Location(**step) for step in item["flow_evidence"]]
            lines.extend([
                f"### {_visible(item['finding_id'])} ({_visible(item['engine'])})", "",
                f"- Rule/Query ID: {_visible(item['rule_id'])}",
                f"- 유형 / CWE: {_visible(item['vulnerability'])} / {_visible(item['cwe'])}",
                f"- Severity / Confidence / 검증: {_visible(item['severity'])} / "
                f"{_visible(item['confidence'])} / {_visible(item['validation_status'])}",
                f"- Source: {_visible(_location(source))}",
                f"- Sink: {_visible(_location(sink))}",
                f"- 흐름: {_visible(' → '.join(_location(step) for step in steps) or '경로 없음')}",
                f"- 근거: {_visible(item['evidence_note'])}",
                f"- 메시지: {_visible(item['message'])}",
                f"- 원본: {_visible(item['raw_report'])} 결과 #{item['raw_result_index']}", "",
            ])
        return "\n".join(lines).rstrip() + "\n"

    def save(self, run_dir: Path, report: dict[str, Any]) -> tuple[Path, Path]:
        run_dir.mkdir(parents=True, exist_ok=True)
        json_path = run_dir / "integrated.json"
        markdown_path = run_dir / "integrated.md"
        json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                             encoding="utf-8")
        markdown_path.write_text(self.markdown(report), encoding="utf-8")
        return json_path, markdown_path
