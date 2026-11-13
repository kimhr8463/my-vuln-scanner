"""엔진에 독립적인 Finding, 실행 상태 및 중복 그룹 모델."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath


@dataclass(frozen=True)
class Location:
    path: str
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        if not self.path or self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("Invalid finding location")


def relative_location(target: Path, path: str, start: int, end: int | None = None) -> Location:
    """절대/상대 엔진 경로를 대상 루트 기준의 한 형식으로 맞춘다."""
    if not isinstance(path, str) or not path:
        raise ValueError("Finding path is missing")
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            normalized = candidate.resolve().relative_to(target.resolve()).as_posix()
        except ValueError as error:
            raise ValueError(f"Finding path is outside target: {path}") from error
    else:
        normalized = PurePosixPath(path.replace("\\", "/")).as_posix()
        if normalized.startswith("../") or normalized in (".", ".."):
            raise ValueError(f"Invalid relative finding path: {path}")
    return Location(normalized, start, end if end is not None else start)


@dataclass(frozen=True)
class HybridFinding:
    finding_id: str
    engine: str
    rule_id: str
    vulnerability: str
    cwe: str
    severity: str
    confidence: str
    validation_status: str
    source: Location | None
    sink: Location
    flow_evidence: tuple[Location, ...]
    evidence_note: str
    message: str
    raw_report: str
    raw_result_index: int


def finding_id(engine: str, rule_id: str, sink: Location, index: int) -> str:
    encoded = json.dumps([engine, rule_id, sink.path, sink.start_line, sink.end_line, index],
                         ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:20]


@dataclass
class QueryRunResult:
    query_name: str
    query_id: str
    status: str
    elapsed_seconds: float
    finding_count: int = 0
    raw_report: str | None = None
    error_stage: str | None = None
    error_message: str | None = None


@dataclass
class EngineResult:
    engine: str
    status: str
    elapsed_seconds: float
    findings: list[HybridFinding] = field(default_factory=list)
    raw_report: str | None = None
    error_stage: str | None = None
    error_message: str | None = None
    database_create_seconds: float | None = None
    queries: list[QueryRunResult] = field(default_factory=list)


@dataclass(frozen=True)
class FindingGroup:
    group_id: str
    member_ids: tuple[str, ...]
    engines: tuple[str, ...]
    vulnerability: str
    cwe: str
    sink_path: str
    start_line: int
    end_line: int


class FindingGrouper:
    """동일 CWE/유형/파일에서 Sink 범위가 겹치는 교차 엔진 결과만 묶는다."""

    @staticmethod
    def _same_sink(left: HybridFinding, right: HybridFinding) -> bool:
        return (
            left.engine != right.engine
            and left.cwe == right.cwe
            and left.vulnerability == right.vulnerability
            and left.sink.path == right.sink.path
            and left.sink.start_line <= right.sink.end_line
            and right.sink.start_line <= left.sink.end_line
        )

    def group(self, findings: list[HybridFinding]) -> list[FindingGroup]:
        parents = list(range(len(findings)))

        def root(index: int) -> int:
            while parents[index] != index:
                parents[index] = parents[parents[index]]
                index = parents[index]
            return index

        for left in range(len(findings)):
            for right in range(left + 1, len(findings)):
                if self._same_sink(findings[left], findings[right]):
                    parents[root(right)] = root(left)

        buckets: dict[int, list[HybridFinding]] = {}
        for index, finding in enumerate(findings):
            buckets.setdefault(root(index), []).append(finding)

        groups = []
        for members in buckets.values():
            first = members[0]
            member_ids = tuple(item.finding_id for item in members)
            digest = hashlib.sha256("|".join(sorted(member_ids)).encode()).hexdigest()[:16]
            groups.append(FindingGroup(
                group_id=f"group-{digest}", member_ids=member_ids,
                engines=tuple(sorted({item.engine for item in members})),
                vulnerability=first.vulnerability, cwe=first.cwe,
                sink_path=first.sink.path,
                start_line=min(item.sink.start_line for item in members),
                end_line=max(item.sink.end_line for item in members),
            ))
        return groups
