"""기존 Semgrep Runner 재사용 및 분리된 CodeQL CLI 어댑터."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import patch

from scanner.result_parser import ResultParser
from scanner.semgrep_runner import SemgrepRunner
from validation.hybrid.model import (
    EngineResult, HybridFinding, Location, QueryRunResult, finding_id, relative_location,
)


ROOT = Path(__file__).resolve().parents[2]
QUERY_ROOT = Path(__file__).resolve().parent / "codeql"
PYTHON_QUERY_ROOT = Path(__file__).resolve().parent / "codeql_python"


@dataclass(frozen=True)
class QuerySpec:
    name: str
    file_path: Path
    query_id: str
    vulnerability: str
    cwe: str
    language: str = "javascript"
    severity: str = "WARNING"
    confidence: str = "MEDIUM"


QUERIES = {
    "command": QuerySpec(
        "command", QUERY_ROOT / "CommandFieldToExecPath.ql",
        "my-vuln-scanner/hybrid-command-field-flow", "Command Injection", "CWE-78",
    ),
    "nosql": QuerySpec(
        "nosql", QUERY_ROOT / "NodeGoatThresholdToWherePath.ql",
        "my-vuln-scanner/hybrid-nodegoat-threshold-where-flow",
        "MongoDB NoSQL Injection", "CWE-943",
    ),
    "python-command": QuerySpec(
        "python-command", PYTHON_QUERY_ROOT / "CommandInjectionPath.ql",
        "my-vuln-scanner/python-command-injection", "Command Injection", "CWE-78",
        language="python", severity="ERROR", confidence="HIGH",
    ),
    "python-sql": QuerySpec(
        "python-sql", PYTHON_QUERY_ROOT / "SqlInjectionPath.ql",
        "my-vuln-scanner/python-sql-injection", "SQL Injection", "CWE-89",
        language="python", severity="ERROR", confidence="HIGH",
    ),
    "python-path": QuerySpec(
        "python-path", PYTHON_QUERY_ROOT / "PathTraversalPath.ql",
        "my-vuln-scanner/python-path-traversal", "Path Traversal", "CWE-22",
        language="python", severity="ERROR", confidence="HIGH",
    ),
    "python-ssrf": QuerySpec(
        "python-ssrf", PYTHON_QUERY_ROOT / "SsrfPath.ql",
        "my-vuln-scanner/python-ssrf", "SSRF", "CWE-918",
        language="python", severity="ERROR", confidence="HIGH",
    ),
}
PYTHON_QUERY_KEYS = ("python-command", "python-sql", "python-path", "python-ssrf")
JAVASCRIPT_QUERY_KEYS = ("command", "nosql")
BATCH_QUERIES = {
    "python-all": PYTHON_QUERY_KEYS,
    "javascript-all": JAVASCRIPT_QUERY_KEYS,
}
BATCH_QUERY_KEY = "python-all"  # 기존 호출자 호환용


def _sarif_location(target: Path, physical: dict[str, Any]) -> Location:
    artifact = physical.get("artifactLocation") or {}
    region = physical.get("region") or {}
    start = region.get("startLine")
    end = region.get("endLine", start)
    if type(start) is not int or type(end) is not int:
        raise ValueError("SARIF result has no valid line number")
    return relative_location(target, artifact.get("uri", ""), start, end)


def parse_sarif(payload: dict[str, Any], target: Path, query: QuerySpec,
                raw_report: str) -> list[HybridFinding]:
    """SARIF path-problem의 원본 인덱스와 Source→Sink 경로를 보존한다."""
    runs = payload.get("runs")
    if not isinstance(runs, list):
        raise ValueError("Invalid CodeQL SARIF: runs must be a list")
    findings = []
    raw_index = 0
    for run in runs:
        results = run.get("results", [])
        if not isinstance(results, list):
            raise ValueError("Invalid CodeQL SARIF: results must be a list")
        for result in results:
            if result.get("ruleId") != query.query_id:
                raise ValueError(f"Unexpected CodeQL query ID: {result.get('ruleId')}")
            locations = result.get("locations") or []
            if not locations:
                raise ValueError("CodeQL result has no sink location")
            sink = _sarif_location(target, locations[0]["physicalLocation"])
            flow_paths: list[tuple[Location, ...]] = []
            for code_flow in result.get("codeFlows") or []:
                for thread_flow in code_flow.get("threadFlows") or []:
                    path_steps: list[Location] = []
                    for entry in thread_flow.get("locations") or []:
                        physical = (entry.get("location") or {}).get("physicalLocation")
                        if physical:
                            step = _sarif_location(target, physical)
                            if not path_steps or step != path_steps[-1]:
                                path_steps.append(step)
                    if path_steps:
                        flow_paths.append(tuple(path_steps))
            representative = flow_paths[0] if flow_paths else ()
            source = representative[0] if representative else None
            note = (
                f"CodeQL SARIF codeFlows의 {len(flow_paths)}개 경로 중 첫 경로를 표시; "
                "모든 대안 경로는 원본 SARIF에 보존됨."
                if flow_paths else
                "CodeQL taint Query 결과이나 SARIF에 경로가 없어 Source 위치는 미확인."
            )
            message = (result.get("message") or {}).get("text", "")
            findings.append(HybridFinding(
                finding_id=finding_id("codeql", query.query_id, sink, raw_index),
                engine="codeql", rule_id=query.query_id,
                vulnerability=query.vulnerability, cwe=query.cwe,
                severity=query.severity, confidence=query.confidence,
                validation_status="UNREVIEWED", source=source, sink=sink,
                flow_evidence=representative, evidence_note=note,
                message=message, raw_report=raw_report, raw_result_index=raw_index,
            ))
            raw_index += 1
    return findings


def _semgrep_trace_locations(trace: Any, target: Path) -> list[Location]:
    locations: list[Location] = []

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            start = node.get("start")
            end = node.get("end") or {}
            if isinstance(start, dict) and type(start.get("line")) is int and node.get("path"):
                try:
                    location = relative_location(target, node["path"],
                                                 start["line"], end.get("line", start["line"]))
                    if location not in locations:
                        locations.append(location)
                except (ValueError, TypeError):
                    pass
            for value in node.values():
                visit(value)
        elif isinstance(node, list):
            for value in node:
                visit(value)

    visit(trace)
    return locations


def parse_semgrep(raw: dict[str, Any], target: Path, raw_report: str) -> list[HybridFinding]:
    parser = ResultParser(raw["scanner_metadata"]["rules"])
    normalized = parser.parse(raw)
    raw_results = raw.get("results", [])
    findings = []
    for finding in normalized:
        raw_index = next((index for index, result in enumerate(raw_results)
                          if isinstance(result, dict)
                          and str(result.get("check_id", "")).endswith(finding.rule_id)
                          and result.get("path") == finding.file_path
                          and (result.get("start") or {}).get("line") == finding.start_line), None)
        if raw_index is None:
            raise ValueError(f"Unable to locate original Semgrep result: {finding.rule_id}")
        sink = relative_location(target, finding.file_path,
                                 finding.start_line, finding.end_line)
        trace = ((raw_results[raw_index].get("extra") or {}).get("dataflow_trace"))
        steps = _semgrep_trace_locations(trace, target) if trace else []
        source = steps[0] if steps else None
        note = (
            "Semgrep dataflow_trace 위치를 보존함." if steps else
            "원본 Semgrep 결과에 Source 경로가 없어 Source 위치는 미확인; 구조적 후보일 수 있음."
        )
        findings.append(HybridFinding(
            finding_id=finding_id("semgrep_ce", finding.rule_id, sink, raw_index),
            engine="semgrep_ce", rule_id=finding.rule_id,
            vulnerability=finding.vulnerability, cwe=finding.cwe,
            severity=finding.severity, confidence=finding.confidence,
            validation_status="UNREVIEWED", source=source, sink=sink,
            flow_evidence=tuple(steps), evidence_note=note,
            message=finding.message, raw_report=raw_report,
            raw_result_index=raw_index,
        ))
    return findings


class EngineAdapter(ABC):
    name: str

    @abstractmethod
    def run(self, target: Path, raw_dir: Path) -> EngineResult:
        """한 엔진을 실행하고 결과 또는 엔진별 오류를 반환한다."""


class SemgrepAdapter(EngineAdapter):
    name = "semgrep_ce"

    def __init__(self, rules_dir: Path, timeout: int = 300):
        self.rules_dir = rules_dir
        self.timeout = timeout

    def run(self, target: Path, raw_dir: Path) -> EngineResult:
        started = time.perf_counter()
        report_name = "raw/semgrep.json"
        destination = raw_dir / "semgrep.json"
        env = os.environ.copy()
        local_bin = ROOT / ".venv" / "bin"
        if not shutil.which("semgrep") and (local_bin / "semgrep").is_file():
            env["PATH"] = f"{local_bin}:{env.get('PATH', '')}"
        env.update({
            "SEMGREP_SETTINGS_FILE": str(raw_dir / "semgrep-settings.yml"),
            "SEMGREP_LOG_FILE": str(raw_dir / "semgrep.log"),
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
        })
        try:
            with patch.dict(os.environ, env, clear=True):
                raw = SemgrepRunner(self.rules_dir, timeout=self.timeout).scan(
                    target, output_path=destination)
            if raw.get("errors"):
                raise RuntimeError(f"Semgrep reported errors: {raw['errors']}")
            findings = parse_semgrep(raw, target, report_name)
            return EngineResult(self.name, "success", round(time.perf_counter() - started, 3),
                                findings, report_name)
        except (OSError, ValueError, TypeError, KeyError, RuntimeError, TimeoutError) as error:
            return EngineResult(self.name, "error", round(time.perf_counter() - started, 3),
                                raw_report=report_name if destination.exists() else None,
                                error_stage="scan_or_parse", error_message=str(error))


class CodeQLAdapter(EngineAdapter):
    name = "codeql"

    def __init__(self, query: QuerySpec, codeql: str | None = None,
                 timeout: int = 900, cache_dir: Path | None = None):
        self.query = query
        self.codeql = codeql
        self.timeout = timeout
        self.cache_dir = cache_dir

    def _execute(self, command: list[str], log: Path, stage: str) -> None:
        try:
            result = subprocess.run(command, capture_output=True, text=True,
                                    timeout=self.timeout, cwd=ROOT, check=False)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(f"CodeQL {stage} timed out after {self.timeout}s") from error
        log.write_text(f"$ {' '.join(command)}\nexit={result.returncode}\n"
                       f"STDOUT\n{result.stdout}\nSTDERR\n{result.stderr}\n",
                       encoding="utf-8")
        if result.returncode:
            detail = result.stderr[-1500:].strip() or result.stdout[-1500:].strip()
            if not detail:
                detail = f"no diagnostic output; see raw/{log.name}"
            raise RuntimeError(f"CodeQL {stage} failed ({result.returncode}): "
                               f"{detail}")

    def run(self, target: Path, raw_dir: Path) -> EngineResult:
        started = time.perf_counter()
        binary = shutil.which(self.codeql) if self.codeql else shutil.which("codeql")
        if binary is None:
            return EngineResult(self.name, "unavailable", 0.0, error_stage="availability",
                                error_message="CodeQL CLI is not installed or not executable")
        if not self.query.file_path.is_file():
            return EngineResult(self.name, "error", 0.0, error_stage="configuration",
                                error_message=f"CodeQL query not found: {self.query.file_path}")
        raw_name = "raw/codeql.sarif"
        sarif = raw_dir / "codeql.sarif"
        cache = self.cache_dir or raw_dir / "codeql-cache"
        cache.mkdir(parents=True, exist_ok=True)
        stage = "database_create"
        try:
            with tempfile.TemporaryDirectory(prefix="scanner-hybrid-codeql-") as temp_name:
                database = Path(temp_name) / "database"
                self._execute([
                    binary, "database", "create", str(database),
                    f"--language={self.query.language}", f"--source-root={target}", "--threads=2",
                ], raw_dir / "codeql-create.log", stage)
                stage = "query_analyze"
                self._execute([
                    binary, "database", "analyze", str(database), str(self.query.file_path),
                    "--format=sarif-latest", f"--output={sarif}", "--threads=2",
                    f"--common-caches={cache}",
                ], raw_dir / "codeql-analyze.log", stage)
            stage = "sarif_parse"
            payload = json.loads(sarif.read_text(encoding="utf-8"))
            findings = parse_sarif(payload, target, self.query, raw_name)
            return EngineResult(self.name, "success", round(time.perf_counter() - started, 3),
                                findings, raw_name)
        except (OSError, ValueError, KeyError, TypeError, RuntimeError, json.JSONDecodeError) as error:
            return EngineResult(self.name, "error", round(time.perf_counter() - started, 3),
                                raw_report=raw_name if sarif.exists() else None,
                                error_stage=stage, error_message=str(error))


class CodeQLBatchAdapter(CodeQLAdapter):
    """동일 언어 Query 여러 개를 한 CodeQL DB에서 순차 실행하고 오류를 격리한다."""

    def __init__(self, queries: tuple[QuerySpec, ...], codeql: str | None = None,
                 timeout: int = 900, cache_dir: Path | None = None):
        if not queries or any(query.language != queries[0].language for query in queries):
            raise ValueError("CodeQL batch requires queries of one language")
        if len({query.name for query in queries}) != len(queries):
            raise ValueError("CodeQL batch query names must be unique")
        super().__init__(queries[0], codeql, timeout, cache_dir)
        self.queries = queries

    def run(self, target: Path, raw_dir: Path) -> EngineResult:
        started = time.perf_counter()
        binary = shutil.which(self.codeql) if self.codeql else shutil.which("codeql")
        if binary is None:
            return EngineResult(
                self.name, "unavailable", 0.0, error_stage="availability",
                error_message="CodeQL CLI is not installed or not executable",
                queries=[QueryRunResult(query.name, query.query_id, "unavailable", 0.0,
                                        error_stage="availability") for query in self.queries],
            )
        cache = self.cache_dir or raw_dir / "codeql-cache"
        cache.mkdir(parents=True, exist_ok=True)
        findings: list[HybridFinding] = []
        query_results: list[QueryRunResult] = []
        create_started = time.perf_counter()
        with tempfile.TemporaryDirectory(prefix="scanner-hybrid-codeql-") as temp_name:
            database = Path(temp_name) / "database"
            try:
                self._execute([
                    binary, "database", "create", str(database),
                    f"--language={self.query.language}", f"--source-root={target}", "--threads=2",
                ], raw_dir / "codeql-create.log", "database_create")
            except (OSError, RuntimeError) as error:
                elapsed = round(time.perf_counter() - started, 3)
                return EngineResult(
                    self.name, "error", elapsed, error_stage="database_create",
                    error_message=str(error), database_create_seconds=elapsed,
                    queries=[QueryRunResult(query.name, query.query_id, "skipped", 0.0,
                                            error_stage="database_create",
                                            error_message="CodeQL database creation failed")
                             for query in self.queries],
                )
            create_seconds = round(time.perf_counter() - create_started, 3)
            for query in self.queries:
                query_started = time.perf_counter()
                raw_name = f"raw/codeql-{query.name}.sarif"
                sarif = raw_dir / f"codeql-{query.name}.sarif"
                stage = "configuration"
                try:
                    if not query.file_path.is_file():
                        raise RuntimeError(f"CodeQL query not found: {query.file_path}")
                    stage = "query_analyze"
                    self._execute([
                        binary, "database", "analyze", str(database), str(query.file_path),
                        "--format=sarif-latest", f"--output={sarif}", "--threads=2",
                        f"--common-caches={cache}",
                    ], raw_dir / f"codeql-{query.name}-analyze.log", stage)
                    stage = "sarif_parse"
                    payload = json.loads(sarif.read_text(encoding="utf-8"))
                    parsed = parse_sarif(payload, target, query, raw_name)
                    findings.extend(parsed)
                    query_results.append(QueryRunResult(
                        query.name, query.query_id, "success",
                        round(time.perf_counter() - query_started, 3), len(parsed), raw_name,
                    ))
                except (OSError, ValueError, KeyError, TypeError, RuntimeError,
                        json.JSONDecodeError) as error:
                    query_results.append(QueryRunResult(
                        query.name, query.query_id, "error",
                        round(time.perf_counter() - query_started, 3),
                        raw_report=raw_name if sarif.exists() else None,
                        error_stage=stage, error_message=str(error),
                    ))
        failed = sum(result.status != "success" for result in query_results)
        status = "success" if not failed else "partial_error" if failed < len(query_results) else "error"
        return EngineResult(
            self.name, status, round(time.perf_counter() - started, 3), findings,
            error_stage="query_execution" if failed else None,
            error_message=f"{failed}/{len(query_results)} CodeQL queries failed" if failed else None,
            database_create_seconds=create_seconds, queries=query_results,
        )
