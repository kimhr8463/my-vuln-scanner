"""동일한 JavaScript fixture를 Semgrep CE와 CodeQL로 분석한다."""

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from scanner.result_parser import ResultParser
from scanner.semgrep_runner import SemgrepRunner


ROOT = Path(__file__).resolve().parents[2]
BASE = Path(__file__).resolve().parent
PROJECT = BASE / "project"
QUERY = BASE / "codeql" / "CommandInputToExec.ql"
RULE_ID = "javascript-command-injection-taint"
CASES = {
    "same_direct": ("same_direct.js", True),
    "same_intermediate": ("same_intermediate.js", True),
    "two_file": ("two_file/dao.js", True),
    "three_file": ("three_file/dao.js", True),
    "helper_argument": ("helper_argument.js", True),
    "destructured": ("destructured.js", True),
    "nested_destructured": ("nested_destructured.js", True),
    "safe_fixed": ("safe_fixed.js", False),
    "safe_numeric": ("safe_numeric.js", False),
}


def timed_command(command: list[str], *, timeout: int = 600) -> tuple[float, str]:
    start = time.perf_counter()
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    duration = round(time.perf_counter() - start, 3)
    if result.returncode:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(command)}\n"
            f"{result.stderr[-4000:]}\n{result.stdout[-4000:]}"
        )
    return duration, result.stdout.strip()


def sarif_locations(payload: dict) -> list[dict]:
    locations = []
    for run in payload["runs"]:
        for result in run.get("results", []):
            physical = result["locations"][0]["physicalLocation"]
            locations.append({
                "path": physical["artifactLocation"]["uri"],
                "line": physical["region"]["startLine"],
                "rule_id": result["ruleId"],
            })
    return locations


def build_cases(semgrep: list[dict], codeql: list[dict]) -> list[dict]:
    rows = []
    for name, (sink_path, expected_vulnerable) in CASES.items():
        semgrep_hits = [item for item in semgrep if item["path"] == sink_path]
        codeql_hits = [item for item in codeql if item["path"] == sink_path]
        rows.append({
            "case": name,
            "sink_path": sink_path,
            "expected_vulnerable": expected_vulnerable,
            "semgrep_detected": bool(semgrep_hits),
            "codeql_detected": bool(codeql_hits),
            "semgrep_locations": semgrep_hits,
            "codeql_locations": codeql_hits,
        })
    return rows


def run(output: Path, codeql: str) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    cache = output / "codeql-cache"
    cache.mkdir(exist_ok=True)
    codeql_version = timed_command([codeql, "version"])[1].splitlines()[0]

    with tempfile.TemporaryDirectory(prefix="scanner-engine-comparison-") as temporary:
        temporary_path = Path(temporary)
        os.environ.update({
            "PATH": f"{ROOT / '.venv' / 'bin'}:{os.environ.get('PATH', '')}",
            "XDG_CONFIG_HOME": str(temporary_path),
            "XDG_CACHE_HOME": str(temporary_path),
            "SEMGREP_SETTINGS_FILE": str(temporary_path / "semgrep-settings.yml"),
            "SEMGREP_LOG_FILE": str(temporary_path / "semgrep.log"),
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
        })
        semgrep_version = timed_command([str(ROOT / ".venv" / "bin" / "semgrep"), "--version"])[1]
        raw = SemgrepRunner(ROOT / "rules" / "javascript").scan(PROJECT)
        if raw["errors"] or raw.get("engine_requested") != "OSS":
            raise RuntimeError(f"Semgrep CE scan failed: {raw['errors']}")
        parsed = ResultParser(raw["scanner_metadata"]["rules"]).parse(raw)
        semgrep_hits = [
            {"path": Path(item.file_path).relative_to(PROJECT).as_posix(),
             "line": item.start_line, "rule_id": item.rule_id}
            for item in parsed if item.rule_id == RULE_ID
        ]

        database = temporary_path / "codeql-db"
        create_seconds, _ = timed_command([
            codeql, "database", "create", str(database), "--language=javascript",
            f"--source-root={PROJECT}", "--threads=2",
        ])
        sarif_path = output / "codeql.sarif"
        analyze_seconds, _ = timed_command([
            codeql, "database", "analyze", str(database), str(QUERY),
            "--format=sarif-latest", f"--output={sarif_path}", "--threads=2",
            f"--common-caches={cache}",
        ])
        codeql_hits = sarif_locations(json.loads(sarif_path.read_text(encoding="utf-8")))

    known_paths = {path for path, _ in CASES.values()}
    unexpected = {
        "semgrep": [item for item in semgrep_hits if item["path"] not in known_paths],
        "codeql": [item for item in codeql_hits if item["path"] not in known_paths],
    }
    report = {
        "project": str(PROJECT),
        "versions": {"semgrep": semgrep_version, "codeql": codeql_version},
        "source_models": {
            "semgrep": "Existing JavaScript Command Injection Rule sources",
            "codeql": "Any function parameter named req; broader than Semgrep field patterns",
        },
        "sink": "child_process.exec/execSync first argument",
        "codeql_barrier": "parseInt call result",
        "seconds": {
            "semgrep_scan": raw["scanner_metadata"]["elapsed_seconds"],
            "codeql_database_create": create_seconds,
            "codeql_analyze": analyze_seconds,
        },
        "cases": build_cases(semgrep_hits, codeql_hits),
        "unexpected": unexpected,
    }
    (output / "comparison.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "reports" / "engine-comparison")
    parser.add_argument("--codeql", default=shutil.which("codeql"))
    args = parser.parse_args()
    if not args.codeql:
        parser.error("CodeQL CLI is not installed or not on PATH")
    result = run(args.output.resolve(), args.codeql)
    print(json.dumps({
        "seconds": result["seconds"],
        "semgrep_cases": [row["case"] for row in result["cases"] if row["semgrep_detected"]],
        "codeql_cases": [row["case"] for row in result["cases"] if row["codeql_detected"]],
        "output": str(args.output.resolve() / "comparison.json"),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
