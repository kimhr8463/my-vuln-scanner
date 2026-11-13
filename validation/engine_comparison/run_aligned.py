"""Run the narrower command-source and pinned NodeGoat CodeQL experiments."""

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

from scanner.result_parser import ResultParser
from scanner.semgrep_runner import SemgrepRunner
from validation.engine_comparison.run_comparison import (
    BASE, CASES, PROJECT, ROOT, RULE_ID, sarif_locations,
)


COMMAND_QUERY = BASE / "codeql" / "CommandInputToExecAligned.ql"
NOSQL_QUERY = BASE / "codeql" / "NodeGoatThresholdToWhere.ql"
NODEGOAT = ROOT / "targets" / "opensource" / "javascript" / "nodegoat"
NODEGOAT_SHA = "c5cb68a7084e4ae7dcc60e6a98768720a81841e8"
CONTROLS = BASE / "nodegoat_controls"
ALIAS = BASE / "extra_cases" / "alias_destructured.js"
EXTENDED_CASES = {**CASES, "alias_destructured": (ALIAS.name, True)}


def run_command(command: list[str], *, timeout: int = 900, env=None) -> tuple[float, subprocess.CompletedProcess]:
    started = time.perf_counter()
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                               timeout=timeout, env=env)
    return round(time.perf_counter() - started, 3), completed


def checked(command: list[str], *, env=None) -> float:
    seconds, completed = run_command(command, env=env)
    if completed.returncode:
        raise RuntimeError(f"Failed ({completed.returncode}): {' '.join(command)}\n"
                           f"{completed.stderr[-4000:]}\n{completed.stdout[-4000:]}")
    return seconds


def codeql_scan(codeql: str, source: Path, query: Path, output: Path,
                temporary: Path, cache: Path, label: str) -> tuple[dict, list[dict]]:
    database = temporary / f"{label}-db"
    create_seconds = checked([codeql, "database", "create", str(database),
                              "--language=javascript", f"--source-root={source}", "--threads=2"])
    sarif = output / f"{label}.sarif"
    analyze_seconds = checked([codeql, "database", "analyze", str(database), str(query),
                               "--format=sarif-latest", f"--output={sarif}", "--threads=2",
                               f"--common-caches={cache}"])
    return {"database_create": create_seconds, "query_analyze": analyze_seconds}, \
        sarif_locations(json.loads(sarif.read_text(encoding="utf-8")))


def semgrep_scan(target: Path, rules: Path) -> tuple[float, list[dict], list[dict]]:
    raw = SemgrepRunner(rules).scan(target)
    if raw["errors"] or raw.get("engine_requested") != "OSS":
        raise RuntimeError(f"Semgrep CE scan failed: {raw['errors']}")
    findings = ResultParser(raw["scanner_metadata"]["rules"]).parse(raw)
    hits = [{"path": Path(item.file_path).relative_to(target).as_posix(),
             "line": item.start_line, "rule_id": item.rule_id} for item in findings]
    return raw["scanner_metadata"]["elapsed_seconds"], hits, raw["errors"]


def run(output: Path, codeql: str) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    cache = output / "codeql-cache"
    cache.mkdir(exist_ok=True)
    sha = run_command(["git", "-C", str(NODEGOAT), "rev-parse", "HEAD"])[1].stdout.strip()
    if sha != NODEGOAT_SHA:
        raise RuntimeError(f"NodeGoat commit mismatch: {sha}")
    with tempfile.TemporaryDirectory(prefix="scanner-aligned-") as temp_name:
        temporary = Path(temp_name)
        project = temporary / "project"
        shutil.copytree(PROJECT, project)
        shutil.copy2(ALIAS, project / ALIAS.name)
        env = os.environ.copy()
        env.update({
            "PATH": f"{ROOT / '.venv' / 'bin'}:{env.get('PATH', '')}",
            "XDG_CONFIG_HOME": str(temporary), "XDG_CACHE_HOME": str(temporary),
            "SEMGREP_SETTINGS_FILE": str(temporary / "semgrep-settings.yml"),
            "SEMGREP_LOG_FILE": str(temporary / "semgrep.log"),
            "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0",
        })
        with patch.dict(os.environ, env, clear=True):
            semgrep_seconds, semgrep_hits, _ = semgrep_scan(project, ROOT / "rules" / "javascript")
            node_semgrep_seconds, node_semgrep_hits, _ = semgrep_scan(NODEGOAT, ROOT / "rules" / "javascript")
        command_times, command_hits = codeql_scan(codeql, project, COMMAND_QUERY,
                                                   output, temporary, cache, "aligned-command")
        node_times, node_hits = codeql_scan(codeql, NODEGOAT, NOSQL_QUERY,
                                             output, temporary, cache, "nodegoat-where")
        control_times, control_hits = codeql_scan(codeql, CONTROLS, NOSQL_QUERY,
                                                   output, temporary, cache, "where-controls")

    cases = []
    for name, (path, vulnerable) in EXTENDED_CASES.items():
        cases.append({"case": name, "sink_path": path, "expected_vulnerable": vulnerable,
                      "semgrep": [h for h in semgrep_hits if h["rule_id"] == RULE_ID and h["path"] == path],
                      "codeql": [h for h in command_hits if h["path"] == path]})
    report = {
        "nodegoat_commit": sha,
        "source_models": {
            "semgrep": "Existing rule: req.body/query fields, destructuring variants, plus params/argv/prompt",
            "codeql_command": "req parameter body.command or query.command property reads",
            "codeql_nosql": "req parameter query.threshold property read",
        },
        "command": {"seconds": {"semgrep_scan": semgrep_seconds, **command_times},
                    "cases": cases},
        "nodegoat": {"seconds": {"semgrep_scan": node_semgrep_seconds, **node_times},
                     "semgrep_hits": node_semgrep_hits, "codeql_hits": node_hits},
        "nosql_controls": {"seconds": control_times, "codeql_hits": control_hits},
    }
    (output / "aligned-results.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "reports" / "engine-comparison-aligned")
    parser.add_argument("--codeql", default=shutil.which("codeql"))
    args = parser.parse_args()
    if not args.codeql:
        parser.error("CodeQL CLI is not installed or not on PATH")
    result = run(args.output.resolve(), args.codeql)
    print(json.dumps({"command_seconds": result["command"]["seconds"],
                      "nodegoat_seconds": result["nodegoat"]["seconds"],
                      "nodegoat_codeql_hits": result["nodegoat"]["codeql_hits"],
                      "output": str(args.output.resolve() / "aligned-results.json")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
