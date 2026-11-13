"""실제 Python CodeQL SARIF를 fixture의 취약/안전 표식과 대조한다."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from validation.hybrid.engines import QUERIES


ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "python_fixtures"
PYTHON_QUERIES = {
    "command": QUERIES["python-command"].query_id,
    "sql": QUERIES["python-sql"].query_id,
    "path": QUERIES["python-path"].query_id,
    "ssrf": QUERIES["python-ssrf"].query_id,
}


def expected_locations(fixtures: Path = FIXTURES) -> dict[str, set[tuple[str, int]]]:
    expected = {}
    for name, query_id in PYTHON_QUERIES.items():
        locations = set()
        for source_file in (fixtures / f"{name}.py", fixtures / f"{name}_service.py"):
            for number, line in enumerate(source_file.read_text(encoding="utf-8").splitlines(), 1):
                if "# vulnerable:" in line:
                    locations.add((source_file.name, number))
        expected[query_id] = locations
    return expected


def observed_locations(payload: dict) -> dict[str, set[tuple[str, int]]]:
    observed = {query_id: set() for query_id in PYTHON_QUERIES.values()}
    for run in payload.get("runs", []):
        for result in run.get("results", []):
            query_id = result.get("ruleId")
            if query_id not in observed:
                continue
            physical = result["locations"][0]["physicalLocation"]
            observed[query_id].add((
                Path(physical["artifactLocation"]["uri"]).name,
                physical["region"]["startLine"],
            ))
    return observed


def compare(payload: dict, fixtures: Path = FIXTURES) -> dict[str, dict[str, list[tuple[str, int]]]]:
    expected = expected_locations(fixtures)
    observed = observed_locations(payload)
    return {
        query_id: {
            "detected": sorted(observed[query_id]),
            "missed": sorted(expected[query_id] - observed[query_id]),
            "unexpected": sorted(observed[query_id] - expected[query_id]),
        }
        for query_id in expected
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sarif", type=Path, nargs="+",
                        help="4종 통합 SARIF 하나 또는 Query별 SARIF 네 파일")
    args = parser.parse_args()
    payload = {"runs": []}
    for path in args.sarif:
        payload["runs"].extend(json.loads(path.read_text(encoding="utf-8"))["runs"])
    summary = compare(payload)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return int(any(case["missed"] or case["unexpected"] for case in summary.values()))


if __name__ == "__main__":
    raise SystemExit(main())
