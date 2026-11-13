"""JavaScript 배치 SARIF를 취약·안전 fixture 표식과 대조한다."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from validation.hybrid.engines import QUERIES


FIXTURES = Path(__file__).resolve().parent / "javascript_fixtures"
JAVASCRIPT_QUERIES = {
    "command": QUERIES["command"].query_id,
    "nosql": QUERIES["nosql"].query_id,
}


def expected_locations(fixtures: Path = FIXTURES) -> dict[str, set[tuple[str, int]]]:
    expected = {}
    for name, query_id in JAVASCRIPT_QUERIES.items():
        locations = set()
        for source_file in (fixtures / f"{name}_vulnerable.js", fixtures / f"{name}_service.js"):
            for number, line in enumerate(source_file.read_text(encoding="utf-8").splitlines(), 1):
                if "// vulnerable:" in line:
                    locations.add((source_file.name, number))
        expected[query_id] = locations
    return expected


def compare(payloads: list[dict], fixtures: Path = FIXTURES) -> dict[str, dict]:
    expected = expected_locations(fixtures)
    observed = {query_id: set() for query_id in expected}
    counts = {query_id: 0 for query_id in expected}
    for payload in payloads:
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
                counts[query_id] += 1
    return {
        query_id: {
            "result_count": counts[query_id],
            "detected": sorted(observed[query_id]),
            "missed": sorted(expected[query_id] - observed[query_id]),
            "unexpected": sorted(observed[query_id] - expected[query_id]),
        }
        for query_id in expected
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sarif", type=Path, nargs="+", help="Query별 SARIF 파일")
    args = parser.parse_args()
    summary = compare([json.loads(path.read_text(encoding="utf-8")) for path in args.sarif])
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return int(any(case["missed"] or case["unexpected"] for case in summary.values()))


if __name__ == "__main__":
    raise SystemExit(main())
