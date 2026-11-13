# Python CodeQL 4종 단일 실행 검증 (2026-11-13)

## 사용법과 실행 구조

```bash
python -m validation.hybrid.main scan validation/hybrid/python_fixtures \
  --engines both --query python-all --codeql /path/to/codeql \
  --output reports/hybrid-python-batch --timeout 900
```

`--query python-all`은 독립 하이브리드 CLI에만 추가했다. 기존 단일 Query(`command`, `nosql`, `python-command` 등)의 선택과 기본값 `command`는 유지한다. 실행 시 Semgrep은 기존 Python Rule을 그대로 사용한다. CodeQL은 Python DB를 **한 번** 생성한 뒤 Command, SQL, Path, SSRF Query를 같은 DB에서 순차 분석한다. 각 Query의 SARIF와 분석 로그는 `raw/codeql-<query-name>.sarif`, `raw/codeql-<query-name>-analyze.log`에 개별 보존한다. 통합 JSON·Markdown에는 원본 Finding을 모두 유지하고 기존 교차 엔진 Sink 그룹화 정책을 적용한다.

CodeQL Query별 상태는 `success`, `error`, `skipped`, `unavailable` 중 하나로 기록한다. 한 Query가 실패하면 다른 Query를 계속 실행하고, 성공한 Finding과 SARIF를 보존한다. 전체 CodeQL 상태는 일부 실패 시 `partial_error`, DB 생성 실패 시 `error`다. 기존 종료 코드 정책에 따라 부분 실패는 1, 전부 성공하고 Finding이 있으면 2, 전부 성공하고 Finding이 없으면 0이다. DB 생성 실패 시 Query 4종을 `skipped`로 표시한다. Semgrep 단독 실행은 CodeQL 설치·Query 파일에 의존하지 않는다.

## 실제 CLI 결과

CodeQL CLI 2.27.1, Python fixture 대상으로 위 명령을 실제 실행했다. 실행 디렉터리: `reports/hybrid-python-batch/python_fixtures-20261113T052030Z-dbbf2469/`. `raw/codeql-create.log`에 DB 생성 명령이 **1회**, 4개 분석 로그에 모두 같은 DB 경로를 사용하는 분석 명령이 각각 1회 기록됐다. DB 생성 4.958초, CodeQL 전체 172.388초, Semgrep 5.447초. 새 보고서 출력 경로의 Query 캐시가 비어 있던 실행이며, 이 시간은 성능 일반화에 사용하면 안 된다.

| Query | 상태 | Finding | Query 시간(초) | SARIF |
| --- | --- | ---: | ---: | --- |
| `python-command` | success | 4 | 60.776 | `raw/codeql-python-command.sarif` |
| `python-sql` | success | 4 | 34.932 | `raw/codeql-python-sql.sarif` |
| `python-path` | success | 4 | 37.370 | `raw/codeql-python-path.sarif` |
| `python-ssrf` | success | 4 | 34.329 | `raw/codeql-python-ssrf.sarif` |

Semgrep 11건 + CodeQL 16건 = 원본 27건. 교차 엔진 그룹 8개, 전체 그룹 19개, 종료 코드 2. `integrated.json`의 `summary.by_query`와 `engines[].queries`에 각 Query ID·CWE·상태·건수·시간·SARIF 경로를 기록했고, Markdown에도 Query별 표가 있다. 원본 SARIF 4개를 `validation.hybrid.check_python_queries`로 대조한 결과 네 Query 모두 `missed=[]`, `unexpected=[]`였다. Source가 없는 SARIF는 기존 파서 정책대로 미확인으로 보존하며 임의 위치를 추정하지 않는다. 기존 Python Query의 Source/Sink 정의와 fixture는 변경하지 않았다.

이전 검증에서 확인한 숫자 변환 안전 사례에 대한 Semgrep Finding 3건은 이번 통합 보고서에도 그대로 포함된다. 이는 CodeQL 4종의 추가 탐지가 아니며, 기존 Rule 보존 조건 때문에 수정하지 않았다.

## 오류 격리 검증

신규 단위 테스트에서는 SQL Query 분석 오류를 주입했다. DB 생성 1회, Query 실행 시도 4회, SQL 상태 `error`, 나머지 3개 `success`, 성공 Finding 3건, 남은 SARIF·JSON·Markdown 저장, 통합 종료 코드 1을 확인했다. DB 생성 오류를 주입한 테스트에서는 Query 4종 모두 `skipped`로 기록되고 추가 Query 실행이 없었다. 0건 결과를 반환하는 4개 SARIF를 주입했을 때는 보고서가 저장되고 종료 코드 0이었다. 이 오류·0건 사례는 **모의 테스트**이며 실제 CodeQL CLI가 실패하거나 실제 fixture에 Finding이 없었다는 뜻이 아니다.

실행 결과 파일은 기존 `.gitignore` 정책에 따라 로컬에 보존되지만 Git에는 추적되지 않는다. 버전 관리가 필요한 검증 데이터는 별도 아카이브 정책이 필요하다.

전체 회귀 테스트는 `python -m unittest discover -s tests -t .`로 **126개 통과**했다(기존 120개 + 신규 6개). 기존 Scanner, Semgrep Rule, JavaScript Query, Python Query Source/Sink, 독립 조사 기록은 수정하지 않았다. NodeGoat checkout은 고정 커밋 `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` 그대로다.
