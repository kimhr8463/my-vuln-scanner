# Semgrep CE / CodeQL 하이브리드 프로토타입

이 프로토타입은 기존 `scanner.main`을 대체하지 않는다. 기존 Scanner, Rule, 검증 기록, 고정 오픈소스 소스 및 엔진 비교 결과는 그대로 두고 `validation/hybrid/`에서 독립 실행한다. CodeQL을 설치하지 않아도 기존 Semgrep CLI와 프로토타입의 `--engines semgrep`은 동작한다.

## 구조와 책임

```text
HybridApplication
├─ SemgrepAdapter → 기존 SemgrepRunner / ResultParser → raw/semgrep.json
├─ CodeQLAdapter → DB 생성 / Path Query / SARIF → raw/codeql.sarif
├─ FindingGrouper → 겹치는 Sink의 교차 엔진 그룹
└─ HybridReporter → integrated.json / integrated.md
```

`model.py`의 `HybridFinding`은 Finding ID, 엔진, Rule/Query ID, 유형, CWE, Severity, Confidence, 검증 상태, Source/Sink 위치, 흐름 단계, 원본 인덱스를 가진다. `validation_status`의 기본값은 `UNREVIEWED`이며 탐지 결과를 TP로 자동 판정하지 않는다. SARIF에 `codeFlows`가 있으면 그 위치들을 기록한다. Semgrep `dataflow_trace`가 없거나 CodeQL Query가 경로를 출력하지 않으면 Source는 `null`로 남긴다. 추정한 위치를 사실처럼 채우지 않는다.

두 엔진의 Finding은 모두 독립된 항목으로 유지한다. 같은 CWE·취약점 유형·대상 상대 경로에서 Sink 줄 범위가 겹치고 엔진이 서로 다를 때만 하나의 그룹으로 연결한다. NodeGoat의 Semgrep 구조적 후보(77–79행)와 CodeQL `$where` 값(78행)은 이 기준의 예다. 그룹은 원본 Finding ID만 참조하며 원본을 삭제하지 않는다. 이 기준은 인접하지만 겹치지 않는 Sink를 합치지 않지만, 같은 범위의 별도 취약점을 합칠 가능성은 남아 있어 사람의 검토가 필요하다.

원본 Semgrep JSON, CodeQL SARIF, CodeQL 실행 로그, 통합 JSON/Markdown은 실행별 고유 디렉터리에 저장한다. 통합 JSON은 엔진별 상태와 개별 Finding 및 그룹을 모두 포함한다. CodeQL DB는 임시 디렉터리에 만들고 분석 후 제거하며 Query 컴파일 캐시는 출력 루트의 `.codeql-cache`에 보존한다.

## Query 모델과 한계

- `command`: `req.body.command` 또는 `req.query.command`의 속성 읽기 → `child_process.exec`/`execSync` 첫 인자. 기존 Semgrep Rule은 다른 요청 필드·`req.params`·`process.argv`·`prompt`도 Source로 보므로 Source 모델이 완전히 같지는 않다.
- `nosql`: `req.query.threshold` → `find()` 첫 인자로 전달되는 `$where` 객체의 값. NodeGoat 경로를 겨냥한 Query이며 일반 `find()` 수신자를 MongoDB 컬렉션으로 확정하지 않는다.

두 Query는 기존 비교 Query를 수정하지 않는 별도 `path-problem`이다. CodeQL SARIF의 경로는 Query 모델 안에서 확인된 정적 데이터 흐름이지 실제 악용의 증명이 아니다. [CodeQL 공식 Path Query 형식](https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/)을 사용했다.

SARIF가 한 Finding에 여러 `codeFlows`를 담으면 통합 Finding에는 첫 경로만 표시하고 대안 경로 전체는 원본 SARIF에 유지한다. 같은 표현식이 Source와 Sink인 직접 전달에서는 CodeQL이 `codeFlows`를 내지 않는 경우가 실제로 있었으므로 그 Source는 `null`로 기록했다.

## 실패 및 종료 코드

엔진은 순차적으로 실행하며 다른 엔진의 실패 때문에 완료된 결과를 버리지 않는다. 요청한 엔진 중 하나라도 `error` 또는 `unavailable`이면 통합 보고서를 저장한 뒤 종료 코드 1을 반환한다. 모두 성공하면 Finding 0건은 0, 1건 이상은 2다. CodeQL 미설치 시 `--engines both`는 Semgrep 결과를 보존하되 부분 실행으로 1, `--engines semgrep`은 CodeQL 없이 정상 완료한다. 보고서 저장 자체가 실패하면 1과 오류 메시지를 반환한다. 이 정책은 프로토타입에만 적용되며 기존 `python -m scanner.main scan ...`의 0/1/2 정책은 변경하지 않는다.

## 재현

```bash
.venv/bin/python -m validation.hybrid.main scan validation/engine_comparison/project \
  --engines both --query command --codeql /home/kimhr/tools/codeql/codeql

.venv/bin/python -m validation.hybrid.main scan targets/opensource/javascript/nodegoat \
  --engines both --query nosql --codeql /home/kimhr/tools/codeql/codeql

.venv/bin/python -m validation.hybrid.main scan validation/engine_comparison/project \
  --engines semgrep
```

기본 출력 경로는 `reports/hybrid/`다. `--rules`, `--output`, `--timeout`으로 실험 설정을 바꿀 수 있다. NodeGoat 실험 전에는 대상 HEAD가 `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`인지 확인한다.

## 실제 실행 결과

2026-11-13 로컬 실행. 시간은 엔진 어댑터 전체 경과 시간이며 CodeQL DB 생성·Query 컴파일·캐시 상태를 포함한다. 캐시가 차가운 실행과 따뜻한 실행은 속도 벤치마크로 직접 비교하지 않는다.

| 대상/모드 | Semgrep CE | CodeQL | 원본 Finding | 교차 엔진 그룹 | 종료 코드 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 공통 프로젝트, Semgrep 단독 | 5건 | — | 5 | 0 | 2 |
| 공통 프로젝트, CodeQL 단독 | — | 7건 | 7 | 0 | 2 |
| 공통 프로젝트, 통합 | 5건 | 7건 | 12 | 4 | 2 |
| NodeGoat 고정 커밋, 통합 | 1건 | 1건 | 2 | 1 | 2 |
| JavaScript 안전 fixture, Semgrep 단독 | 0건 | — | 0 | 0 | 0 |
| 공통 프로젝트, CodeQL 미설치 시뮬레이션 | 5건 | unavailable | 5 | 0 | 1 |
| 공통 프로젝트, CodeQL 실행 실패 시뮬레이션 | 5건 | error | 5 | 0 | 1 |
| 공통 프로젝트, Semgrep Rule 경로 오류 | error | 7건 | 7 | 0 | 1 |

공통 프로젝트의 통합 실행 시간은 Semgrep 4.121초, CodeQL 105.730초였다. 같은 Query의 후속 CodeQL 단독 실행은 캐시를 사용해 16.993초였다. NodeGoat 통합 후속 실행은 Semgrep 2.874초, CodeQL 18.447초였다. 공통 프로젝트에서 Semgrep 5건 중 하나는 기존 `safe_numeric.js` 테스트의 숫자 변환 오탐이며, CodeQL은 이를 탐지하지 않았다. 나머지 4건은 같은 Sink에서 두 엔진의 근거를 원본 그대로 그룹화했다. CodeQL만 탐지한 3건은 함수 인자 전달과 2·3파일 흐름이다.

NodeGoat에서는 Semgrep 구조적 후보가 `app/data/allocations-dao.js:77–79`, CodeQL Path Query가 `app/routes/allocations.js:20` → `:23` → `app/data/allocations-dao.js:57` → `:78` 흐름을 기록했다. 두 결과는 Sink 범위가 겹쳐 한 그룹에 속하지만, 구조적 후보를 CodeQL taint 결과와 같은 근거 수준으로 승격하지 않는다. CodeQL SARIF에는 대안 경로 2개가 있고 통합 Finding은 첫 경로를 표시한다. [NodeGoat 통합 JSON](../reports/hybrid/nodegoat-20261113T042706Z-1a73358f/integrated.json), [원본 SARIF](../reports/hybrid/nodegoat-20261113T042706Z-1a73358f/raw/codeql.sarif), [공통 프로젝트 통합 JSON](../reports/hybrid/project-20261113T042150Z-8a1857d4/integrated.json)에서 확인할 수 있다.

기존 `scanner.main`도 별도 실행해 안전 JavaScript fixture 0건/종료 코드 0, 잘못된 경로 종료 코드 1, 공통 프로젝트 5건/종료 코드 2를 확인했다. 정상 스캔의 Markdown/JSON 보고서도 저장됐다. `scanner.main`의 코드나 옵션은 변경하지 않았다.

기존 98개와 하이브리드 신규 14개를 포함한 전체 112개 단위 테스트가 통과했다.

CodeQL 미설치(`--codeql /definitely/missing/codeql`), 실행 실패(`--codeql /bin/false`), Semgrep Rule 경로 오류(`--rules /definitely/missing/rules`)를 별도로 실행했다. 각 경우 실패한 엔진의 단계/오류 메시지와 성공한 엔진의 원본·통합 결과가 함께 저장됐으며 종료 코드는 1이었다.

## 다음 단계

프로토타입 결과가 안정화되면 기존 CLI와 병행하는 명시적 `--engine` 옵션, Python CodeQL Query 등록, Query 메타데이터의 외부 설정화, SARIF 다중 run/다중 경로 보존, 교차 엔진 그룹의 수동 검토 워크플로를 검토한다. 기본 CLI를 자동으로 하이브리드로 바꾸지는 않는다.
