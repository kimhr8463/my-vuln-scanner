# Express 구조 분해 Source 검증

## 범위

기존 JavaScript Rule을 변경하지 않고 `tests/javascript/destructuring/`에 축소 예제를 추가했다. `tests/scanner/test_destructuring_sources.py`는 JavaScript Rule 전체를 `SemgrepRunner`로 실제 실행하고 `engine_requested: OSS`, Finding별 `engine_kind: OSS`를 확인한다. 아래의 **탐지**는 Source 단독 인식 결과가 아니라 Source에서 각 Rule의 실제 Sink까지 이어진 taint Finding이다. `source_only.js`는 Sink가 없으므로 Finding이 없는 것이 정상이며 Source 인식 실패의 증거가 아니다.

## 결과

| 사례 | Source와 Sink | CE taint | 구조적 후보 | 해석 |
| --- | --- | ---: | ---: | --- |
| `query_direct.js` | `req.query.threshold` → MongoDB `$where` | 1 (3행) | 0 | 직접 접근 대조군. |
| `query_destructured.js` | `const {threshold} = req.query` → `$where` | 1 (3행) | 0 | NoSQL Rule의 `req.query` 전체 객체 Source가 구조 분해 이후 값까지 전파됨. |
| `query_multiline.js` | NodeGoat와 같은 여러 줄 query 구조 분해 → `$where` | 1 (5행) | 0 | 여러 줄 표현도 같은 파일에서는 탐지됨. |
| `alias_destructured.js` | `{threshold: userThreshold} = req.query` → `$where` | 1 (3행) | 0 | 별칭 구조 분해도 NoSQL Rule에서 탐지됨. |
| `body_direct.js` | `req.body.command` → `child_process.exec` | 1 (5행) | 0 | Command Injection Rule의 필드 접근 Source 대조군. |
| `body_destructured.js` | `{command} = req.body` → `child_process.exec` | 0 | 0 | Command Injection Rule에는 `req.body` 전체 객체 Source가 없어 미탐. |
| `body_destructured_nosql.js` | `{command} = req.body` → MongoDB `$where` | 1 (3행) | 0 | 동일 문법을 NoSQL Rule의 `req.body` 전체 객체 Source는 인식함. 문법 자체의 전면적 한계가 아님. |
| `nested_destructured.js` / `nested_destructured_nosql.js` | `{body: {command}} = req` → 각 Sink | 0 | 0 | 기존 패턴에 `req.body`/`req.body.command` 접근식이 없으므로 두 Rule에서 미탐. |
| `fixed.js` | `const threshold = 100` → `$where` | 0 | 0 | 사용자 입력이 없는 고정 값. |
| `source_only.js` | Query·Body 구조 분해만 수행 | 0 | 0 | Sink가 없으므로 Finding 없음. |
| `cross_file/route.js` → `dao.js` | Query 구조 분해 → DAO 인자 → `$where` | 0 | 1 (`dao.js:2`) | 같은 문법의 단일 파일 사례가 taint로 탐지되므로, 여기서는 Source 구조 분해만이 아니라 파일 경계가 중요한 차이. 후보 Rule은 요청에서 DAO까지의 전달을 증명하지 않음. |

실제 고정 NodeGoat의 Source는 `app/routes/allocations.js:19-23`의 여러 줄 `const {threshold} = req.query`이고, Sink 후보는 `app/data/allocations-dao.js:77-86`의 `$where` 및 `find`이다. 이전 `docs/interfile-analysis.md`의 실제 NodeGoat 스캔은 taint 0건, 구조적 후보 1건이었다. 이번 `query_multiline.js` 실험은 **같은 파일의 동등한 Source 문법**이 NoSQL Rule에서 인식됨을 확인한다. 다만 NodeGoat의 전체 코드에는 파일 경계 외에도 DAO 호출·클로저가 있으므로, NodeGoat 미탐 원인을 단 하나로 확정하지 않는다.

## Rule 정의와 개선 판단

- `rules/javascript/nosql_injection.yml`: 필드 접근 Source 외에 `req.query`, `req.body` 전체 객체 Source가 있다. 따라서 직접 query/body 구조 분해 및 query 별칭은 같은 파일에서 탐지됐다. 중첩 구조 분해는 현재 패턴으로 탐지되지 않았다.
- `rules/javascript/command_injection.yml`: `req.body.$FIELD`와 `req.body[$FIELD]`는 있지만 `req.body` 전체 객체 Source는 없다. 직접 접근은 탐지됐고, body 구조 분해는 미탐이었다.
- Rule 변경을 승인받는 후속 작업에서는 body 구조 분해와 중첩 구조 분해의 Source를 좁게 추가하고, 안전한 값·비관련 객체·별칭 사례로 오탐을 함께 검증해야 한다. 전체 객체를 무조건 Source로 늘리면 과도한 taint 전파 가능성이 있으므로 정밀도 평가가 필요하다. 이번 작업에서는 기존 Rule을 수정하지 않았다.

재현: `python -m unittest tests.scanner.test_destructuring_sources -v`. 전체 회귀 테스트는 `python -m unittest discover -s tests -t . -p 'test_*.py'`로 실행한다. Semgrep 설정·캐시는 쓰기 가능한 임시 경로로 지정한다.
