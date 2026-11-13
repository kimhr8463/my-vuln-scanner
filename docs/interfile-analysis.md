# NodeGoat 파일 간 데이터 흐름 검증 (Semgrep CE)

## 범위와 재현 조건

- 대상: NodeGoat `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` (`targets/opensource/javascript/nodegoat`), 소스 수정 없음.
- 엔진: 로컬 Semgrep CLI 1.185.0. 실제 JSON의 `engine_requested`와 각 Finding의 `extra.engine_kind`는 `OSS`였다. Pro 엔진은 실행하지 않았다.
- Rule: 기존 `rules/javascript/nosql_injection.yml`의 `javascript-mongodb-nosql-injection-taint`(taint)와 `javascript-mongodb-dynamic-where-candidate`(구조적 후보). Rule 자체는 수정하지 않았다.
- 축소 재현: `tests/javascript/interfile/`의 독립 디렉터리 7종(동일 파일, 2파일, 3파일, 헬퍼 인자, 숫자 변환 2종, 고정 쿼리). `tests/scanner/test_interfile_analysis.py`가 실제 Semgrep 실행 결과를 검사한다.

## NodeGoat의 호출 및 인자 전달 경로

1. `app/routes/index.js:63`: `GET /allocations/:userId`가 `allocationsHandler.displayAllocations`에 연결된다.
2. `app/routes/allocations.js:11-23`: 핸들러가 `req.params.userId`와 **Source** `req.query.threshold`를 구조 분해하여 `allocationsDAO.getByUserIdAndThreshold(userId, threshold, callback)`에 순서대로 전달한다. DAO import는 같은 파일 1행, 인스턴스 생성은 9행이다.
3. `app/data/allocations-dao.js:57-60`: DAO 메서드의 두 번째 인자 `threshold`가 내부 함수 `searchCriteria`의 클로저 변수로 사용된다. `parseInt(userId)`(58행)는 *userId만* 변환한다.
4. `app/data/allocations-dao.js:62-79`: `threshold`가 참일 때 **Sink 후보** `$where` JavaScript 표현식의 템플릿 리터럴에 그대로 삽입된다(77-79행). `parseInt(threshold, 10)` 및 범위 검사는 63-76행의 **주석**일 뿐 실행되지 않는다.
5. `app/data/allocations-dao.js:86`: `searchCriteria()` 반환 객체가 `allocationsCol.find(...)`에 전달된다. `allocationsCol`은 15행의 `db.collection("allocations")`이다.

따라서 요청 값 → 라우트 핸들러 변수 → DAO 호출의 두 번째 인자 → DAO의 `threshold` 매개변수 → 내부 함수 클로저 → `$where` 문자열 → MongoDB `find` 순서다. 이는 코드상 입력과 sink가 연결된 후보 경로이며, 원격 실행이나 공격 재현은 수행하지 않았다. 기존 독립 조사 분류도 변경하지 않는다.

## CE와 구조적 Rule의 실제 결과

표의 위치는 `tests/javascript/interfile/` 기준이며, 숫자는 원본 Semgrep Finding 수다. 모든 축소 예제는 `engine_requested: OSS`, Finding은 `engine_kind: OSS`였다.

| 예제 | 주요 전달 경로 | taint | 구조적 후보 | 해석 |
| --- | --- | ---: | ---: | --- |
| `same_file/direct.js` | `req.query.threshold` → 지역 변수 → `$where` → `find` | 2 (3, 4행) | 0 | CE가 같은 함수 내부의 직접 흐름을 잡음. 두 sink 위치가 각각 보고됨. |
| `two_file/` | route의 요청 값 → `dao.findByThreshold` → DAO의 `$where` | 0 | 1 (`dao.js:2`) | 후보는 DAO 매개변수의 동적 삽입만 봄. 요청 값과의 연결을 증명하지 않음. |
| `three_file/` | route → service의 `passedThreshold` → DAO | 0 | 1 (`dao.js:2`) | 3파일을 스캔해도 CE taint의 파일 간 추적은 발생하지 않음. |
| `helper_argument/route.js` | 요청 값 → `buildWhere(threshold)` → `find` (한 파일) | 1 (7행) | 1 (2행) | CE는 tainted 인자가 포함된 `find(...)` 호출을 보고하지만, `buildWhere` 내부 `$where`(2행)에 대한 taint Finding은 없음. 호출 위치만으로 헬퍼 내부 흐름을 입증할 수 없음. |
| `sanitized_same_file/route.js` | 요청 값 → `Number.parseInt` → `$where` | 0 | 0 | 현재 Rule의 숫자 변환 sanitizer가 적용됨. |
| `sanitized_two_file/` | 요청 값 → `Number.parseInt` → DAO | 0 | 1 (`dao.js:2`) | 구조적 후보는 호출 측 변환을 볼 수 없어 안전한 경로도 보고할 수 있음. |
| `fixed_query/dao.js` | 사용자 입력 없는 고정 `$where` | 0 | 0 | 고정 쿼리는 미탐. |

NodeGoat 전체 스캔에서도 **taint 0건, 구조적 후보 1건** (`app/data/allocations-dao.js:77`)이었다. 이 1건은 `$where`에 DAO 매개변수가 삽입된다는 경고이며, CE가 `req.query.threshold`부터 `$where`까지 파일 간 taint 경로를 증명했다는 의미가 아니다. 더욱이 NodeGoat의 요청 값은 구조 분해로 읽히므로 현재 Source 패턴의 적용 여부도 별도 검증이 필요하다. 위 2파일/3파일 예제는 직접 `req.query.threshold`를 읽어 파일 경계 효과를 독립적으로 확인했다.

실제 CLI를 `python -m scanner.main scan targets/opensource/javascript/nodegoat --rules rules/javascript --output reports/interfile-ce --format both`로 재실행한 결과, 종료 코드 2와 Finding 1건을 확인했다. `reports/interfile-ce/nodegoat-scan.json` 및 `.md`를 재읽어 `javascript-mongodb-dynamic-where-candidate`, DAO 77행, `CWE-943`이 기록된 것도 확인했다. 생성 보고서는 현재 Rule의 **후보** 결과를 보존한다.

## 엔진 범위와 대안

[Semgrep 공식 용어집](https://semgrep.dev/docs/writing-rules/glossary)은 CE를 파일 단위 분석으로 설명하고, [공식 CE/플랫폼 비교](https://semgrep.dev/products/semgrep-vs-ce)는 CE의 함수 단위 한계를 명시한다. [Semgrep Pro Engine](https://semgrep.dev/products/pro-engine/)은 JavaScript의 파일 간·함수 간 분석을 제공하는 별도 제품 기능이다. 이 환경에서는 Pro를 실행하거나 그 결과를 확인하지 않았으므로, 현 Rule이 Pro에서 NodeGoat 경로를 탐지할지는 미확정이다.

[CodeQL JavaScript 전역 taint 분석 문서](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-javascript-and-typescript/)는 함수 호출을 지나는 경로를 모델링한다. 로컬 `codeql version`은 2.27.1이지만, 이 작업에서는 NodeGoat용 CodeQL 쿼리를 작성·실행하지 않았다. 따라서 CodeQL의 이 사례 탐지 성공을 주장하지 않는다. [CodeQL 사용 조건](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/set-up-codeql-cli)도 별도 확인이 필요하다.

## 한계 및 다음 우선순위

1. 현재 구조적 후보를 검증 전 확정 Finding으로 취급하지 말고, 입력 전달·변환·DB API 여부를 수동 검토한다. 숫자 변환의 파일 간 사례가 구조적 후보의 잠재 오탐을 재현한다.
2. NodeGoat 구조 분해 Source를 별도 축소 예제로 검증하고, 기존 Rule 변경이 허용되는 단계에서 Source 패턴 보완을 검토한다.
3. 파일 간 경로를 실제로 평가하려면 해당 Source/Sink를 명시한 CodeQL 전역 taint 경로 쿼리 또는 허가된 Pro Engine 비교 실험을 별도 수행한다. 단순 파일 간 함수명 연결은 데이터 흐름의 증거가 아니다.

재현 명령: `python -m unittest tests.scanner.test_interfile_analysis -v` 및 `python -m unittest discover -s tests -t . -p 'test_*.py'`. Semgrep이 사용자 홈에 설정 파일을 쓰지 못하는 환경에서는 테스트의 `semgrep_environment`처럼 `SEMGREP_SETTINGS_FILE`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`을 쓰기 가능한 임시 경로로 지정한다.
