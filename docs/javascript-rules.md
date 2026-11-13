# JavaScript Rule 범위와 검증 기록

아래 세 Rule은 `mode: taint`로 사용자 입력에서 위험한 API 인자까지의 데이터 흐름을 검사한다. MongoDB NoSQL Rule은 별도 파일과 [검증 문서](nosql-rule.md)에서 관리한다.

| Rule ID | 취약점 | CWE | 주요 Source | Sink |
| --- | --- | --- | --- | --- |
| `javascript-command-injection-taint` | Command Injection | CWE-78 | `req.query/body/params`, `process.argv`, `prompt` | `child_process.exec`, `execSync` |
| `javascript-sql-injection-taint` | SQL Injection | CWE-89 | `req.query/body/params`, `process.argv`, `prompt` | SQL 텍스트가 확인된 DB 관례 수신자의 `query`, `execute`, `raw` 첫 번째 인자; 직접 생성된 pg/mysql 연결의 쿼리 인자 |
| `javascript-dom-xss-taint` | DOM XSS | CWE-79 | URL 검색어·해시, `URLSearchParams.get`, `prompt`, `req.query` | `innerHTML`, `outerHTML`, `document.write` |

SQL Rule은 요청 입력 `INPUT`과 SQL 문맥 `SQL_TEXT`의 taint label이 함께 첫 번째 인자에 도달해야 일반적인 `query`/`execute`/`raw` 호출을 보고한다. SQL 문맥은 `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `WITH`로 시작하는 문자열/템플릿 리터럴에서 얻으며, 수신자는 `db`, `client`, `pool`, `connection`, `sequelize`, `knex` 등의 관례 이름으로 제한한다. 로컬에서 `new pg.Pool/Client` 또는 `mysql.createConnection/createPool`을 직접 생성한 경우에는 완성된 SQL 문자열을 요청에서 그대로 넘기는 것도 탐지한다. PostgreSQL `query({text, values})` 형식은 객체 전체가 아닌 `text`만 Sink로 검사한다. 따라서 `pool.query("... WHERE id = $1", [req.query.id])`와 `pool.query({text: "... WHERE id = $1", values: [req.query.id]})`처럼 바인딩 값만 오염된 경우는 탐지하지 않는다. Command Injection 안전 예제는 고정 명령어와 `execFile`/`spawn`의 `shell: false`를 포함한다. XSS 안전 예제는 `textContent`와 고정 HTML을 포함한다.

기존 검증 기준은 `tests/javascript/vulnerable/`의 8개 Finding(명령 주입 3, SQL 주입 2, DOM XSS 3)과 `tests/javascript/safe/`의 0개 Finding이다. 추가 SQL Rule fixture `rules/javascript/sql_injection.js`는 Semgrep `test`로 pg·mysql2·Knex·Sequelize의 문자열 연결, 템플릿 리터럴, 중간 변수, 직접 요청 SQL, 바인딩과 일반 객체 호출을 검증한다. 기본 CLI는 Python Rule 4개와 JavaScript Rule 5개를 함께 로드한다.

## 오탐 및 미탐 가능성

- SQL Rule의 수신자 이름은 타입 증명이 아니다. 일반 객체를 `db`나 `pool`이라고 이름 붙이고 SQL 형태 문자열을 넘기면 오탐할 수 있다. 반대로 DB 객체가 다른 이름이거나 별도 파일/함수에서 주입되면 놓칠 수 있다. SQL prefix 목록에 없는 쿼리와 동적으로만 만들어진 쿼리도 미탐 가능하다. 실제 패키지의 데이터베이스 타입·호출 관계를 모두 검증하는 Rule은 아니다.
- Source는 예제에서 확인한 요청 변수 이름 `req` 및 브라우저 전역 객체를 중심으로 정의했다. `request` 같은 다른 이름, 구조 분해된 입력, 별도 모듈에서 전달된 값은 놓칠 수 있다.
- Command Injection은 지정된 `exec`/`execSync` 호출을 다룬다. 구조 분해 import나 별칭, `execFile`/`spawn`의 `shell: true`는 현재 범위 밖이다. 고정 문자열 명령어는 taint가 없어 탐지하지 않는다.
- XSS는 HTML을 쓰는 세 DOM API만 다룬다. `insertAdjacentHTML`, jQuery `.html()`, React의 `dangerouslySetInnerHTML` 등은 별도 Rule이 필요하다. 고정 문자열에서 만든 `URLSearchParams`는 Source로 취급하지 않는다. `DOMPurify.sanitize` 같은 정화 호출을 인식하지 않아 정화 후 HTML Sink에 전달하는 경우 오탐할 수 있다.
- 현재 Semgrep OSS 엔진의 범위에서 검증했으며, 파일 간 데이터 흐름은 보장하지 않는다. [Semgrep의 taint mode 설명](https://semgrep.dev/blog/2022/demystifying-taint-mode/)과 [Semgrep Pro의 파일 간 분석 설명](https://semgrep.dev/blog/2023/the-birth-of-semgrep-pro-engine/)을 참고했다.

SQL Rule 정밀화 이후 고정 NodeGoat 커밋을 기본 CLI로 재검증했다. SQL Finding은 0건, 기존 MongoDB `$where` 구조적 후보는 1건으로 유지됐고 종료 코드는 2였다. Markdown/JSON 재생성 결과와 새 Rule 집합의 해시는 `validation/rule_trials/nodegoat_sql_precision.json`에 기록했다. 기존 독립 조사와 앞선 NoSQL 실험 기록은 변경하지 않았다.
