# JavaScript CodeQL 배치 실행 검증 (2026-11-13)

## 지원 범위와 실행

독립 하이브리드 CLI에 `--query javascript-all`을 추가했다. 이 선택은 현재 하이브리드 프로토타입에서 이미 Query와 Source/Sink 정의가 존재하는 아래 **2개만** 실행한다. 기존 단일 Query, `python-all`, Python Query, Semgrep Rule은 수정하지 않았다.

```bash
python -m validation.hybrid.main scan validation/hybrid/javascript_fixtures \
  --engines both --query javascript-all \
  --codeql /home/kimhr/tools/codeql/codeql \
  --output reports/hybrid-javascript-batch
```

| 취약점 | CodeQL Query | Source | Sink | 범위 |
| --- | --- | --- | --- | --- |
| Command Injection (CWE-78) | `CommandFieldToExecPath.ql` | 이름이 `req`인 함수 인자의 `body.command`, `query.command` 읽기 | `child_process.exec`, `execSync`의 첫 인자 | 다른 필드명·명령 실행 API는 이 Query의 검증 범위 밖 |
| MongoDB NoSQL Injection (CWE-943) | `NodeGoatThresholdToWherePath.ql` | 이름이 `req`인 함수 인자의 `query.threshold` 읽기 | `find()` 첫 인자로 전달되는 객체의 `$where` 값 | NodeGoat 경로에 특화됨. `find`의 실제 수신 객체가 MongoDB 컬렉션인지 정적으로 제한하지 않음 |

설치된 CodeQL JavaScript Query 팩에는 SQL Injection, XSS, SSRF, Path 관련 표준 Query가 있지만, 이 하이브리드 프로토타입의 Source/Sink 모델·안전 사례·SARIF 변환 검증을 거친 독립 Query로 등록돼 있지 않다. 따라서 **SQL Injection(CWE-89), DOM XSS(CWE-79), SSRF(CWE-918), Path Traversal(CWE-22)은 이번 CodeQL 배치에서 미지원**이다. 이들의 0건을 안전 판정이나 미탐 확정으로 해석하지 않는다. JavaScript Semgrep Rule의 지원 범위도 CodeQL 배치 범위와 별개다.

Python 배치의 `CodeQLBatchAdapter`를 동일 언어 Query 집합에 재사용하도록 확장했다. JavaScript DB를 실행당 한 번 생성하고 같은 DB로 2개 Query를 순차 실행한다. Query별 SARIF·로그·상태·시간·Finding 수를 보존한다. 한 Query가 실패하면 다음 Query를 계속 실행하고 성공 Finding을 보고서에 유지한다. 부분 실패의 종료 코드는 1이다. 통합 JSON·Markdown과 교차 엔진 그룹화 정책은 기존 방식 그대로다.

## fixture 실제 실행

최종 JavaScript fixture는 각 유형별 `*_vulnerable.js`·`*_service.js`와 `*_safe.js`를 분리했다. 취약 사례는 직접 전달, 중간 변수, 함수 인자, 2파일 흐름 각 1개다. 안전 사례는 고정 입력, 허용목록/숫자 변환, Sink 미도달을 포함한다. CodeQL CLI 2.27.1로 실제 배치 실행했으며 `check_javascript_queries`는 두 Query 모두 `missed=[]`, `unexpected=[]`로 종료 코드 0이었다. fixture 코드는 실행하지 않고 정적 분석만 했다.

최종 실행 디렉터리: `reports/hybrid-javascript-batch/javascript_fixtures-20261113T055926Z-dd9802cd/`.

| Query | 직접 | 중간 변수 | 함수 인자 | 2파일 | 안전 fixture | 분석 시간 |
| --- | --- | --- | --- | --- | --- | ---: |
| Command | `command_vulnerable.js:6` | `:11` | `:19` | `command_service.js:4` | 0건 | 11.397초 |
| NoSQL | `nosql_vulnerable.js:5` | `:11` | `:19` | `nosql_service.js:2` | 0건 | 9.735초 |

실제 `codeql-create.log`에 `--language=javascript` DB 생성 명령 **1회**가 기록됐고, 분석 로그 2개는 같은 DB 경로를 사용한다. DB 생성 5.593초, CodeQL 전체 26.764초, Semgrep 2.929초. 이는 같은 출력 루트의 Query 캐시를 재사용한 시간이며, 첫 캐시 없는 실행의 Query 시간(Command 97.750초, NoSQL 46.062초)과 직접 성능 비교하면 안 된다.

Semgrep 7건 + CodeQL 8건 = 원본 Finding 15건, 교차 엔진 그룹 6개, 전체 그룹 9개, 종료 코드 2. 개별 SARIF는 `raw/codeql-command.sarif`, `raw/codeql-nosql.sarif`에, 통합 결과는 `integrated.json`, `integrated.md`에 저장됐다. Semgrep이 `command_safe.js:17`의 숫자 변환 사례를 탐지한 것은 이 fixture 기준 오탐 후보이며 기존 Rule을 변경하지 않았다. CodeQL은 이를 탐지하지 않았다.

## NodeGoat 고정 커밋 대조

대상 checkout SHA는 `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` 그대로다. 실행 디렉터리: `reports/hybrid-javascript-batch/nodegoat-20261113T060028Z-1f12ea6c/`.

- DB 생성 1회, 6.555초. Command Query 0건/11.509초, NoSQL Query 1건/8.863초. CodeQL 전체 26.957초, Semgrep 2.698초.
- CodeQL SARIF 경로: `app/routes/allocations.js:20` → `:23` → `app/data/allocations-dao.js:57` → `:78`. 기존 독립 조사에서 기록한 `req.query.threshold` → DAO 인자 → `$where` 값과 부합한다.
- Semgrep은 DAO `:77–79`의 구조적 후보 1건을 기록했다. CodeQL Finding의 Sink `:78`과 겹쳐 교차 엔진 그룹 1개가 생겼다. 원본 Finding 2건을 모두 보존하며 기존 조사 분류를 변경하지 않는다. 이 정적 결과를 실제 악용의 증명으로 단정하지 않는다.

## 한계·오류 처리

NoSQL Query는 `req.query.threshold`와 `$where` 객체가 `find()`에 들어가는 형태로 좁혀져 있어 다른 요청 필드·MongoDB API는 놓칠 수 있다. 반대로 임의 객체의 `find()`에 `$where` 객체가 전달돼도 MongoDB 사용 여부를 확인하지 않아 오탐 가능성이 있다. Command Query 역시 지정된 `req` 필드와 두 `child_process` API 외에는 검증하지 않았다. 새로운 유형의 Query를 배치에 자동 추가하지 않으며, Source/Sink와 취약·안전 fixture 검증을 거쳐 등록해야 한다.

모의 테스트에서 NoSQL Query만 실패시켜도 Command 결과·SARIF·통합 보고서가 보존되고 전체 종료 코드 1인 것을 확인했다. 실제 CLI 실행에서는 두 Query 모두 성공했다. 실행 산출물은 로컬 `reports/`에 남지만 기존 `.gitignore`에 따라 Git에는 추적되지 않는다.

전체 회귀 테스트는 `python -m unittest discover -s tests -t .`로 **131개 통과**했다(기존 126개 + 신규 5개). `git diff --check`도 통과했다.
