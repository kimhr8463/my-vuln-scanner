# Semgrep CE와 CodeQL JavaScript 데이터 흐름 비교

## 실험 범위

공통 대상은 `validation/engine_comparison/project/`의 12개 JavaScript 파일, 9개 사례다. 기존 Scanner 및 Rule을 수정하지 않았다. Semgrep 1.185.0의 실제 `engine_requested`는 `OSS`였다. CodeQL CLI 2.27.1과 `codeql/javascript-all` 2.10.2를 로컬에서 실행했다. 외부 서비스, NodeGoat, PyGoat를 스캔한 결과가 아니다.

Semgrep은 기존 `javascript-command-injection-taint` Rule을 전체 JavaScript Rule과 함께 실행했다. CodeQL은 [`CommandInputToExec.ql`](../validation/engine_comparison/codeql/CommandInputToExec.ql)의 `TaintTracking::Global`을 실행했다. **두 Source 모델은 완전히 같지 않다.** Semgrep은 Rule에 열거된 `req.query/body/params` 필드 접근 및 좁은 구조 분해를 Source로 삼는다. 비교 Query는 이름이 `req`인 함수 매개변수 전체를 Source로 삼아 더 넓다. Sink는 양쪽 모두 `child_process.exec`/`execSync`의 첫 번째 인자다. CodeQL Query에는 `parseInt` 호출 결과를 차단점으로 명시했다.

## 실제 결과

`+`는 해당 Sink 위치의 Finding, `−`는 없음이다. FP/FN 판정은 아래 **인위적 fixture의 의도**에 한정한다. 위치는 대상 프로젝트 기준이다.

| 사례 | Source → Sink / 근거 | Semgrep CE | CodeQL | 관찰 판정 |
| --- | --- | :---: | :---: | --- |
| 동일 파일 직접 | `same_direct.js:3`의 `req.query.command` → `exec` | + | + | 양쪽 TP |
| 동일 파일 중간 변수 | `same_intermediate.js:3-5`의 `req.body.command` → `selected` → `execSync` | + | + | 양쪽 TP |
| 2파일 | `two_file/route.js:3-4` → `dao.run(command)` → `dao.js:3` | − | + | 이 fixture에서 CE FN, CodeQL TP |
| 3파일 | `three_file/route.js:3-4` → `service.js:3-4` → `dao.js:3` | − | + | 이 fixture에서 CE FN, CodeQL TP |
| 동일 파일 함수 인자 | `helper_argument.js:6-7` → `execute(command)` → 3행 `exec` | − | + | 이 fixture에서 CE FN, CodeQL TP |
| body 구조 분해 | `destructured.js:3-4`의 `{command} = req.body` → `exec` | + | + | 양쪽 TP |
| 중첩 구조 분해 | `nested_destructured.js:3-4`의 `{body: {command}} = req` → `exec` | + | + | 양쪽 TP |
| 고정 입력 | `safe_fixed.js:3-4`의 고정 `git status` → `exec` | − | − | 양쪽 TN |
| 숫자 변환 | `safe_numeric.js:3-4`의 `Number.parseInt` → ``echo ${count}`` | + | − | 이 fixture에서 CE FP, CodeQL 미탐 |

숫자 변환 예제의 명령 인자에는 변환 결과(정수 또는 `NaN`)만 삽입되므로 요청 문자열의 셸 메타문자가 보존되지 않는다. 따라서 이 fixture에서 Semgrep Finding은 오탐으로 분류한다. 별도 [`차단점 없는 진단 Query`](../validation/engine_comparison/codeql/CommandInputToExecNoBarrier.ql)도 동일한 7건만 반환하고 `safe_numeric.js`를 탐지하지 못했다. 즉 CodeQL의 미탐을 **명시한 차단점의 효과로 설명할 근거는 없다**. `Number.parseInt` 호출을 통과하는 기본 taint 전파 모델의 한계일 가능성이 있으며, 이 실험으로 일반적인 숫자 검증 처리의 정확도를 입증하지 못한다. 일반적인 검증 함수나 임의의 shell 명령까지 안전하다는 뜻도 아니다.

CodeQL SARIF의 Sink 위치 7개는 `same_direct.js:3`, `same_intermediate.js:5`, `two_file/dao.js:3`, `three_file/dao.js:3`, `helper_argument.js:3`, `destructured.js:4`, `nested_destructured.js:4`였다. Semgrep Command Rule의 위치 5개는 동일 파일 4곳과 `safe_numeric.js:4`였다. 다른 Rule의 추가 Finding은 없었다. 기계 판독용 결과는 [`observed-results.json`](../validation/engine_comparison/observed-results.json)에 보존했다.

## 분석 시간과 한계

동일 프로젝트 전체를 한 번씩 분석했으며 **사례별 시간을 측정하지 않았다**. 독립 재실행 스크립트의 콜드 측정값은 Semgrep 스캔 **2.479초**, CodeQL 데이터베이스 생성 **5.366초**, CodeQL Query 분석 **108.844초**였다. CodeQL 분석 시간에는 첫 컴파일과 평가가 함께 포함되어 Semgrep의 스캔 시간과 같은 단계가 아니다. 이 작은 프로젝트의 단일 콜드 실행만으로 일반적인 속도 우열을 주장할 수 없다.

[CodeQL JavaScript 전역 taint 문서](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-javascript-and-typescript/)는 함수 호출을 지나는 전역 경로를 설명한다. 실제로 이 Query는 위 2·3파일의 `require` 경로를 탐지했다. 반면 [Semgrep 공식 용어집](https://semgrep.dev/docs/writing-rules/glossary)은 CE를 파일 단위 분석으로 설명한다. 이 결과는 현재 Command Rule/CodeQL Query와 fixture의 비교이지, 모든 취약점 유형이나 실제 오픈소스에 대한 엔진 정확도 비교가 아니다. 특히 CodeQL의 `req` 매개변수 Source는 비-Express 객체를 과도하게 taint할 수 있고, 각 엔진의 Rule 모델 품질도 결과에 영향을 준다. Semgrep Pro Engine은 별도 기능이며 실행하지 않았다.

로컬 CodeQL CLI가 실행된다는 사실은 모든 저장소·CI 사용이 무제한 허용된다는 뜻이 아니다. 실제 배포 전에는 [GitHub의 CodeQL 사용 조건](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/set-up-codeql-cli)을 별도로 확인해야 한다.

## 재현

프로젝트 루트에서 `codeql version`, `codeql resolve languages`로 CLI와 JavaScript extractor를 확인한 뒤 다음을 실행한다.

```bash
.venv/bin/python -m validation.engine_comparison.run_comparison --output reports/engine-comparison
```

스크립트는 쓰기 가능한 임시 디렉터리에 CodeQL DB를 생성하고, 지정 출력 디렉터리의 `codeql-cache/`에 컴파일 캐시를 둔다. `comparison.json`과 `codeql.sarif`를 저장하며 Semgrep 결과는 기존 Runner/Parser로 정규화한다. CodeQL이 PATH에 없거나 Query가 실패하면 성공 결과를 만들지 않고 오류를 낸다. 전체 회귀 테스트는 `.venv/bin/python -m unittest discover -s tests -t . -p 'test_*.py'`다.

다음 단계는 Source 모델을 더 가깝게 맞춘 Query, 여러 독립 fixture에서의 오탐 점검, NodeGoat NoSQL 경로용 별도 CodeQL Query다. 현 비교 Query의 성공을 NodeGoat `$where` 흐름 검증으로 확대 해석하지 않는다.
