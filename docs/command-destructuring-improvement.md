# JavaScript Command Injection 구조 분해 Source 개선

## 변경 범위와 방법

`rules/javascript/command_injection.yml`의 기존 직접 필드 Source와 `child_process.exec`/`execSync` Sink는 유지했다. 새 취약·안전 재현 예제를 먼저 작성해 Semgrep CE(OSS)로 실행했을 때 직접 필드 2건만 탐지되고 구조 분해 5건은 빠지는 것을 확인했다. 그 후 구조 분해 Source 패턴을 추가했다. NoSQL·SQL·Python Rule, 독립 조사 기록, 고정 NodeGoat 소스는 변경하지 않았다.

추가 Source는 `req`를 매개변수로 받는 함수 선언·`const` 화살표 함수·멤버 할당 화살표 함수 안의 다음 구조 분해에만 적용된다.

- `const {$FIELD} = req.body` — 바인딩 변수에 Source를 맞춤.
- `const {$FIELD: $VALUE} = req.body` — 별칭 선언 안의 `req.body`를 Source로 맞춤.
- `const {body: {$FIELD}} = req` — 중첩 구조 분해의 바인딩 변수에 Source를 맞춤.
- `const {body: {$FIELD: $VALUE}} = req` — 중첩 별칭 선언 안의 `req`를 Source로 맞춤.

이는 `req.body`나 `req`를 모든 사용 위치에서 무조건 Source로 추가한 방식이 아니다. 별칭 바인딩을 `focus-metavariable`로 직접 Source 처리하는 방식은 실제 CE에서 패턴은 매치하지만 taint가 Sink까지 전파되지 않았다. 선언으로 범위를 제한해 우변을 Source로 삼는 방식은 전파됐으며, `req` 매개변수 조건을 추가하기 전에는 로컬 고정 객체가 우연히 `req`라는 이름을 가진 경우 오탐이 발생했다. 현재 조건에서는 그 예제가 미탐된다.

## Semgrep CE 실측 결과

`tests/scanner/test_command_destructuring.py`는 Semgrep Runner로 두 fixture 디렉터리를 실제 스캔한다. 두 스캔의 `engine_requested`와 Finding의 `engine_kind`는 모두 `OSS`였다.

| 취약 예제 | Sink | 결과 |
| --- | --- | --- |
| `req.body.command` 직접 접근 | `exec` | 탐지 |
| `req.query.command` 직접 접근 | `execSync` | 탐지 |
| `{command} = req.body` | `exec` | 탐지 |
| `{command: userCommand} = req.body` | `execSync` | 탐지 |
| `{body: {command}} = req` | `exec` | 탐지 |
| 구조 분해 → 중간 변수 → `exec` | `exec` | 탐지 |
| 중첩 별칭 → `require("child_process").execSync` | `execSync` | 탐지 |
| `const` 화살표 핸들러의 body 구조 분해 | `exec` | 탐지 |
| 멤버 할당 화살표 핸들러의 중첩 별칭 | `execSync` | 탐지 |

취약 예제 9건은 각각 정확히 1개 Finding이었다. 안전 예제 8개 파일(고정 명령, 입력과 무관한 상수, 입력 검사 후 두 고정 명령 중 선택, 일반 객체의 단순·중첩 구조 분해, Sink 없는 요청 입력, 고정 로컬 `req` 객체의 단순·중첩 구조 분해)은 모두 Finding 0건이었다. 기존 JavaScript Rule의 직접 접근·CLI 테스트도 통과했다.

전체 JavaScript Rule을 지정한 실제 CLI 실행에서도 취약 fixture는 종료 코드 2, Command Injection 9건(CWE-78 9건), 안전 fixture는 종료 코드 0, Finding 0건이었다. 두 경우 모두 Markdown·JSON 보고서를 저장했고 JSON을 재읽어 건수와 Rule ID를 확인했다. 생성 위치는 `/tmp/my-vuln-scanner-command-cli-reports/`이다.

기존 `tests/scanner/test_destructuring_sources.py`의 body·중첩 구조 분해 미탐 기대값은 이 개선 뒤 탐지 기대값으로 갱신했다. 테스트 수는 줄이지 않았다. `docs/destructuring-sources.md`는 변경 **전**의 관찰 기록으로 보존한다.

## 남은 한계

- 구조 분해 패턴은 `const`와 위의 함수 형태를 대상으로 한다. `let`/`var`, 기본값·rest 문법, 매개변수 자체의 구조 분해, 다른 이름의 요청 객체 등은 이번 실험에서 보장하지 않는다.
- 별칭 패턴은 선언의 요청 객체를 Source로 사용하므로 같은 구조 분해에서 여러 필드를 받으면 다른 필드로도 taint가 퍼질 수 있다. `req` 매개변수라는 이름만으로 실제 Express 객체임을 증명할 수 없고, CE는 호출자에서 안전하게 구성된 객체인지 파일 간 확인할 수 없다.
- 검증된 명령을 실행하는 안전 예제는 실제로 Sink에 고정 문자열만 전달했다. 사용자 문자열 자체를 검사한 뒤 실행하는 더 복잡한 검증 로직은 추가 검토가 필요하다.
- Semgrep CE의 파일 간 taint 한계는 변하지 않는다. 이번 개선은 동일 파일의 Source 인식 범위만 넓힌다.

재현: `python -m unittest tests.scanner.test_command_destructuring tests.scanner.test_destructuring_sources -v`. 전체 회귀 테스트: `python -m unittest discover -s tests -t . -p 'test_*.py'`.
