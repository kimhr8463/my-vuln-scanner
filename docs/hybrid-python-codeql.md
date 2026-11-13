# Python CodeQL 독립 하이브리드 검증 (2026-11-13)

## 변경 범위와 모델

기존 `scanner/`, Semgrep Rule, JavaScript Query, NodeGoat checkout 및 기존 검증 기록은 변경하지 않았다. 독립 하이브리드 프로토타입의 Query 등록에 Python 4종을 추가했다. CodeQL Python 표준 보안 데이터 흐름 구성(`codeql/python-all` 7.2.6)을 재사용하므로 Source/Sink 모델은 기존 Semgrep YAML과 **완전히 동일하지 않다**. 기존 JavaScript Query 키 `command`, `nosql`은 유지한다.

| 선택 키 | CWE | Source | Sink 및 제한 |
| --- | --- | --- | --- |
| `python-command` | CWE-78 | CodeQL 활성 위협 모델의 원격 입력(실험에서는 Flask `request.args/form.get`) | `SystemCommandExecution`의 명령 인자; 실험에서 `os.system`, `subprocess.run(..., shell=True)` |
| `python-sql` | CWE-89 | 동일 | `SqlConstruction` 또는 `SqlExecution`의 SQL 문자열; 실험에서 `sqlite3.Connection.execute`의 첫 인자. 바인딩 값 인자는 Sink가 아님 |
| `python-path` | CWE-22 | 동일 | `FileSystemAccess`의 취약 경로 인자; 실험에서 `open`의 첫 인자. 표준 모델의 정규화·검사 상태를 사용 |
| `python-ssrf` | CWE-918 | 동일 | `Http::Client::Request`의 URL; **전체 URL 제어**가 가능한 흐름만 선택. 실험에서 `requests.get/post` |

Query별 `.ql` 파일은 `validation/hybrid/codeql_python/`에 독립 관리된다. Source는 표준 라이브러리의 `ActiveThreatModelSource`이며, 로컬 `input()`을 포함하는지 이번 fixture로 검증하지 않았다. Sink와 sanitizer의 실제 범위는 설치된 CodeQL 라이브러리 버전에 종속된다. 예를 들어 SQL Query는 SQL *생성* 지점도 Sink로 모델링할 수 있으므로 모든 Finding이 DB 실행까지 도달했다는 의미는 아니다. SSRF Query는 부분 URL 제어를 의도적으로 제외하므로 부분 URL 공격은 미탐 가능성이 있다.

## 재현

로컬 CodeQL CLI 2.27.1 및 `codeql/python-all` 7.2.6이 필요하다. 기존 Python 가상환경 외 추가 Python 의존성은 없다. 아래 분석은 fixture 코드를 실행하지 않고 DB 추출과 정적 Query 평가만 수행한다.

```bash
codeql database create /tmp/my-vuln-python-codeql-db \
  --language=python --source-root=validation/hybrid/python_fixtures --threads=2
codeql database analyze /tmp/my-vuln-python-codeql-db \
  validation/hybrid/codeql_python --format=sarif-latest \
  --output=/tmp/my-vuln-python-codeql-all.sarif --threads=2
python -m validation.hybrid.check_python_queries /tmp/my-vuln-python-codeql-all.sarif

python -m validation.hybrid.main scan validation/hybrid/python_fixtures \
  --engines both --query python-command --codeql /path/to/codeql \
  --output reports/hybrid-python
```

개별 Query는 `--engines codeql --query python-command|python-sql|python-path|python-ssrf`로 실행한다. 각 실행 디렉터리에 `raw/codeql.sarif`, `integrated.json`, `integrated.md`가 저장된다. 하이브리드 원본 SARIF의 `codeFlows`를 공통 Finding으로 변환하며, 경로가 없으면 Source를 임의로 만들지 않는다. 원본 결과는 그룹화 후에도 삭제하지 않는다.

## 실제 실행 결과

CodeQL CLI 2.27.1, Python extractor 7.1.10, Python 3.12.3, `codeql/python-all` 7.2.6. fixture 전체에 대해 네 Query를 한 번에 분석한 SARIF와 개별 CLI 실행을 확인했다. 각 Query 4건, 전체 16건. `check_python_queries`는 4종 모두 `missed=[]`, `unexpected=[]`로 종료 코드 0을 반환했다.

| Query | 동일 파일 직접 | 중간 변수 | 함수 인자 | 2파일 호출 | 고정·안전 변환·Sink 미도달 |
| --- | --- | --- | --- | --- | --- |
| Command | `command.py:10` | `command.py:15` | `command.py:24` | `command_service.py:5` | 0건 |
| SQL | `sql.py:10` | `sql.py:17` | `sql.py:26` | `sql_service.py:6` | 0건 |
| Path | `path.py:8` | `path.py:14` | `path.py:22` | `path_service.py:2` | 0건 |
| SSRF | `ssrf.py:9` | `ssrf.py:15` | `ssrf.py:23` | `ssrf_service.py:5` | 0건 |

안전 사례는 `*_safe.py`에, 취약 사례는 대응하는 기본 파일과 `*_service.py`에 분리했다. 안전 사례에는 고정 입력, 허용목록을 거친 고정값, 숫자 `int()` 변환, SQL 파라미터 바인딩, 입력이 Sink에 도달하지 않는 함수가 포함된다. 이 결과는 fixture 범위에서만 오탐 0건을 의미하며 일반 프로젝트 전체의 정확도를 보장하지 않는다. `request` 객체의 import 줄이 SARIF 경로의 첫 노드로 나오는 경우가 있다. 공통 모델은 이를 CodeQL이 제시한 Source 위치로 보존하며, 실제 `.get()` 호출 위치라고 재해석하지 않는다.

안전 fixture 분리 후 최종 하이브리드 CLI의 Command Query 동시 실행: Semgrep 11건(3.931초), CodeQL 4건(13.441초, Query 캐시 재사용), 통합 15건, 교차 엔진 그룹 2개, 종료 코드 2. CodeQL은 함수 인자 및 2파일 흐름을 탐지했다. Semgrep의 11건 중 숫자 변환된 SQL·Path·SSRF 안전 예제 각 1건(`sql_safe.py:20`, `path_safe.py:20`, `ssrf_safe.py:21`)은 이 fixture 기준 오탐 후보이며, 기존 Rule 보존 조건 때문에 수정하지 않았다. Semgrep Source 위치는 원본 결과에 dataflow trace가 없어서 미확인으로 보존된다. 초기 CodeQL 캐시 없는 실행은 62.883초였다. SQL·Path·SSRF의 최종 개별 CLI 실행도 각각 Finding 4건, 종료 코드 2, SARIF·JSON·Markdown 저장을 확인했다. 개별 CLI 실행 시간은 캐시·병렬 부하에 민감하므로 엔진 성능의 엄밀한 비교치가 아니다.

최종 동시 실행 보고서는 `reports/hybrid-python/python_fixtures-20261113T045907Z-b42de486/`에 있다. 개별 SQL·Path·SSRF 보고서는 각각 `reports/hybrid-python/python_fixtures-20261113T045954Z-bf7c412b/`, `reports/hybrid-python/python_fixtures-20261113T045955Z-42f9661e/`, `reports/hybrid-python/python_fixtures-20261113T045956Z-551e8f54/`에 있다. 이 실행 산출물은 기존 `.gitignore` 정책에 따라 로컬에는 보존되지만 Git에는 추적되지 않는다.

전체 회귀 테스트는 `python -m unittest discover -s tests -t .`로 120개 통과했다. 안전 fixture 분리 검증을 포함하는 신규 테스트 8개는 분리 이후 별도로 재실행해 통과했다. CodeQL SARIF 비교 도구 역시 최종 분리된 fixture에서 미탐 0건·추가 탐지 0건이었다.

## 남은 한계

- Python 표준 CodeQL Source 모델은 Semgrep의 구체적 Flask/Django 패턴보다 넓다. 다른 입력 API와 위협 모델 설정은 아직 테스트하지 않았다.
- CodeQL 표준 Sink 모델의 일부(`SqlConstruction` 등)는 실제 실행 전 단계도 포함한다. 개별 Finding은 코드 리뷰로 확인해야 한다.
- 함수 인자 및 2파일 흐름은 이 fixture에서 확인했다. 동적 import, reflection, 비표준 DB/HTTP 라이브러리, 복잡한 sanitizer, 3파일 이상 경로는 이번 검증 범위 밖이다.
- CodeQL이 없거나 Python Query 파일이 없는 환경에서도 Semgrep 엔진은 독립적으로 실행된다. `both`에서 CodeQL 오류가 나면 보고서를 저장하되 종료 코드는 1이다.
- 현재 CLI는 한 번에 CodeQL Query 하나를 선택한다. 네 종류를 한 실행에서 통합 보고하려면 다중 Query 실행·결과 병합 기능이 후속 작업이다.
