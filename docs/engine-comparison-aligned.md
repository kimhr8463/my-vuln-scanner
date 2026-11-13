# 좁힌 Source 모델과 NodeGoat `$where` 파일 간 흐름 실험

기존 [엔진 비교](engine-comparison.md), `validation/engine_comparison/observed-results.json`, Scanner/Rule 및 NodeGoat 고정 소스는 변경하지 않았다. 이 문서는 별도의 Query와 fixture를 사용한 후속 실험이다. CodeQL 2.27.1과 Semgrep CE 1.185.0의 결과는 `validation/engine_comparison/aligned-observed-results.json`에 요약하고, 전체 결과는 `reports/engine-comparison-aligned/aligned-results.json` 및 같은 디렉터리의 SARIF 파일에 저장했다.

## 모델

| 항목 | Semgrep CE 기존 Rule | 새 CodeQL Command Query |
| --- | --- | --- |
| 공통 Source | `req.body.command`, `req.query.command`, 일반/중첩/별칭 구조 분해 | 이름이 `req`인 매개변수의 `body.command`/`query.command` 속성 읽기 |
| 공통 Sink | `child_process.exec`, `execSync` 첫 인자 | 동일 모듈 함수 첫 인자 |
| 모델 차이 | Rule은 필드 이름 전체에 대한 와일드카드이며 `req.params`, `process.argv`, `prompt`도 포함 | `command` 필드만 지정; `req` 이외 매개변수 이름은 제외. CodeQL은 모듈 데이터 흐름을 추적 |

즉 기존 Rule을 보존하는 조건상 두 모델이 완전히 같지는 않다. 아래 명령어 fixture의 Source/Sink 교집합으로 결과를 비교한다. 별칭 구조 분해 fixture는 기존 9개 공통 프로젝트를 변경하지 않도록 별도 파일로 두고, 실행 시 임시 복제본에만 추가한다. 숫자 변환 사례는 기존 Semgrep Rule의 와일드카드 Source와 sanitizer 정의 차이도 시험한다.

## NodeGoat 경로 및 Query

고정 SHA: `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`.

`app/routes/index.js:63`의 GET `/allocations/:userId` → `app/routes/allocations.js:11`의 `displayAllocations(req, ...)` → `:19–21`의 `const {threshold} = req.query` → `:23`의 `allocationsDAO.getByUserIdAndThreshold(userId, threshold, ...)` → `app/data/allocations-dao.js:57`의 DAO 인자 → `:77–79`의 `$where` 템플릿 → `:86`의 `allocationsCol.find(searchCriteria())`.

새 NoSQL Query의 Source는 이름이 `req`인 매개변수에서 읽은 `query.threshold`다. Sink는 `$where` 속성 값이며, 그 속성을 포함한 객체가 `find()` 첫 인자까지 데이터 흐름으로 연결되어야 한다. `allocationsCol`은 `app/data/allocations-dao.js:15`에서 `db.collection("allocations")`로 생성된다. `threshold` 숫자 변환/범위 검사 예시는 원본 코드의 주석 안에만 있으므로 실제 경로의 sanitizer가 아니다. Query는 `find()` 수신자가 반드시 MongoDB 컬렉션인지 증명하지 않으므로 일반 객체의 동명 메서드에 대한 오탐 가능성이 남는다. 또한 `req`/`threshold` 이름 및 `$where` 구조에 의존해 다른 NoSQL 삽입 형태는 미탐할 수 있다.

대조 프로젝트는 취약한 2파일 흐름, 고정 `$where`, `Number.parseInt` 후 정수 검사, DB 조회와 무관한 `$where` 객체를 포함한다. 이들은 특정 Query의 정밀도를 확인하는 예제이지 모든 sanitizer의 안전성을 증명하지 않는다.

## 관측 결과

새 실험의 공통 프로젝트 결과 (`●` 탐지, `–` 미탐):

| 사례 | Semgrep CE | CodeQL | 판정/차이 |
| --- | :---: | :---: | --- |
| 직접 전달 | ● | ● | 양쪽 탐지 |
| 동일 파일 중간 변수 | ● | ● | 양쪽 탐지 |
| 일반 구조 분해 | ● | ● | 양쪽 탐지 |
| 중첩 구조 분해 | ● | ● | 양쪽 탐지 |
| 별칭 구조 분해 | ● | ● | 양쪽 탐지; 별도 fixture를 임시 복제본에 추가 |
| 함수 인자 전달 | – | ● | Semgrep CE 미탐 |
| 2파일 전달 | – | ● | Semgrep CE 미탐 |
| 3파일 전달 | – | ● | Semgrep CE 미탐 |
| 고정 명령 | – | – | 양쪽 정상 |
| `Number.parseInt(req.query.count)` | ● | – | Semgrep의 `req.query.$FIELD` 와일드카드가 `count`를 Source로 취급한 오탐; CodeQL Query는 `command`만 Source라 직접 동등 비교 불가 |

NodeGoat 실제 소스의 CodeQL 결과는 `app/data/allocations-dao.js:78` 1건으로, Route의 `req.query.threshold`가 다른 파일의 `$where` 값에 도달했다. Semgrep CE 결과는 같은 DAO의 `:77` 구조적 후보 1건이며, 이는 Source에서 Sink까지의 taint 연결을 입증하는 Finding이 아니다. 안전 대조 프로젝트의 CodeQL 결과는 취약한 `vulnerable/dao.js:3`만 1건이었다. 고정 조건, 숫자 변환 후 정수 검사, `find()`로 이어지지 않는 일반 `$where` 객체는 0건이었다. 이 한정된 fixture에서 새 CodeQL Query의 확인된 오탐/미탐은 없지만, 앞서 적은 일반 `find()` 수신자 및 고정 필드 이름의 모델 한계는 남는다.

| 실행 구간 | Semgrep CE | CodeQL DB 생성 | CodeQL Query 분석 |
| --- | ---: | ---: | ---: |
| 공통 프로젝트 + 별칭 사례 | 2.976초 | 5.609초 | 101.452초 |
| NodeGoat | 2.504초 | 6.313초 | 52.285초 |
| NoSQL 대조 프로젝트 | 미실행 | 6.106초 | 11.708초 |

CodeQL 분석 시간에는 Query 컴파일 및 캐시 상태가 반영된다. 세 Query 분석은 순서대로 실행되어 뒤쪽은 컴파일 캐시의 이점을 받으므로 독립적인 cold-run 속도 비교로 해석하면 안 된다. 기존 비교의 2.479/5.366/108.844초 수치는 그대로 보존했다. 실제 Scanner CLI도 NodeGoat에서 구조적 후보 1건, `reports/engine-comparison-aligned/nodegoat-cli/`에 Markdown/JSON 저장, 종료 코드 2를 확인했다. 전체 회귀 테스트는 기존 94개와 신규 4개, 총 98개 통과했다.

향후 Scanner에는 `req` 전체를 Source로 보는 방식보다 속성 단위 모델 및 alias/구조 분해 fixture를 유지하는 편이 타당하다. 파일 간 실제 taint가 필요한 경우 CodeQL 등의 별도 엔진 연동을 고려하되, Semgrep CE 구조적 후보와 taint 검증 Finding을 같은 확신도로 합산하지 않아야 한다. 기존 Semgrep Rule의 숫자 변환 사례와 `req.query.$FIELD` 와일드카드 정밀화는 별도 Rule 변경 작업으로 다룬다.

## 재현

프로젝트 루트에서 다음 명령을 실행한다. CodeQL CLI 및 Semgrep 가상환경이 설치되어 있어야 한다. 스크립트는 NodeGoat HEAD가 고정 SHA인지 검사하고 임시 DB를 만든다.

```bash
.venv/bin/python -m validation.engine_comparison.run_aligned \
  --codeql /home/kimhr/tools/codeql/codeql
```

실제 Scanner CLI는 Semgrep의 설정/로그 경로를 쓰기 가능한 위치로 지정해 실행한다.

```bash
PATH="$PWD/.venv/bin:$PATH" \
SEMGREP_SETTINGS_FILE=/tmp/my-vuln-semgrep-settings.yml \
SEMGREP_LOG_FILE=/tmp/my-vuln-semgrep.log \
SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
.venv/bin/python -m scanner.main scan targets/opensource/javascript/nodegoat \
  --format both --output /tmp/my-vuln-nodegoat-reports
```

이 CLI의 정상적인 탐지 종료 코드는 2다. CodeQL Query는 실제 런타임 공격을 증명하지 않으며, 결과는 검토할 취약점 후보로 취급한다. 기존 독립 조사 분류는 변경하지 않는다.
