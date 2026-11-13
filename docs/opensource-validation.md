# 고정 오픈소스 검증 환경

외부 대상 코드는 `targets/opensource/python/pygoat`와 `targets/opensource/javascript/nodegoat`에 분리한다. `targets/`의 외부 체크아웃은 Git에서 제외하고 기존 `tests/`의 스캐너 테스트와 섞지 않는다. 대상 정보는 [`validation/targets.json`](../validation/targets.json)에 저장한다. PyGoat는 커밋 스냅샷 `2aa4cc1`, NodeGoat는 `package.json` 버전 `1.3.0`을 사용한다. 전체 커밋 SHA와 날짜는 대상 목록에 기록했다.

| 대상 | Repository | 고정 SHA | 라이선스 파일 |
| --- | --- | --- | --- |
| PyGoat | [adeyosemanputra/pygoat](https://github.com/adeyosemanputra/pygoat) | `2aa4cc14f251e4a780e94e200aed6b36a5b15c21` | [MIT LICENSE.md](https://github.com/adeyosemanputra/pygoat/blob/2aa4cc14f251e4a780e94e200aed6b36a5b15c21/LICENSE.md) |
| NodeGoat | [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) | `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` | [Apache-2.0 LICENSE](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/LICENSE) |

대상을 다시 받을 때는 각 Repository를 해당 경로에 clone한 후 목록의 전체 SHA로 `git checkout --detach <SHA>` 한다. 대상 저장소의 라이선스 전문은 체크아웃 안에 유지한다. 검증 도구는 대상 경로, 정확한 HEAD, 변경되지 않은 작업 트리, 라이선스 파일을 스캔 전에 확인한다. 대상 앱이나 외부 서버는 실행하지 않는다.

```bash
python -m validation.quality verify
python -m validation.quality scan
python -m validation.quality metrics
python -m validation.quality scan --target pygoat
```

스캔 실행에는 프로젝트 가상환경의 `semgrep`이 PATH에 있어야 한다. 보고서는 `reports/validation/<대상 ID>/<커밋 SHA>/<Rule 해시 앞 12자리>/`에 Markdown, JSON, `run.json`으로 저장된다. `run.json`은 대상 버전·커밋·라이선스·Rule 해시·Scanner/Semgrep 버전·실행 시각과 통계를 기록한다. 이 보고서들은 Git에서 제외된다.

`validation.quality scan`은 검증 환경 작업이 성공하면 종료 코드 0을 반환한다. 취약점 발견을 CI 종료 코드 2로 처리하려면 기존 `python -m scanner.main scan <대상>` 명령을 사용한다.

판정 대기열은 `validation/reviews/<대상 ID>/<커밋 앞 12자리>-<Rule 해시 앞 12자리>.json`에 저장한다. 각 행은 안정적인 Finding ID, Repository, SHA, Rule ID, 유형, CWE, 상대 파일 경로, 시작·종료 줄, 판정 상태, TP/FP 분류와 근거를 포함한다. 새 스캔은 기존 판정을 덮어쓰지 않는다. 수동으로 발견한 미탐은 같은 형식의 행을 `missed_findings`에 추가하고 `classification`을 `FN`으로 설정한다. 범위 밖 사례는 FN에 넣지 않고 [`validation/scope-gaps.json`](../validation/scope-gaps.json)에 따로 기록한다.

`precision = TP / (TP + FP)`, `recall = TP / (TP + FN)`이다. 미검토 Finding이 남아 있으면 Precision을 `null`로 표시한다. Recall은 대상과 Rule 범위의 독립적인 정답 집합 조사가 끝나 `ground_truth_complete`가 `true`일 때만 계산한다. 0건 스캔이나 확인된 FN 0건만으로 Recall 100%를 선언하지 않는다.

## 첫 스캔 결과

| 대상 | 탐지 | 정적 검토 TP | 확인된 FP | 확인된 FN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| PyGoat | 4 | 4 | 0 | 0 | 1.0 (검토된 4건) | 미산출 |
| NodeGoat | 0 | 0 | 0 | 0 | 미산출 | 미산출 |

PyGoat의 명령 주입, SQL 주입, 경로 탐색, SSRF 각 1건은 요청 입력에서 해당 Sink로 이어지는 코드를 로컬에서 검토해 TP로 분류했다. 이는 정적 코드 흐름에 대한 판정이며 실제 공격 성공을 주장하지 않는다. 현재 4건에서 오탐은 발견되지 않았다. NodeGoat의 MongoDB `$where` 코드 사례는 현재 SQL Rule의 대상이 아니므로 FP/FN에 포함하지 않았다. 별도의 NoSQL Rule과 파일 간 데이터 흐름 지원이 향후 개선 후보이다. 두 대상 모두 독립적인 전체 미탐 조사가 끝나지 않았다.
