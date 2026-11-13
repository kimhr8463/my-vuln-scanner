# CLI 사용 및 설계

프로젝트 루트에서 가상환경을 활성화한 뒤 실행한다.

```bash
python -m scanner.main scan ./targets/my-project
python -m scanner.main scan ./targets/my-project --rules ./rules --output ./reports --format both --timeout 300
python -m scanner.main --version
python -m scanner.main --help
```

기본 Rule 경로는 프로젝트의 `rules/`, 보고서 경로는 프로젝트의 `reports/`이다. 상대 경로로 전달한 대상·Rule·보고서 경로는 현재 작업 디렉터리를 기준으로 해석한다. 기본 출력은 Markdown과 JSON이며, `--format markdown` 또는 `--format json`으로 하나만 선택할 수 있다.

`ScanApplication`은 Rule 검증 → Runner 실행 → Parser 정규화 → Reporter 저장을 연결한다. 기존 모듈의 공개 인터페이스는 변경하지 않았다. 보고서 파일명은 `<대상 폴더명>-scan.md`와 `<대상 폴더명>-scan.json`이다. 같은 대상과 출력 경로로 다시 실행하면 기존 보고서를 갱신한다.

성공하면 Finding 수와 세 가지 통계, 저장 경로를 출력한다. 종료 코드 0은 Finding이 없는 정상 스캔, 2는 Finding이 있는 정상 스캔이다. 두 경우 모두 선택한 보고서를 저장한다. 대상·Rule·입력·실행·저장 오류는 표준 오류에 표시하고 종료 코드 1을 반환한다. CI에서는 종료 코드 2를 취약점 발견으로 구분해 처리할 수 있다.

전체 모듈 테스트는 `python -m unittest discover -s tests -t . -p 'test_*.py' -v`로 실행한다. `-t .`는 프로젝트 루트의 `scanner` 패키지를 올바르게 찾기 위해 필요하다.
