# Reporter 설계 기록

- 입력은 `ResultParser`의 `Finding` 목록과 `SemgrepRunner`의 `scanner_metadata`에서 얻는 대상 경로 및 실행 시간이다. Reporter가 Semgrep 원본 JSON에 결합되지 않도록 했다.
- `Reporter.build_report()`가 입력 검증, 세 가지 통계 집계, 상세 정보 직렬화를 담당한다. 출력 순서와 통계 키 순서는 재현 가능하도록 일정하게 유지한다.
- `ReportFormatter`가 출력 형식의 공통 계약이다. `MarkdownFormatter`와 `JsonFormatter`를 기본 등록하며, 향후 HTML/CSV는 새 Formatter를 등록해 추가할 수 있다.
- `Reporter.save()`는 내용을 먼저 생성하고 검증이 끝난 후 저장 디렉터리를 만든다. 빈 Finding도 정상적인 보고서로 처리한다.
- CLI와 자동 저장 경로 정책은 후속 단계에서 결정한다. 현재 Reporter는 호출자가 지정한 경로에만 저장한다.
