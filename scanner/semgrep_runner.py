import json
import subprocess
import tempfile
import time

from pathlib import Path

from scanner.rule_loader import RuleLoader


class SemgrepRunner:
    """여러 Semgrep Rule을 통합하여 대상 코드를 검사한다."""

    def __init__(
        self,
        rules_dir: str | Path,
        timeout: int = 300,
    ):
        self.rules_dir = Path(rules_dir).resolve()
        self.timeout = timeout
        self.loader = RuleLoader(self.rules_dir)

    def build_config(self, output_path: Path) -> list[str]:
        """수집한 Rule을 하나의 YAML 파일로 통합한다."""

        rules = self.loader.load_rules()
        combined_rules = []

        for rule_info in rules:
            with rule_info.file_path.open(
                "r", encoding="utf-8"
            ) as file:
                data = __import__("yaml").safe_load(file)

            combined_rules.extend(data["rules"])

        import yaml

        config = {"rules": combined_rules}

        with output_path.open("w", encoding="utf-8") as file:
            yaml.safe_dump(
                config,
                file,
                allow_unicode=True,
                sort_keys=False,
            )

        return [
            rule_id
            for rule in rules
            for rule_id in rule.rule_ids
        ]

    def scan(
        self,
        target: str | Path,
        output_path: str | Path | None = None,
    ) -> dict:
        """대상 디렉터리를 스캔하고 JSON 결과를 반환한다."""

        target_path = Path(target).resolve()

        if not target_path.exists():
            raise FileNotFoundError(
                f"Scan target not found: {target_path}"
            )

        if not target_path.is_dir():
            raise NotADirectoryError(
                f"Scan target must be a directory: {target_path}"
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "combined_rules.yml"

            rule_ids = self.build_config(config_path)

            command = [
                "semgrep",
                "scan",
                "--config",
                str(config_path),
                "--json",
                "--no-git-ignore",
                str(target_path),
            ]

            start_time = time.perf_counter()

            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                raise TimeoutError(
                    f"Semgrep scan timed out after {self.timeout}s"
                ) from error
            except FileNotFoundError as error:
                raise RuntimeError(
                    "Semgrep CLI was not found. Check installation."
                ) from error

            elapsed = time.perf_counter() - start_time

            if result.returncode not in (0, 1):
                raise RuntimeError(
                    f"Semgrep execution failed:\n{result.stderr}"
                )

            try:
                report = json.loads(result.stdout)
            except json.JSONDecodeError as error:
                raise RuntimeError(
                    "Semgrep returned invalid JSON."
                ) from error

            report["scanner_metadata"] = {
                "target": str(target_path),
                "rules": rule_ids,
                "elapsed_seconds": round(elapsed, 3),
            }

            if output_path is not None:
                destination = Path(output_path).resolve()
                destination.parent.mkdir(
                    parents=True, exist_ok=True
                )
                destination.write_text(
                    json.dumps(
                        report,
                        indent=2,
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )

            return report
