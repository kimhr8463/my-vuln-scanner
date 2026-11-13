from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class RuleInfo:
    """개별 Semgrep Rule 정보."""

    file_path: Path
    rule_ids: tuple[str, ...]
    languages: tuple[str, ...]


class RuleLoader:
    """Rule 디렉터리에서 Semgrep YAML Rule을 자동 수집한다."""

    def __init__(self, rules_dir: str | Path):
        self.rules_dir = Path(rules_dir).resolve()

        if not self.rules_dir.exists():
            raise FileNotFoundError(
                f"Rule directory not found: {self.rules_dir}"
            )

        if not self.rules_dir.is_dir():
            raise NotADirectoryError(
                f"Not a directory: {self.rules_dir}"
            )

    def discover(self) -> list[Path]:
        """하위 디렉터리까지 YAML 파일을 검색한다."""

        files = [
            *self.rules_dir.rglob("*.yml"),
            *self.rules_dir.rglob("*.yaml"),
        ]

        return sorted(set(files))

    def validate(self, file_path: Path) -> RuleInfo:
        """YAML 파일의 기본 구조와 필수 항목을 검사한다."""

        try:
            with file_path.open("r", encoding="utf-8") as file:
                data = yaml.safe_load(file)

        except yaml.YAMLError as error:
            raise ValueError(
                f"Invalid YAML syntax: {file_path}"
            ) from error

        if not isinstance(data, dict):
            raise ValueError(
                f"Invalid Rule configuration: {file_path}"
            )

        rules = data.get("rules")

        if not isinstance(rules, list) or not rules:
            raise ValueError(
                f"'rules' must be a non-empty list: {file_path}"
            )

        rule_ids = []
        languages = set()

        for rule in rules:
            if not isinstance(rule, dict):
                raise ValueError(
                    f"Each rule must be a mapping: {file_path}"
                )

            rule_id = rule.get("id")
            rule_languages = rule.get("languages")

            if not isinstance(rule_id, str) or not rule_id.strip():
                raise ValueError(
                    f"Missing or invalid Rule ID: {file_path}"
                )

            if (
                not isinstance(rule_languages, list)
                or not rule_languages
                or not all(
                    isinstance(language, str) and language.strip()
                    for language in rule_languages
                )
            ):
                raise ValueError(
                    f"Missing or invalid languages: {file_path}"
                )

            rule_ids.append(rule_id)
            languages.update(rule_languages)

        return RuleInfo(
            file_path=file_path,
            rule_ids=tuple(rule_ids),
            languages=tuple(sorted(languages)),
        )

    def load_rules(self) -> list[RuleInfo]:
        """모든 Rule을 수집하고 중복 ID를 검사한다."""

        files = self.discover()

        if not files:
            raise ValueError(
                f"No YAML rules found in: {self.rules_dir}"
            )

        loaded_rules = []
        seen_ids = {}

        for file_path in files:
            rule_info = self.validate(file_path)

            for rule_id in rule_info.rule_ids:
                if rule_id in seen_ids:
                    raise ValueError(
                        f"Duplicate Rule ID '{rule_id}': "
                        f"{seen_ids[rule_id]} and {file_path}"
                    )

                seen_ids[rule_id] = file_path

            loaded_rules.append(rule_info)

        return loaded_rules
