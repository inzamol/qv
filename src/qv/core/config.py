"""Configuration loader and validator for qv."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from qv.core.models import Severity


class ConfigurationError(Exception):
    """Raised when a configuration file cannot be parsed or contains invalid settings."""


@dataclass
class RuleConfig:
    """Per-rule configuration."""

    severity: Severity | None = None  # None means use rule default
    disabled: bool = False


@dataclass
class PathConfig:
    """Path matching configuration."""

    exclude: list[str] = field(
        default_factory=lambda: [
            ".venv",
            "venv",
            "env",
            ".env",
            "build",
            "dist",
            "node_modules",
            "__pycache__",
            ".pytest_cache",
            ".git",
        ]
    )
    include: list[str] = field(default_factory=list)


@dataclass
class QvConfig:
    """Top-level configuration for qv."""

    rules: dict[str, RuleConfig] = field(default_factory=dict)
    ignored_rules: set[str] = field(default_factory=set)
    paths: PathConfig = field(default_factory=PathConfig)
    target_python: str | None = None
    strict: bool = False
    offline: bool = False
    hide_warnings: bool = False
    errors_only: bool = False
    min_severity: Severity | None = None

    def is_rule_enabled(self, rule_id: str) -> bool:
        if rule_id in self.ignored_rules:
            return False
        if rule_id in self.rules and self.rules[rule_id].disabled:
            return False
        return True

    def get_effective_severity(self, rule_id: str, default_severity: Severity) -> Severity:
        if rule_id in self.rules and self.rules[rule_id].severity is not None:
            sev = self.rules[rule_id].severity
            assert sev is not None
            if self.strict and sev == Severity.WARNING:
                return Severity.ERROR
            return sev
        if self.strict and default_severity == Severity.WARNING:
            return Severity.ERROR
        return default_severity

    @classmethod
    def from_pyproject(cls, pyproject_path: Path | None = None) -> QvConfig:
        """Load configuration from pyproject.toml if present."""
        if pyproject_path is None or not pyproject_path.exists():
            return cls()

        try:
            with open(pyproject_path, "rb") as f:
                data = tomllib.load(f)
        except Exception as e:
            raise ConfigurationError(
                f"Failed to parse configuration file '{pyproject_path}': {e}"
            ) from e

        if not isinstance(data, dict):
            raise ConfigurationError(f"Invalid TOML root in '{pyproject_path}': expected a table")

        tool_table = data.get("tool")
        if tool_table is not None and not isinstance(tool_table, dict):
            raise ConfigurationError(
                f"Invalid [tool] section in '{pyproject_path}': expected a table"
            )

        # Support [tool.qv] as primary and [tool.pydoctor] as fallback
        tool_config: Any = None
        if isinstance(tool_table, dict):
            tool_config = tool_table.get("qv") or tool_table.get("pydoctor")

        if tool_config is None:
            return cls()

        if not isinstance(tool_config, dict):
            raise ConfigurationError(
                f"Invalid [tool.qv] section in '{pyproject_path}': expected a table"
            )

        rules: dict[str, RuleConfig] = {}
        rules_table = tool_config.get("rules")
        if rules_table is not None:
            if not isinstance(rules_table, dict):
                raise ConfigurationError(
                    f"Invalid [tool.qv.rules] in '{pyproject_path}': expected a table of rule severities"
                )
            for rule_id, sev_str in rules_table.items():
                if not isinstance(sev_str, str):
                    raise ConfigurationError(
                        f"Invalid severity value for rule '{rule_id}' in '{pyproject_path}': expected string, got {type(sev_str).__name__}"
                    )
                sev_str_lower = sev_str.strip().lower()
                if sev_str_lower == "off":
                    rules[rule_id] = RuleConfig(disabled=True)
                elif sev_str_lower in ("error", "warning", "info"):
                    rules[rule_id] = RuleConfig(severity=Severity(sev_str_lower))
                else:
                    raise ConfigurationError(
                        f"Invalid severity '{sev_str}' for rule '{rule_id}' in '{pyproject_path}'. Expected one of: 'error', 'warning', 'info', 'off'."
                    )

        ignored_rules: set[str] = set()
        ignore_table = tool_config.get("ignore")
        if ignore_table is not None:
            if not isinstance(ignore_table, dict):
                raise ConfigurationError(
                    f"Invalid [tool.qv.ignore] in '{pyproject_path}': expected a table"
                )
            ignore_rules_list = ignore_table.get("rules")
            if ignore_rules_list is not None:
                if not isinstance(ignore_rules_list, (list, tuple, set)):
                    raise ConfigurationError(
                        f"Invalid [tool.qv.ignore.rules] in '{pyproject_path}': expected a list of rule IDs"
                    )
                for r in ignore_rules_list:
                    if not isinstance(r, str):
                        raise ConfigurationError(
                            f"Invalid rule ID in [tool.qv.ignore.rules] in '{pyproject_path}': expected string"
                        )
                    ignored_rules.add(r.strip())

        paths_dict = tool_config.get("paths")
        if paths_dict is not None and not isinstance(paths_dict, dict):
            raise ConfigurationError(
                f"Invalid [tool.qv.paths] in '{pyproject_path}': expected a table"
            )
        if isinstance(paths_dict, dict):
            exclude_val = paths_dict.get("exclude")
            if exclude_val is not None and not isinstance(exclude_val, (list, tuple)):
                raise ConfigurationError(
                    f"Invalid [tool.qv.paths.exclude] in '{pyproject_path}': expected a list"
                )
            include_val = paths_dict.get("include")
            if include_val is not None and not isinstance(include_val, (list, tuple)):
                raise ConfigurationError(
                    f"Invalid [tool.qv.paths.include] in '{pyproject_path}': expected a list"
                )
            paths = PathConfig(
                exclude=list(exclude_val) if exclude_val is not None else PathConfig().exclude,
                include=list(include_val) if include_val is not None else [],
            )
        else:
            paths = PathConfig()

        runtime_dict = tool_config.get("runtime")
        if runtime_dict is not None and not isinstance(runtime_dict, dict):
            raise ConfigurationError(
                f"Invalid [tool.qv.runtime] in '{pyproject_path}': expected a table"
            )
        target_python = (
            runtime_dict.get("python") if isinstance(runtime_dict, dict) else None
        ) or (
            data.get("project", {}).get("requires-python")
            if isinstance(data.get("project"), dict)
            else None
        )
        if target_python is not None and not isinstance(target_python, str):
            raise ConfigurationError(
                f"Invalid python runtime target in '{pyproject_path}': expected string"
            )

        offline = bool(tool_config.get("offline", False))
        hide_warnings = bool(
            tool_config.get("hide_warnings", tool_config.get("hide-warnings", False))
        )
        errors_only = bool(tool_config.get("errors_only", tool_config.get("errors-only", False)))
        min_sev_str = (
            tool_config.get("min_severity")
            or tool_config.get("min-severity")
            or tool_config.get("severity")
        )
        if min_sev_str is not None:
            if not isinstance(min_sev_str, str) or min_sev_str.strip().lower() not in (
                "error",
                "warning",
                "info",
            ):
                raise ConfigurationError(
                    f"Invalid min_severity '{min_sev_str}' in '{pyproject_path}'. Expected one of: 'error', 'warning', 'info'."
                )
            min_severity = Severity(min_sev_str.strip().lower())
        else:
            min_severity = None

        return cls(
            rules=rules,
            ignored_rules=ignored_rules,
            paths=paths,
            target_python=target_python,
            offline=offline,
            hide_warnings=hide_warnings,
            errors_only=errors_only,
            min_severity=min_severity,
        )


# Backward compatibility alias
PyDoctorConfig = QvConfig
