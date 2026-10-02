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
        except Exception:
            return cls()

        # Support [tool.qv] as primary and [tool.pydoctor] as fallback
        tool_config: dict[str, Any] = data.get("tool", {}).get("qv") or data.get("tool", {}).get(
            "pydoctor", {}
        )
        if not tool_config:
            return cls()

        rules: dict[str, RuleConfig] = {}
        for rule_id, sev_str in tool_config.get("rules", {}).items():
            sev_str_lower = str(sev_str).lower()
            if sev_str_lower == "off":
                rules[rule_id] = RuleConfig(disabled=True)
            elif sev_str_lower in ("error", "warning", "info"):
                rules[rule_id] = RuleConfig(severity=Severity(sev_str_lower))

        ignored_rules = set(tool_config.get("ignore", {}).get("rules", []))

        paths_dict = tool_config.get("paths", {})
        paths = PathConfig(
            exclude=paths_dict.get("exclude", PathConfig().exclude),
            include=paths_dict.get("include", []),
        )

        runtime_dict = tool_config.get("runtime", {})
        target_python = runtime_dict.get("python") or data.get("project", {}).get("requires-python")
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
        min_severity = (
            Severity(str(min_sev_str).lower())
            if min_sev_str and str(min_sev_str).lower() in ("error", "warning", "info")
            else None
        )

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
