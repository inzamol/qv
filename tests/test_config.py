"""Unit tests for configuration loading."""

from pathlib import Path

from qv.core.config import QvConfig
from qv.core.models import Severity


def test_default_config():
    config = QvConfig()
    assert config.is_rule_enabled("DEP-001") is True
    assert config.get_effective_severity("DEP-001", Severity.ERROR) == Severity.ERROR


def test_config_from_pyproject(tmp_path: Path):
    toml_file = tmp_path / "pyproject.toml"
    toml_file.write_text(
        """
[tool.qv.rules]
DEP-001 = "warning"
DEP-002 = "off"

[tool.qv.ignore]
rules = ["DEP-003"]

[tool.qv.runtime]
python = "3.12"
""",
        encoding="utf-8",
    )

    config = QvConfig.from_pyproject(toml_file)
    assert config.is_rule_enabled("DEP-001") is True
    assert config.get_effective_severity("DEP-001", Severity.ERROR) == Severity.WARNING
    assert config.is_rule_enabled("DEP-002") is False
    assert config.is_rule_enabled("DEP-003") is False
    assert config.target_python == "3.12"


def test_strict_mode():
    config = QvConfig(strict=True)
    # Warnings are promoted to errors in strict mode
    assert config.get_effective_severity("DEP-003", Severity.WARNING) == Severity.ERROR
