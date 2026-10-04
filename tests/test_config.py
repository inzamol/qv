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


def test_load_project_centralized(tmp_path: Path):
    """Test that load_project produces unified Project with config and context."""
    from qv.core.project import load_project

    toml_file = tmp_path / "pyproject.toml"
    toml_file.write_text(
        """[project]
name = "test-project"
version = "0.1.0"
dependencies = ["requests>=2.0.0"]

[tool.qv.rules]
DEP-003 = "off"
""",
        encoding="utf-8",
    )

    project = load_project(tmp_path)
    assert project.root == tmp_path.resolve()
    assert project.config.is_rule_enabled("DEP-003") is False
    assert project.context.project_name == "test-project"


def test_cli_commands_share_configuration_suppression(tmp_path: Path):
    """Test that rule suppression in pyproject.toml behaves identically in scan and dependency commands."""
    from click.testing import CliRunner

    from qv.cli.main import cli

    toml_file = tmp_path / "pyproject.toml"
    toml_file.write_text(
        """[project]
name = "test-project"
version = "0.1.0"
dependencies = ["unused-lib>=1.0.0"]

[tool.qv.rules]
DEP-003 = "off"
""",
        encoding="utf-8",
    )

    runner = CliRunner()

    # qv scan should suppress DEP-003
    scan_res = runner.invoke(cli, ["scan", str(tmp_path)])
    print("SCAN OUTPUT:", scan_res.output)
    assert "DEP-003" not in scan_res.output

    # qv dependency should also suppress DEP-003
    dep_res = runner.invoke(cli, ["dependency", str(tmp_path)])
    print("DEP OUTPUT:", dep_res.output)
    assert "DEP-003" not in dep_res.output
    assert dep_res.exit_code == scan_res.exit_code
