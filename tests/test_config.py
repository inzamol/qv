"""Unit tests for configuration loading."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from qv.cli.main import cli
from qv.core.config import ConfigurationError, QvConfig
from qv.core.models import Severity
from qv.core.project import load_project


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


def test_invalid_toml_syntax_raises_configuration_error(tmp_path: Path):
    toml_file = tmp_path / "pyproject.toml"
    toml_file.write_text("[tool.qv\ninvalid = true", encoding="utf-8")

    with pytest.raises(ConfigurationError) as excinfo:
        QvConfig.from_pyproject(toml_file)
    assert "Failed to parse configuration file" in str(excinfo.value)


def test_invalid_rule_severity_raises_configuration_error(tmp_path: Path):
    toml_file = tmp_path / "pyproject.toml"
    toml_file.write_text(
        """
[tool.qv.rules]
DEP-001 = "not_a_valid_severity"
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError) as excinfo:
        QvConfig.from_pyproject(toml_file)
    assert "Invalid severity 'not_a_valid_severity'" in str(excinfo.value)


def test_invalid_min_severity_raises_configuration_error(tmp_path: Path):
    toml_file = tmp_path / "pyproject.toml"
    toml_file.write_text(
        """
[tool.qv]
min_severity = "fatal"
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError) as excinfo:
        QvConfig.from_pyproject(toml_file)
    assert "Invalid min_severity 'fatal'" in str(excinfo.value)


def test_cli_exits_with_code_2_on_invalid_config(tmp_path: Path):
    toml_file = tmp_path / "pyproject.toml"
    toml_file.write_text("[tool.qv\ninvalid = true", encoding="utf-8")

    runner = CliRunner()

    for cmd in ["scan", "dependency", "environment", "architecture", "fix", "tree"]:
        res = runner.invoke(cli, [cmd, str(tmp_path)])
        assert res.exit_code == 2, (
            f"Command '{cmd}' expected exit code 2, got {res.exit_code}: {res.output}"
        )
        assert "Configuration error:" in res.output


def test_dependency_ignore(tmp_path: Path):
    """AC-02: [tool.qv.dependencies] ignore = ['amqp'] ignores amqp in DEP-003."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "dep-ignore-demo"
version = "0.1.0"
dependencies = [
    "amqp",
]

[tool.qv.dependencies]
ignore = ["amqp"]
""",
        encoding="utf-8",
    )
    main_py = tmp_path / "main.py"
    main_py.write_text("print('hello')\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "DEP-003" not in result.output
    assert "amqp" not in result.output


def test_dependency_ignore_is_case_insensitive(tmp_path: Path):
    """AC-02: Dependency ignore is case-insensitive (e.g. 'AMQP')."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "dep-ignore-case"
version = "0.1.0"
dependencies = [
    "amqp",
]

[tool.qv.dependencies]
ignore = ["AMQP"]
""",
        encoding="utf-8",
    )
    main_py = tmp_path / "main.py"
    main_py.write_text("print('hello')\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "DEP-003" not in result.output


def test_dependency_ignore_normalizes_package_name(tmp_path: Path):
    """AC-02: Dependency ignore normalizes requirement specifiers, extras, hyphens/underscores."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "dep-ignore-norm"
version = "0.1.0"
dependencies = [
    "scikit-learn>=1.0.0",
    "celery[redis]~=5.2.0",
]

[tool.qv.dependencies]
ignore = ["scikit_learn", "Celery[extra]>=5.0.0"]
""",
        encoding="utf-8",
    )
    main_py = tmp_path / "main.py"
    main_py.write_text("print('hello')\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "DEP-003" not in result.output
    assert "scikit-learn" not in result.output
    assert "celery" not in result.output


def test_dependency_ignore_does_not_disable_other_rules(tmp_path: Path):
    """AC-02: Ignoring a dependency does not disable DEP-001, DEP-002, or other rules."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "dep-ignore-other-rules"
version = "0.1.0"
dependencies = []

[tool.qv.dependencies]
ignore = ["httpx"]
""",
        encoding="utf-8",
    )
    # Source code imports httpx (which is not declared -> DEP-002)
    main_py = tmp_path / "main.py"
    main_py.write_text("import httpx\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    # DEP-002 must still be emitted!
    assert "DEP-002" in result.output
    assert "httpx" in result.output


def test_existing_ignore_rules_still_work(tmp_path: Path):
    """AC-02: [tool.qv.ignore].rules continues to work as expected."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "existing-ignore-demo"
version = "0.1.0"
dependencies = [
    "requests",
]

[tool.qv.ignore]
rules = ["DEP-003"]
""",
        encoding="utf-8",
    )
    main_py = tmp_path / "main.py"
    main_py.write_text("print('hello')\n", encoding="utf-8")

    project = load_project(tmp_path)
    assert project.config.is_rule_enabled("DEP-003") is False

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "DEP-003" not in result.output
