"""Unit and integration tests for CLI commands."""

from click.testing import CliRunner

from qv import __version__
from qv.cli.main import cli


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["version"])
    assert result.exit_code == 0
    assert f"qv v{__version__}" in result.output


def test_cli_explain_valid_rule():
    runner = CliRunner()
    result = runner.invoke(cli, ["explain", "DEP-001"])
    assert result.exit_code == 0
    assert "DEP-001" in result.output
    assert "Dependency constraint conflict" in result.output


def test_cli_explain_invalid_rule():
    runner = CliRunner()
    result = runner.invoke(cli, ["explain", "INVALID-999"])
    assert result.exit_code == 2


def test_cli_scan_json_output(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "test-pkg"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path), "--json"])
    assert result.exit_code in (0, 1)
    assert '"project_name": "test-pkg"' in result.output


def test_cli_scan_sarif_output(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "sarif-test"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path), "--sarif"])
    assert result.exit_code in (0, 1)
    assert '"version": "2.1.0"' in result.output
    assert f'"semanticVersion": "{__version__}"' in result.output


def test_cli_framework_command(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "fastapi-sample"
version = "0.1.0"
dependencies = ["fastapi"]
""",
        encoding="utf-8",
    )
    app_file = tmp_path / "app.py"
    app_file.write_text(
        """
import time
from fastapi import FastAPI

app = FastAPI()

@app.get("/slow")
async def slow_route():
    time.sleep(1)
    return {"status": "ok"}
""",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["framework", str(tmp_path)])
    assert result.exit_code == 1
    assert "FAP-001" in result.output
    assert "Blocking call" in result.output


def test_cli_frameworks_alias(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "clean-sample"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["frameworks", str(tmp_path), "--name", "fastapi"])
    assert result.exit_code == 0
