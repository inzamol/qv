"""Unit tests for qv fix --diff and --interactive flags."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from qv.cli.main import cli


def test_qv_fix_diff_option(tmp_path: Path):
    runner = CliRunner()
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[project]\nname = 'fix-diff-proj'\nversion = '0.1.0'\ndependencies = []\n",
        encoding="utf-8",
    )
    src = tmp_path / "app.py"
    src.write_text("import httpx\n", encoding="utf-8")

    result = runner.invoke(cli, ["fix", str(tmp_path), "--diff", "--dry-run"])
    assert result.exit_code == 0
    assert "Proposed File Diffs" in result.output
    assert "+ httpx" in result.output


def test_qv_fix_interactive_accept(tmp_path: Path):
    runner = CliRunner()
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[project]\nname = 'fix-inter-proj'\nversion = '0.1.0'\ndependencies = []\n",
        encoding="utf-8",
    )
    src = tmp_path / "app.py"
    src.write_text("import httpx\n", encoding="utf-8")

    # Send 'y' to accept the individual fix
    result = runner.invoke(cli, ["fix", str(tmp_path), "-i"], input="y\n")
    assert result.exit_code == 0
    assert "Successfully applied" in result.output
    assert "httpx" in pyproject.read_text(encoding="utf-8")
