"""CLI tests for qv pr, pr-analysis, and scan --pr commands."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from qv.cli.main import cli


def test_pr_cli_basic(tmp_path: Path):
    """Verify basic qv pr command execution returns 0 and expected terminal sections."""
    runner = CliRunner()
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "cli-pr-test"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )

    res = runner.invoke(cli, ["pr", str(tmp_path)])
    assert res.exit_code == 0
    assert "QV Pull Request Analysis" in res.output
    assert "Changed files:" in res.output


def test_pr_cli_json_and_sarif(tmp_path: Path):
    """Verify qv pr --json and --sarif generate valid structured output."""
    runner = CliRunner()
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "cli-json-test"
version = "0.1.0"
dependencies = ["unimported-lib"]
""",
        encoding="utf-8",
    )

    # JSON mode
    res_json = runner.invoke(cli, ["pr", str(tmp_path), "--json", "--files", "pyproject.toml"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.output)
    assert data["project_name"] == "cli-json-test"
    assert data["changed_files_count"] == 1
    assert "affected_checks_count" in data

    # SARIF mode
    res_sarif = runner.invoke(cli, ["pr", str(tmp_path), "--sarif", "--files", "pyproject.toml"])
    assert res_sarif.exit_code == 0
    sarif_data = json.loads(res_sarif.output)
    assert sarif_data["version"] == "2.1.0"


def test_pr_cli_comment_and_output(tmp_path: Path):
    """Verify qv pr --comment generates Markdown and supports file output."""
    runner = CliRunner()
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "cli-comment-test"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )

    # Comment mode stdout
    res_comment = runner.invoke(cli, ["pr", str(tmp_path), "--comment"])
    assert res_comment.exit_code == 0
    assert "# 🔍 QV Pull Request Analysis: cli-comment-test" in res_comment.output

    # Output to file
    out_file = tmp_path / "pr_comment.md"
    res_out = runner.invoke(cli, ["pr", str(tmp_path), "--comment", "-o", str(out_file)])
    assert res_out.exit_code == 0
    assert out_file.exists()
    assert "# 🔍 QV Pull Request Analysis" in out_file.read_text(encoding="utf-8")


def test_pr_cli_scan_flag(tmp_path: Path):
    """Verify qv scan --pr activates PR differential analysis mode."""
    runner = CliRunner()
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "scan-pr-flag-test"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )

    res = runner.invoke(cli, ["scan", str(tmp_path), "--pr"])
    assert res.exit_code == 0
    assert "QV Pull Request Analysis" in res.output


def test_pr_analysis_alias(tmp_path: Path):
    """Verify qv pr-analysis alias executes identically to qv pr."""
    runner = CliRunner()
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "alias-test"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )

    res = runner.invoke(cli, ["pr-analysis", str(tmp_path)])
    assert res.exit_code == 0
    assert "QV Pull Request Analysis" in res.output


def test_scan_pr_options_and_sarif_metadata(tmp_path: Path, monkeypatch):
    """Verify scan --pr respects --strict, --hide-warnings, --errors-only, and emits true metadata in SARIF."""
    runner = CliRunner()
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "scan-metadata-test"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["unimported-lib"]
""",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("import sys\n", encoding="utf-8")

    # 1. Without strict/ci, warning exits 0
    res_normal = runner.invoke(cli, ["scan", str(tmp_path), "--pr"])
    assert res_normal.exit_code == 0

    # 2. With --strict, warning causes exit code 1
    res_strict = runner.invoke(cli, ["scan", str(tmp_path), "--pr", "--strict"])
    assert res_strict.exit_code == 1

    # 3. With --ci, warning causes exit code 1
    res_ci = runner.invoke(cli, ["scan", str(tmp_path), "--pr", "--ci"])
    assert res_ci.exit_code == 1

    # 4. With --hide-warnings, warnings are suppressed
    res_hide = runner.invoke(cli, ["scan", str(tmp_path), "--pr", "--hide-warnings"])
    assert res_hide.exit_code == 0
    assert "DEP-003" not in res_hide.output

    # 5. With --errors-only, warning is filtered out
    res_errors_only = runner.invoke(cli, ["scan", str(tmp_path), "--pr", "--errors-only"])
    assert res_errors_only.exit_code == 0
    assert "DEP-003" not in res_errors_only.output

    # 6. With --min-severity error, warning is filtered out
    res_min_sev = runner.invoke(cli, ["scan", str(tmp_path), "--pr", "--min-severity", "error"])
    assert res_min_sev.exit_code == 0
    assert "DEP-003" not in res_min_sev.output

    # 7. With --sarif, check SARIF JSON contains valid tool metadata and head info
    res_sarif = runner.invoke(cli, ["scan", str(tmp_path), "--pr", "--sarif"])
    assert res_sarif.exit_code == 0
    sarif_data = json.loads(res_sarif.output)
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"]) > 0
    assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "qv"
