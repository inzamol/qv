"""Unit and integration tests for 'qv doctor' command and DoctorReporter."""

import json

from click.testing import CliRunner

from qv.cli.main import cli
from qv.core.models import Diagnostic, ScanResult, Severity
from qv.reporters.doctor_reporter import DoctorReporter, make_bar


def test_make_bar_ranges():
    assert make_bar(100) == "██████████"
    assert make_bar(96) == "██████████"
    assert make_bar(92) == "█████████░"
    assert make_bar(84) == "████████░░"
    assert make_bar(78) == "████████░░"
    assert make_bar(91) == "█████████░"
    assert make_bar(88) == "█████████░"
    assert make_bar(50) == "█████░░░░░"
    assert make_bar(0) == "░░░░░░░░░░"


def test_doctor_reporter_empty_findings():
    result = ScanResult.create(
        project_name="healthy-app",
        project_path="/app",
        python_version="3.12.0",
        package_manager="uv",
        diagnostics=[],
        checks_passed=42,
    )
    reporter = DoctorReporter()
    report = reporter.build_report(result)

    assert report.health_score == 100
    assert report.errors_count == 0
    assert report.warnings_count == 0
    assert report.checks_passed == 42
    assert len(report.top_problems) == 0
    assert report.explain_hint is None
    for cat in report.categories:
        assert cat.score == 100
        assert cat.bar == "██████████"

    rendered = reporter.render(result)
    assert "QV Project Health" in rendered
    assert "Health Score: 100/100" in rendered
    assert "42 checks passed" in rendered
    assert "No issues detected" in rendered


def test_doctor_reporter_with_findings():
    diags = [
        Diagnostic(
            id="SQL-014",
            severity=Severity.ERROR,
            category="framework",
            title="N+1 query detected",
            message="N+1 query inside loop",
        ),
        Diagnostic(
            id="DEP-002",
            severity=Severity.ERROR,
            category="dependency",
            title="Missing dependency declaration",
            message="Package httpx is missing",
            affected_packages=["httpx"],
        ),
        Diagnostic(
            id="ENV-003",
            severity=Severity.WARNING,
            category="environment",
            title="CI runtime drift",
            message="CI Python mismatch",
        ),
    ]
    result = ScanResult.create(
        project_name="test-project",
        project_path="/proj",
        python_version="3.11.0",
        package_manager="pip",
        diagnostics=diags,
        checks_passed=39,
    )
    reporter = DoctorReporter(top_n=3)
    report = reporter.build_report(result)

    assert report.errors_count == 2
    assert report.warnings_count == 1
    assert len(report.top_problems) == 3
    assert report.top_problems[0].id == "SQL-014"
    assert report.top_problems[1].id == "DEP-002"
    assert "httpx" in report.top_problems[1].title
    assert report.top_problems[2].id == "ENV-003"
    assert report.explain_hint == "qv explain SQL-014"

    rendered = reporter.render(result)
    assert "QV Project Health" in rendered
    assert "Top problems:" in rendered
    assert "SQL-014" in rendered
    assert "DEP-002" in rendered
    assert "ENV-003" in rendered
    assert "qv explain SQL-014" in rendered


def test_cli_doctor_healthy_project(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "healthy-sample"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor", str(tmp_path), "--offline"])
    assert result.exit_code == 0
    assert "QV Project Health" in result.output
    assert "Dependencies" in result.output
    assert "Security" in result.output
    assert "Packaging" in result.output
    assert "Architecture" in result.output
    assert "Environment" in result.output
    assert "Framework" in result.output
    assert "Health Score:" in result.output


def test_cli_doctor_json_output(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "json-doctor-sample"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor", str(tmp_path), "--json", "--offline"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["project_name"] == "json-doctor-sample"
    assert "health_score" in data
    assert "categories" in data
    assert len(data["categories"]) == 6
    assert data["errors_count"] == 0


def test_cli_doctor_unhealthy_exit_code(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "unhealthy-sample"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )
    src_file = tmp_path / "app.py"
    src_file.write_text(
        """
import nonexistent_unregistered_package
""",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor", str(tmp_path), "--offline"])
    assert result.exit_code == 1
    assert "DEP-002" in result.output
    assert "Top problems:" in result.output


def test_cli_doctor_file_output(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "file-out-sample"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )
    out_file = tmp_path / "doctor_report.txt"
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor", str(tmp_path), "--output", str(out_file), "--offline"])
    assert result.exit_code == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "QV Project Health" in content
