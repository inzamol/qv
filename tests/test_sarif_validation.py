"""Tests for SARIF output correctness (AC-10)."""

import json
from pathlib import Path

from click.testing import CliRunner

from qv.cli.main import cli
from qv.core.models import Diagnostic, ScanResult, Severity
from qv.reporters.sarif import SarifReporter


def test_sarif_structure_and_schema(tmp_path: Path):
    """AC-10: SARIF output must conform to schema, preserve rule IDs, and include locations."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "sarif-test"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )
    main_py = tmp_path / "main.py"
    main_py.write_text("import missing_pkg\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path), "--format", "sarif"])
    assert result.exit_code == 1

    sarif_data = json.loads(result.output)
    assert sarif_data["version"] == "2.1.0"
    assert "$schema" in sarif_data
    assert "runs" in sarif_data
    assert len(sarif_data["runs"]) == 1

    run = sarif_data["runs"][0]
    assert run["tool"]["driver"]["name"] == "qv"

    # Verify rule catalog in tool driver
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert "DEP-002" in rule_ids

    # Verify results
    assert len(run["results"]) >= 1
    dep_result = next(r for r in run["results"] if r["ruleId"] == "DEP-002")
    assert dep_result["level"] == "error"
    assert "locations" in dep_result
    loc = dep_result["locations"][0]["physicalLocation"]
    assert "main.py" in loc["artifactLocation"]["uri"]
    assert loc["region"]["startLine"] == 1


def test_sarif_analyzer_failure_representation(tmp_path: Path):
    """AC-10: Analyzer failure is represented as an error diagnostic in SARIF."""
    scan_res = ScanResult.create(
        project_name="fail-test",
        project_path=str(tmp_path),
        python_version="3.12.0",
        package_manager="uv",
        diagnostics=[
            Diagnostic(
                id="ENG-001",
                severity=Severity.ERROR,
                category="engine",
                title="Analyzer execution failed: BrokenAnalyzer",
                message="Analyzer 'BrokenAnalyzer' raised unexpected exception: RuntimeError('test')",
            )
        ],
    )

    reporter = SarifReporter()
    output = reporter.render(scan_res)
    sarif_json = json.loads(output)

    results = sarif_json["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "ENG-001"
    assert results[0]["level"] == "error"
    assert "BrokenAnalyzer" in results[0]["message"]["text"]
