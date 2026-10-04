"""Unit tests for reporters."""

import json

from qv import __version__
from qv.core.models import Diagnostic, ScanResult, Severity
from qv.reporters.json_reporter import JsonReporter
from qv.reporters.sarif import SarifReporter
from qv.reporters.terminal import TerminalReporter


def test_reporters():
    diag = Diagnostic(
        id="DEP-001",
        severity=Severity.ERROR,
        category="dependency",
        title="Conflict",
        message="Conflict between A and B",
        file="pyproject.toml",
        line=10,
    )
    result = ScanResult.create(
        project_name="demo",
        project_path="/demo",
        python_version="3.12.0",
        package_manager="uv",
        diagnostics=[diag],
    )

    # 1. Terminal reporter
    term = TerminalReporter()
    output_str = term.render(result)
    assert "qv" in output_str
    assert "DEP-001" in output_str

    # 2. JSON reporter
    json_rep = JsonReporter()
    json_str = json_rep.render(result)
    data = json.loads(json_str)
    assert data["project_name"] == "demo"
    assert len(data["diagnostics"]) == 1

    # 3. SARIF reporter
    sarif_rep = SarifReporter()
    sarif_str = sarif_rep.render(result)
    sarif_data = json.loads(sarif_str)
    assert sarif_data["version"] == "2.1.0"
    assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "qv"
    assert sarif_data["runs"][0]["tool"]["driver"]["semanticVersion"] == __version__
    assert len(sarif_data["runs"][0]["results"]) == 1
    assert sarif_data["runs"][0]["results"][0]["ruleId"] == "DEP-001"

    # 4. SARIF reporter with explicit version
    custom_sarif = SarifReporter(tool_version="2.0.0").to_sarif_dict(result)
    assert custom_sarif["runs"][0]["tool"]["driver"]["semanticVersion"] == "2.0.0"
