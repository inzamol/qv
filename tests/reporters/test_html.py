"""Tests for HtmlReporter."""

from __future__ import annotations

from pathlib import Path

from qv.core.models import Diagnostic, Evidence, ScanResult, Severity, Suggestion
from qv.reporters.html_reporter import HtmlReporter


def test_html_reporter_generates_valid_html(tmp_path: Path):
    diag = Diagnostic(
        id="DEP-002",
        severity=Severity.ERROR,
        category="dependency",
        title="Missing dependency declaration: httpx",
        message="Package 'httpx' is imported in source code but not declared.",
        file="app/main.py",
        line=10,
        evidence=[Evidence(fact="Imported 'httpx' at app/main.py:10", source="app/main.py")],
        suggestions=[Suggestion(description="Add 'httpx' to dependencies", command="uv add httpx")],
        doc_url="https://github.com/inzamol/qv/blob/main/docs/rules.md#dep-002",
    )

    result = ScanResult.create(
        project_name="demo-app",
        project_path="/workspace/demo-app",
        python_version="3.12.0",
        package_manager="uv",
        diagnostics=[diag],
        checks_passed=45,
    )

    reporter = HtmlReporter()
    html_output = reporter.render(result)

    assert "<!DOCTYPE html>" in html_output
    assert "qv Health Report - demo-app" in html_output
    assert "Missing dependency declaration: httpx" in html_output
    assert "DEP-002" in html_output
    assert "uv add httpx" in html_output
    assert "toggleTheme" in html_output
    assert "filterDiagnostics" in html_output
