"""Unit tests for core models."""

from qv.core.models import Diagnostic, ScanResult, Severity


def test_severity_ranking():
    assert Severity.INFO.rank < Severity.WARNING.rank < Severity.ERROR.rank


def test_scan_result_health_score_calculation():
    diag_err = Diagnostic(
        id="DEP-001",
        severity=Severity.ERROR,
        category="dependency",
        title="Conflict",
        message="Conflict error",
    )
    diag_warn = Diagnostic(
        id="DEP-003",
        severity=Severity.WARNING,
        category="dependency",
        title="Unused",
        message="Unused warning",
    )

    result = ScanResult.create(
        project_name="test",
        project_path="/tmp/test",
        python_version="3.12.0",
        package_manager="uv",
        diagnostics=[diag_err, diag_warn],
        checks_passed=20,
    )

    assert result.has_blocking_errors is True
    assert result.summary.errors_count == 1
    assert result.summary.warnings_count == 1
    # 100 - (1*15 + 1*5) = 80
    assert result.summary.health_score == 80


def test_scan_result_no_errors():
    result = ScanResult.create(
        project_name="clean-test",
        project_path="/tmp/clean",
        python_version="3.12.0",
        package_manager="pip",
        diagnostics=[],
        checks_passed=30,
    )
    assert result.has_blocking_errors is False
    assert result.summary.health_score == 100
