"""Unit tests for baseline snapshots and differential scanning."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from qv.cli.main import cli
from qv.core.baseline import (
    filter_against_baseline,
    load_baseline_fingerprints,
    save_baseline,
)
from qv.core.models import Diagnostic, ScanResult, Severity, Suggestion


def _create_sample_result() -> ScanResult:
    diag1 = Diagnostic(
        id="DEP-002",
        severity=Severity.ERROR,
        category="dependency",
        title="Missing dependency: requests",
        message="Package requests is imported but not in dependencies.",
        file="src/app.py",
        line=10,
        suggestions=[Suggestion(description="Add requests to dependencies")],
    )
    diag2 = Diagnostic(
        id="DOC-005",
        severity=Severity.INFO,
        category="docker",
        title="Missing --no-cache-dir",
        message="pip install without cache cleanup.",
        file="Dockerfile",
        line=5,
    )
    return ScanResult.create(
        project_name="baseline-test",
        project_path="/tmp/baseline",
        python_version="3.12.0",
        package_manager="uv",
        diagnostics=[diag1, diag2],
        checks_passed=5,
    )


def test_baseline_save_and_load(tmp_path: Path):
    result = _create_sample_result()
    baseline_file = tmp_path / ".qv-baseline.json"

    save_baseline(result, baseline_file)
    assert baseline_file.exists()

    data = json.loads(baseline_file.read_text(encoding="utf-8"))
    assert data["project_name"] == "baseline-test"
    assert data["total_diagnostics"] == 2

    fingerprints = load_baseline_fingerprints(baseline_file)
    assert len(fingerprints) == 2

    # Filter against exact same diagnostics -> all suppressed
    new_diags, suppressed = filter_against_baseline(result.diagnostics, fingerprints)
    assert len(new_diags) == 0
    assert suppressed == 2


def test_baseline_differential_filtering(tmp_path: Path):
    result = _create_sample_result()
    baseline_file = tmp_path / ".qv-baseline.json"
    save_baseline(result, baseline_file)
    fingerprints = load_baseline_fingerprints(baseline_file)

    # Introduce a new diagnostic
    new_diag = Diagnostic(
        id="SEC-001",
        severity=Severity.ERROR,
        category="security",
        title="Security advisory CVE-2024-1234",
        message="Critical flaw found in package.",
        file="src/auth.py",
        line=20,
    )
    combined = [*result.diagnostics, new_diag]

    filtered, suppressed = filter_against_baseline(combined, fingerprints)
    assert len(filtered) == 1
    assert filtered[0].id == "SEC-001"
    assert suppressed == 2


def test_baseline_cli_record_and_verify(tmp_path: Path):
    runner = CliRunner()
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[project]\nname = 'test-proj'\nversion = '0.1.0'\ndependencies = []\n",
        encoding="utf-8",
    )
    app = tmp_path / "app.py"
    app.write_text("import fastapi\n", encoding="utf-8")

    baseline_path = tmp_path / "my-baseline.json"

    # 1. Record baseline
    res_rec = runner.invoke(cli, ["baseline", "record", str(tmp_path), "-o", str(baseline_path)])
    assert res_rec.exit_code == 0
    assert baseline_path.exists()

    # 2. Verify baseline -> passes with 0 new issues
    res_ver = runner.invoke(cli, ["baseline", "verify", str(tmp_path), "-b", str(baseline_path)])
    assert res_ver.exit_code == 0
    assert "baseline findings suppressed" in res_ver.output

    # 3. Scan with --baseline
    res_scan = runner.invoke(cli, ["scan", str(tmp_path), "--baseline", str(baseline_path)])
    assert res_scan.exit_code == 0
