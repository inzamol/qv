"""Tests for GitHub Annotator and Step Summary."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from qv.core.models import Diagnostic, ScanResult, Severity
from qv.reporters.github_annotator import GitHubAnnotator


def test_github_annotator_emits_annotations(capsys):
    diag = Diagnostic(
        id="IMP-001",
        severity=Severity.ERROR,
        category="architecture",
        title="Circular import detected",
        message="Circular import between module_a and module_b",
        file="module_a.py",
        line=5,
    )
    result = ScanResult.create(
        project_name="proj",
        project_path="/proj",
        python_version="3.12.0",
        package_manager="uv",
        diagnostics=[diag],
    )

    annotator = GitHubAnnotator()
    annotator.emit_annotations(result)

    captured = capsys.readouterr()
    assert (
        "::error file=module_a.py,line=5,title=IMP-001: Circular import detected::Circular import between module_a and module_b"
        in captured.out
    )


def test_github_annotator_writes_step_summary(tmp_path: Path):
    summary_file = tmp_path / "step_summary.md"
    diag = Diagnostic(
        id="DEP-003",
        severity=Severity.WARNING,
        category="dependency",
        title="Unused declared dependency: requests",
        message="Declared 'requests' is never imported.",
        file="pyproject.toml",
    )
    result = ScanResult.create(
        project_name="proj",
        project_path="/proj",
        python_version="3.12.0",
        package_manager="uv",
        diagnostics=[diag],
    )

    annotator = GitHubAnnotator()
    with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary_file)}):
        annotator.write_step_summary(result)

    assert summary_file.exists()
    content = summary_file.read_text(encoding="utf-8")
    assert "# 🔍 qv Health Report: proj" in content
    assert "DEP-003" in content
    assert "Unused declared dependency: requests" in content
