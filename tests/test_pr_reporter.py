"""Unit tests for Pull Request Reporter, annotations, and step summary."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from qv.core.models import Diagnostic, Severity
from qv.core.pr import PRAnalysisResult, ResolvedIssue
from qv.reporters.pr_reporter import PRReporter


def test_pr_reporter_terminal_output():
    """Verify PRReporter formats terminal output matching PR analysis specification."""
    new_diag1 = Diagnostic(
        id="FAP-021",
        severity=Severity.ERROR,
        category="framework",
        title="Async endpoint performs blocking I/O",
        message="Async endpoint performs blocking I/O",
        file="users.py",
        line=42,
    )
    new_diag2 = Diagnostic(
        id="DEP-002",
        severity=Severity.ERROR,
        category="dependency",
        title="Missing declaration for httpx",
        message="Missing declaration for httpx",
        file="requirements.txt",
    )
    resolved = ResolvedIssue(
        id="SQL-008",
        title="Legacy Column() with Mapped",
        message="Legacy Column usage",
        file="models.py",
        line=15,
        severity=Severity.WARNING,
    )

    pr_result = PRAnalysisResult(
        project_name="my-app",
        project_path="/app",
        changed_files_count=8,
        changed_files=["users.py", "requirements.txt"],
        affected_checks_count=17,
        new_issues=[new_diag1, new_diag2],
        resolved_issues=[resolved],
        total_issues_head=2,
        total_issues_base=1,
    )

    reporter = PRReporter()
    rendered = reporter.render(pr_result, no_color=True)

    assert "QV Pull Request Analysis" in rendered
    assert "Changed files: 8" in rendered
    assert "Affected checks: 17" in rendered
    assert "New issues" in rendered
    assert "FAP-021" in rendered
    assert "users.py:42" in rendered
    assert "Async endpoint performs blocking I/O" in rendered
    assert "DEP-002" in rendered
    assert "requirements.txt" in rendered
    assert "Resolved" in rendered
    assert "SQL-008" in rendered


def test_pr_reporter_annotations_and_step_summary(tmp_path: Path, capsys):
    """Verify PRReporter emits workflow command annotations and appends to step summary."""
    new_diag = Diagnostic(
        id="FAP-021",
        severity=Severity.ERROR,
        category="framework",
        title="Async endpoint performs blocking I/O",
        message="Call to blocking sleep inside async route handler.",
        file="src/users.py",
        line=42,
    )
    resolved = ResolvedIssue(
        id="SQL-008",
        title="Legacy Column() with Mapped",
        message="Legacy Column usage",
        severity=Severity.WARNING,
    )

    pr_result = PRAnalysisResult(
        project_name="demo-service",
        project_path=str(tmp_path),
        changed_files_count=3,
        changed_files=["src/users.py"],
        affected_checks_count=12,
        new_issues=[new_diag],
        resolved_issues=[resolved],
    )

    reporter = PRReporter()
    reporter.emit_annotations(pr_result)

    captured = capsys.readouterr()
    assert (
        "::error file=src/users.py,line=42,title=FAP-021: Async endpoint performs blocking I/O::Call to blocking sleep inside async route handler."
        in captured.out
    )

    # Step summary
    summary_file = tmp_path / "step_summary.md"
    with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary_file)}):
        reporter.write_step_summary(pr_result)

    assert summary_file.exists()
    content = summary_file.read_text(encoding="utf-8")
    assert "# 🔍 QV Pull Request Analysis: demo-service" in content
    assert "FAP-021" in content
    assert "SQL-008" in content
    assert "Changed Files" in content


def test_pr_reporter_clean_state():
    """Verify PRReporter produces clean outputs when no new issues or regressions exist."""
    pr_result = PRAnalysisResult(
        project_name="clean-app",
        project_path="/app",
        changed_files_count=2,
        changed_files=["main.py"],
        affected_checks_count=10,
        new_issues=[],
        resolved_issues=[],
    )

    reporter = PRReporter()
    rendered = reporter.render(pr_result)
    assert "No new issues introduced in this PR!" in rendered

    md = reporter.render_markdown(pr_result)
    assert "No new issues or regressions detected in this PR." in md
