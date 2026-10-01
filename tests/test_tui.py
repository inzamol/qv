"""Tests for TUI Explorer."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from qv.core.models import Diagnostic, Evidence, ScanResult, Severity, Suggestion
from qv.tui.app import TuiExplorer


def test_tui_explorer_render_layout(tmp_path: Path):
    diag = Diagnostic(
        id="DEP-002",
        severity=Severity.ERROR,
        category="dependency",
        title="Missing dependency: pydantic",
        message="Package pydantic is not declared.",
        file="main.py",
        line=1,
        evidence=[Evidence(fact="import pydantic", source="main.py")],
        suggestions=[Suggestion(description="Add pydantic", command="uv add pydantic")],
    )
    result = ScanResult.create(
        project_name="tui_proj",
        project_path=str(tmp_path),
        python_version="3.12.0",
        package_manager="uv",
        diagnostics=[diag],
    )

    console = Console(record=True, width=120)
    explorer = TuiExplorer(result=result, console=console)
    layout = explorer._render_view()

    assert layout is not None
    list_panel = explorer._render_list_panel()
    assert list_panel is not None
    details_panel = explorer._render_details_panel()
    assert details_panel is not None


def test_tui_explorer_empty_state(tmp_path: Path):
    result = ScanResult.create(
        project_name="clean_proj",
        project_path=str(tmp_path),
        python_version="3.12.0",
        package_manager="uv",
        diagnostics=[],
    )

    console = Console(record=True)
    explorer = TuiExplorer(result=result, console=console)
    explorer.run()
    output = console.export_text()
    assert "100% healthy" in output
