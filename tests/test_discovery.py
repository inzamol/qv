"""Tests for discovery error handling and scan resilience (AC-03)."""

from pathlib import Path

from click.testing import CliRunner

from qv.cli.main import cli
from qv.core.engine import AnalysisEngine
from qv.core.project import load_project


def test_unreadable_source_file_does_not_abort_scan(tmp_path: Path, monkeypatch):
    """AC-03: A single unreadable source file must not crash the entire scan."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "resilience-demo"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )

    valid_py = tmp_path / "valid.py"
    valid_py.write_text("import os\n", encoding="utf-8")

    unreadable_py = tmp_path / "unreadable.py"
    unreadable_py.write_text("import sys\n", encoding="utf-8")

    original_read_text = Path.read_text

    def mock_read_text(self, *args, **kwargs):
        if self.name == "unreadable.py":
            raise PermissionError("Access denied to unreadable.py")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", mock_read_text)

    # Discovery should succeed without crashing
    project = load_project(tmp_path)
    assert len(project.context.source_files) == 1
    assert project.context.source_files[0].path.name == "valid.py"

    # Discovery diagnostic should be captured
    assert len(project.context.discovery_diagnostics) == 1
    diag = project.context.discovery_diagnostics[0]
    assert diag.id == "DISC-001"
    assert "unreadable.py" in diag.title
    assert "Access denied" in diag.message

    # CLI scan should finish gracefully
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "DISC-001" in result.output
    assert "unreadable.py" in result.output


def test_project_parser_failure_is_reported(tmp_path: Path):
    """AC-03: Syntax errors in source files produce structured diagnostics and do not abort scan."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "syntax-error-demo"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )

    valid_py = tmp_path / "valid.py"
    valid_py.write_text("import math\n", encoding="utf-8")

    bad_syntax_py = tmp_path / "bad_syntax.py"
    bad_syntax_py.write_text("def broken_func(\n", encoding="utf-8")

    project = load_project(tmp_path)
    # Valid file is still parsed
    assert any(sf.path.name == "valid.py" for sf in project.context.source_files)

    # DISC-002 diagnostic is recorded for bad_syntax.py
    syntax_diags = [d for d in project.context.discovery_diagnostics if d.id == "DISC-002"]
    assert len(syntax_diags) == 1
    assert syntax_diags[0].file is not None
    assert "bad_syntax.py" in syntax_diags[0].file

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "DISC-002" in result.output
    assert "bad_syntax.py" in result.output


def test_recoverable_discovery_failure_produces_warning(tmp_path: Path, monkeypatch):
    """AC-03: Recoverable discovery failure produces a warning diagnostic and respects hide_warnings."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "warning-test"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )

    main_py = tmp_path / "main.py"
    main_py.write_text("import os\n", encoding="utf-8")

    unreadable_py = tmp_path / "corrupt.py"
    unreadable_py.write_text("import sys\n", encoding="utf-8")

    original_read_text = Path.read_text

    def mock_read_text(self, *args, **kwargs):
        if self.name == "corrupt.py":
            raise OSError("I/O error reading corrupt.py")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", mock_read_text)

    project = load_project(tmp_path)
    engine = AnalysisEngine(config=project.config)
    scan_result = engine.run(project.context)

    # Produces DISC-001 warning
    disc_diags = [d for d in scan_result.diagnostics if d.id == "DISC-001"]
    assert len(disc_diags) == 1
    assert scan_result.summary.warnings_count == 1

    # With hide_warnings=True, the warning is suppressed
    runner = CliRunner()
    res_hide = runner.invoke(cli, ["scan", str(tmp_path), "--hide-warnings"])
    assert res_hide.exit_code == 0
    assert "DISC-001" not in res_hide.output
