"""Unit and integration tests for AnalysisEngine and analyzer execution diagnostics."""

from pathlib import Path

from click.testing import CliRunner

from qv.cli.main import cli
from qv.core.analyzer import Analyzer
from qv.core.config import QvConfig
from qv.core.context import CIConfig, DockerConfig, ProjectContext, PythonRuntime
from qv.core.engine import AnalysisEngine
from qv.core.models import AnalyzerStatus, Diagnostic, Severity
from qv.reporters.json_reporter import JsonReporter
from qv.reporters.sarif import SarifReporter
from qv.reporters.terminal import TerminalReporter


class CrashingAnalyzer(Analyzer):
    """An analyzer that intentionally raises an exception during analysis."""

    id: str = "CRASH-001"
    name: str = "CrashingAnalyzer"
    description: str = "Simulates analyzer failures for testing"

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        raise RuntimeError("Simulated internal analyzer crash in parsing AST")


class HealthyAnalyzer(Analyzer):
    """An analyzer that succeeds and returns findings."""

    id: str = "HEALTHY-001"
    name: str = "HealthyAnalyzer"
    description: str = "Simulates healthy analyzer execution for testing"

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        return [
            Diagnostic(
                id="DEP-003",
                severity=Severity.WARNING,
                category="dependency",
                title="Unused dependency",
                message="Sample warning",
            )
        ]


def create_sample_context(tmp_path: Path) -> ProjectContext:
    return ProjectContext(
        project_root=tmp_path,
        project_name="test-proj",
        python_runtime=PythonRuntime(
            version_str="3.12.0",
            major=3,
            minor=12,
            micro=0,
        ),
        package_manager="uv",
        manifest_files=(),
        lock_files=(),
        dependencies=(),
        installed_packages={},
        source_files=(),
        imports=(),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )


def test_engine_handles_analyzer_crash(tmp_path: Path):
    """Test that analyzer exceptions emit ENG-001 diagnostics and track failure status."""
    context = create_sample_context(tmp_path)

    engine = AnalysisEngine(
        config=QvConfig(),
        analyzers=[CrashingAnalyzer(), HealthyAnalyzer()],
    )

    result = engine.run(context)

    # Must have blocking error because an analyzer crashed
    assert result.has_blocking_errors is True
    assert result.has_analyzer_failures is True
    assert result.summary.analyzers_run == 2
    assert result.summary.analyzers_failed == 1

    # Check analyzer execution results
    crashed_res = next(r for r in result.analyzer_results if r.analyzer_name == "CrashingAnalyzer")
    assert crashed_res.status == AnalyzerStatus.FAILED
    assert "RuntimeError" in (crashed_res.error or "")

    healthy_res = next(r for r in result.analyzer_results if r.analyzer_name == "HealthyAnalyzer")
    assert healthy_res.status == AnalyzerStatus.OK
    assert healthy_res.diagnostics_count == 1

    # Check ENG-001 diagnostic is present
    eng_diags = [d for d in result.diagnostics if d.id == "ENG-001"]
    assert len(eng_diags) == 1
    assert eng_diags[0].severity == Severity.ERROR
    assert "CrashingAnalyzer" in eng_diags[0].title
    assert "Simulated internal analyzer crash" in eng_diags[0].message

    # Ensure other analyzers still ran and contributed findings
    dep_diags = [d for d in result.diagnostics if d.id == "DEP-003"]
    assert len(dep_diags) == 1


def test_reporters_render_analyzer_crash(tmp_path: Path):
    """Test that JSON, SARIF, and Terminal reporters display analyzer failures."""
    context = create_sample_context(tmp_path)

    engine = AnalysisEngine(
        config=QvConfig(),
        analyzers=[CrashingAnalyzer()],
    )
    result = engine.run(context)

    # JSON reporter
    json_out = JsonReporter().render(result)
    assert '"status": "failed"' in json_out
    assert '"ENG-001"' in json_out

    # SARIF reporter
    sarif_out = SarifReporter().render(result)
    assert '"ruleId": "ENG-001"' in sarif_out
    assert '"level": "error"' in sarif_out

    # Terminal reporter
    term_out = TerminalReporter().render(result)
    assert "ENG-001" in term_out
    assert "Analyzer execution failed" in term_out


def test_cli_scan_analyzer_crash_exits_nonzero(tmp_path: Path, monkeypatch):
    """Test that CLI scan exits with non-zero exit code when an analyzer fails."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "test-pkg"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )

    # Patch AnalysisEngine to include a crashing analyzer
    original_init = AnalysisEngine.__init__

    def mock_init(self, config=None, analyzers=None):
        original_init(self, config=config, analyzers=[CrashingAnalyzer()])

    monkeypatch.setattr(AnalysisEngine, "__init__", mock_init)

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "ENG-001" in result.output
    assert "CrashingAnalyzer" in result.output
