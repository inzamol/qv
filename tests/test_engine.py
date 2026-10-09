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
    rules: tuple[str, ...] = ("CRASH-001",)

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        """Raise a RuntimeError to simulate an analyzer crash."""
        raise RuntimeError("Simulated internal analyzer crash in parsing AST")


class HealthyAnalyzer(Analyzer):
    """An analyzer that succeeds and returns findings."""

    id: str = "HEALTHY-001"
    name: str = "HealthyAnalyzer"
    description: str = "Simulates healthy analyzer execution for testing"
    rules: tuple[str, ...] = ("DEP-003", "DEP-004")

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        """Return a sample DEP-003 warning diagnostic."""
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
    """Build a minimal ProjectContext for use in engine tests."""
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
        """Patch AnalysisEngine.__init__ to always use a CrashingAnalyzer."""
        original_init(self, config=config, analyzers=[CrashingAnalyzer()])

    monkeypatch.setattr(AnalysisEngine, "__init__", mock_init)

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "ENG-001" in result.output
    assert "CrashingAnalyzer" in result.output


def test_reported_check_counts_reflect_actual_analysis(tmp_path: Path):
    """Test that checks_passed reflects actual evaluated rules minus failed rules."""
    context = create_sample_context(tmp_path)

    # HealthyAnalyzer evaluates ("DEP-003", "DEP-004") and emits finding for DEP-003
    engine = AnalysisEngine(
        config=QvConfig(),
        analyzers=[HealthyAnalyzer()],
    )
    result = engine.run(context)

    # Evaluated rules: DEP-003, DEP-004 (2 rules)
    # Failed rules: DEP-003 (1 rule)
    # Checks passed: DEP-004 (1 check)
    assert result.summary.checks_passed == 1
    assert result.summary.warnings_count == 1
    assert result.summary.errors_count == 0


def test_reported_check_counts_with_disabled_rule(tmp_path: Path):
    """Test that disabled rules are excluded from evaluated and passed counts."""
    context = create_sample_context(tmp_path)

    config = QvConfig(ignored_rules={"DEP-003"})
    engine = AnalysisEngine(
        config=config,
        analyzers=[HealthyAnalyzer()],
    )
    result = engine.run(context)

    # Evaluated rules: DEP-004 (1 rule, since DEP-003 is ignored)
    # Failed rules: 0 (DEP-003 finding was filtered out)
    # Checks passed: DEP-004 (1 check)
    assert result.summary.checks_passed == 1
    assert result.summary.warnings_count == 0


def test_reported_check_counts_across_multiple_analyzers(tmp_path: Path):
    """Test that passed check counts dynamically change when analyzers are added or removed."""
    from qv.analyzers.dependencies.analyzer import DependencyAnalyzer
    from qv.analyzers.packaging.analyzer import PackagingAnalyzer

    context = create_sample_context(tmp_path)

    # PackagingAnalyzer (PKG-001, PKG-002) = 2 rules
    # On empty context without pyproject.toml, PKG analyzer returns 0 diagnostics -> 2 passed
    pkg_engine = AnalysisEngine(
        config=QvConfig(),
        analyzers=[PackagingAnalyzer()],
    )
    pkg_res = pkg_engine.run(context)
    assert pkg_res.summary.checks_passed == 2

    # DependencyAnalyzer (DEP-001, DEP-002, DEP-003, DEP-004, DEP-005, DEP-007) = 6 rules
    # Both analyzers together = 8 rules
    combined_engine = AnalysisEngine(
        config=QvConfig(),
        analyzers=[PackagingAnalyzer(), DependencyAnalyzer()],
    )
    combined_res = combined_engine.run(context)
    assert combined_res.summary.checks_passed == 8


def test_reported_check_counts_with_unknown_status_analyzer(tmp_path: Path):
    """Test that analyzers with UNKNOWN status (e.g. unreachable API) do not report declared rules as passed."""
    from unittest.mock import MagicMock

    from qv.analyzers.security.analyzer import SecurityAnalyzer
    from qv.analyzers.security.osv_client import OsvClient, OsvUnavailableError
    from qv.core.context import InstalledDistribution

    # Context with an installed package
    context = ProjectContext(
        project_root=tmp_path,
        project_name="security-test",
        python_runtime=PythonRuntime("3.12.0", 3, 12, 0),
        package_manager="uv",
        manifest_files=(),
        lock_files=(),
        dependencies=(),
        installed_packages={
            "requests": InstalledDistribution(
                name="requests",
                version="2.31.0",
                requires=(),
            )
        },
        source_files=(),
        imports=(),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    # Mock OSV client raising OsvUnavailableError
    mock_osv = MagicMock(spec=OsvClient)
    mock_osv.query_packages.side_effect = OsvUnavailableError("Network unreachable")

    analyzer = SecurityAnalyzer(osv_client=mock_osv)
    engine = AnalysisEngine(config=QvConfig(), analyzers=[analyzer])
    result = engine.run(context)

    # SecurityAnalyzer emitted SEC-001 warning and status is UNKNOWN
    # DEP-006 must NOT be counted as a passed check
    assert result.summary.warnings_count == 1
    assert result.summary.checks_passed == 0
    assert any(d.id == "SEC-001" for d in result.diagnostics)


def test_reported_check_counts_with_filtered_warnings(tmp_path: Path):
    """Test that hiding warnings removes them from display but still counts them as failed rules."""
    context = create_sample_context(tmp_path)

    # HealthyAnalyzer evaluates ("DEP-003", "DEP-004") and emits a warning finding for DEP-003
    config = QvConfig(hide_warnings=True)
    engine = AnalysisEngine(
        config=config,
        analyzers=[HealthyAnalyzer()],
    )
    result = engine.run(context)

    # Displayed diagnostics should filter out the warning
    assert len(result.diagnostics) == 0
    assert result.summary.warnings_count == 0

    # Checks passed must still only be 1 (DEP-004), since DEP-003 failed during analysis
    assert result.summary.checks_passed == 1


def test_check_counts_all_rules_pass(tmp_path: Path):
    """AC-09 Case 1: When all evaluated rules pass, checks_passed equals total enabled rules."""
    context = create_sample_context(tmp_path)

    class AllPassAnalyzer(Analyzer):
        id = "PASS-001"
        name = "AllPassAnalyzer"
        description = "Test analyzer where all rules pass"
        rules = ("RULE-1", "RULE-2", "RULE-3")

        def analyze(self, context: ProjectContext) -> list[Diagnostic]:
            return []

    engine = AnalysisEngine(config=QvConfig(), analyzers=[AllPassAnalyzer()])
    result = engine.run(context)
    assert result.summary.checks_passed == 3
    assert result.summary.errors_count == 0
    assert result.summary.warnings_count == 0


def test_check_counts_one_rule_multiple_diagnostics(tmp_path: Path):
    """AC-09 Case 2: When one rule produces multiple diagnostics, it only counts as 1 failed rule."""
    context = create_sample_context(tmp_path)

    class MultiDiagAnalyzer(Analyzer):
        id = "MULTI-001"
        name = "MultiDiagAnalyzer"
        description = "Test analyzer producing multiple diagnostics per rule"
        rules = ("DEP-001", "DEP-002", "DEP-003")

        def analyze(self, context: ProjectContext) -> list[Diagnostic]:
            # DEP-002 produces 3 separate diagnostics
            return [
                Diagnostic(
                    id="DEP-002",
                    severity=Severity.ERROR,
                    category="dependency",
                    title="Missing pkg1",
                    message="pkg1 missing",
                ),
                Diagnostic(
                    id="DEP-002",
                    severity=Severity.ERROR,
                    category="dependency",
                    title="Missing pkg2",
                    message="pkg2 missing",
                ),
                Diagnostic(
                    id="DEP-002",
                    severity=Severity.ERROR,
                    category="dependency",
                    title="Missing pkg3",
                    message="pkg3 missing",
                ),
            ]

    engine = AnalysisEngine(config=QvConfig(), analyzers=[MultiDiagAnalyzer()])
    result = engine.run(context)

    # Total evaluated rules: 3 (DEP-001, DEP-002, DEP-003)
    # Failed rules: 1 (DEP-002)
    # Passed checks: 2 (DEP-001, DEP-003)
    assert result.summary.checks_passed == 2
    assert result.summary.errors_count == 3
    assert len(result.diagnostics) == 3


def test_check_counts_rule_disabled_and_ignored(tmp_path: Path):
    """AC-09 Cases 3 & 4: Disabled and ignored rules do not count as passed or failed."""
    context = create_sample_context(tmp_path)

    class ThreeRuleAnalyzer(Analyzer):
        id = "THREE-001"
        name = "ThreeRuleAnalyzer"
        description = "Test analyzer with three rules"
        rules = ("RULE-A", "RULE-B", "RULE-C")

        def analyze(self, context: ProjectContext) -> list[Diagnostic]:
            return []

    # Disable RULE-A and ignore RULE-B
    from qv.core.config import RuleConfig

    config = QvConfig(
        rules={"RULE-A": RuleConfig(disabled=True)},
        ignored_rules={"RULE-B"},
    )
    engine = AnalysisEngine(config=config, analyzers=[ThreeRuleAnalyzer()])
    result = engine.run(context)

    # Only RULE-C is evaluated and passed
    assert result.summary.checks_passed == 1


def test_check_counts_analyzer_failure_does_not_count_as_passed(tmp_path: Path):
    """AC-09 Case 5 & AC-08: A failed analyzer's rules are not counted as passed, and failure is visible."""
    context = create_sample_context(tmp_path)

    class FailingAnalyzer(Analyzer):
        id = "FAIL-001"
        name = "FailingAnalyzer"
        description = "Test failing analyzer"
        rules = ("RULE-X", "RULE-Y")

        def analyze(self, context: ProjectContext) -> list[Diagnostic]:
            raise RuntimeError("test failure")

    class SiblingAnalyzer(Analyzer):
        id = "SIB-001"
        name = "SiblingAnalyzer"
        description = "Test sibling analyzer"
        rules = ("RULE-Z",)

        def analyze(self, context: ProjectContext) -> list[Diagnostic]:
            return []

    engine = AnalysisEngine(config=QvConfig(), analyzers=[FailingAnalyzer(), SiblingAnalyzer()])
    result = engine.run(context)

    # FailingAnalyzer status = FAILED
    failed_ar = next(r for r in result.analyzer_results if r.analyzer_name == "FailingAnalyzer")
    assert failed_ar.status == AnalyzerStatus.FAILED

    # SiblingAnalyzer still continued and passed
    sib_ar = next(r for r in result.analyzer_results if r.analyzer_name == "SiblingAnalyzer")
    assert sib_ar.status == AnalyzerStatus.OK

    # ENG-001 diagnostic exists
    assert any(d.id == "ENG-001" for d in result.diagnostics)
    # Scan did not silently pass
    assert result.has_blocking_errors is True

    # Checks passed only includes RULE-Z from SiblingAnalyzer (RULE-X and RULE-Y from failed analyzer are NOT passed)
    assert result.summary.checks_passed == 1


def test_check_counts_severity_filtering(tmp_path: Path):
    """AC-09 Case 6: Severity filtering removes diagnostic from display but rule is not counted as passed."""
    context = create_sample_context(tmp_path)

    class WarnAnalyzer(Analyzer):
        id = "WARN-001"
        name = "WarnAnalyzer"
        description = "Test warning analyzer"
        rules = ("RULE-W", "RULE-P")

        def analyze(self, context: ProjectContext) -> list[Diagnostic]:
            return [
                Diagnostic(
                    id="RULE-W",
                    severity=Severity.WARNING,
                    category="test",
                    title="Warn finding",
                    message="Warn",
                )
            ]

    # Filter by min_severity = ERROR (removes RULE-W warning)
    config = QvConfig(min_severity=Severity.ERROR)
    engine = AnalysisEngine(config=config, analyzers=[WarnAnalyzer()])
    result = engine.run(context)

    assert len(result.diagnostics) == 0
    # RULE-P passed (1 check), RULE-W was not passed
    assert result.summary.checks_passed == 1
