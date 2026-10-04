"""Analysis engine coordinating analyzer execution and root cause grouping."""

from __future__ import annotations

from collections.abc import Sequence

from qv.analyzers.dependencies.analyzer import DependencyAnalyzer
from qv.analyzers.environment.drift import EnvironmentAnalyzer
from qv.analyzers.imports.analyzer import ImportAnalyzer
from qv.analyzers.packaging.analyzer import PackagingAnalyzer
from qv.analyzers.security.analyzer import SecurityAnalyzer
from qv.core.analyzer import Analyzer
from qv.core.config import QvConfig
from qv.core.context import ProjectContext
from qv.core.models import (
    AnalyzerExecutionResult,
    AnalyzerStatus,
    Diagnostic,
    Evidence,
    RootCause,
    ScanResult,
    Severity,
    Suggestion,
)
from qv.frameworks.fastapi import FastApiAnalyzer
from qv.frameworks.sqlalchemy import SqlAlchemyAnalyzer


class AnalysisEngine:
    """Coordinates execution of analyzers, applies config, and correlates root causes."""

    def __init__(
        self,
        config: QvConfig | None = None,
        analyzers: Sequence[Analyzer] | None = None,
    ) -> None:
        self.config = config or QvConfig()
        if analyzers is not None:
            self.analyzers = list(analyzers)
        else:
            self.analyzers = [
                PackagingAnalyzer(),
                EnvironmentAnalyzer(),
                DependencyAnalyzer(),
                ImportAnalyzer(),
                SecurityAnalyzer(),
                FastApiAnalyzer(),
                SqlAlchemyAnalyzer(),
            ]

    def run(self, context: ProjectContext) -> ScanResult:
        """Run all registered analyzers against the given ProjectContext."""
        raw_diagnostics: list[Diagnostic] = []
        analyzer_results: list[AnalyzerExecutionResult] = []
        checks_evaluated = 0

        for analyzer in self.analyzers:
            checks_evaluated += 1
            analyzer_name = getattr(analyzer, "name", analyzer.__class__.__name__)
            try:
                findings = analyzer.analyze(context)
                status = getattr(analyzer, "status", AnalyzerStatus.OK)
                raw_diagnostics.extend(findings)
                analyzer_results.append(
                    AnalyzerExecutionResult(
                        analyzer_name=analyzer_name,
                        status=status,
                        diagnostics_count=len(findings),
                    )
                )
            except Exception as exc:
                error_msg = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
                analyzer_results.append(
                    AnalyzerExecutionResult(
                        analyzer_name=analyzer_name,
                        status=AnalyzerStatus.FAILED,
                        error=error_msg,
                        diagnostics_count=0,
                    )
                )
                diag = Diagnostic(
                    id="ENG-001",
                    severity=Severity.ERROR,
                    category="engine",
                    title=f"Analyzer execution failed: {analyzer_name}",
                    message=f"Analyzer '{analyzer_name}' failed with unexpected error: {error_msg}",
                    evidence=[
                        Evidence(
                            fact=f"Analyzer: {analyzer_name}",
                            source="AnalysisEngine",
                        ),
                        Evidence(
                            fact=f"Error: {error_msg}",
                            source="Exception",
                        ),
                    ],
                    suggestions=[
                        Suggestion(
                            description=f"Inspect project files or report an issue for {analyzer_name}.",
                            is_safe=False,
                        )
                    ],
                    metadata={"analyzer": analyzer_name, "error": error_msg},
                )
                raw_diagnostics.append(diag)

        # Apply configuration (filtering and severity overrides)
        filtered_diagnostics: list[Diagnostic] = []
        for diag in raw_diagnostics:
            if not self.config.is_rule_enabled(diag.id):
                continue

            effective_sev = self.config.get_effective_severity(diag.id, diag.severity)

            if self.config.hide_warnings and effective_sev == Severity.WARNING:
                continue
            if self.config.errors_only and effective_sev != Severity.ERROR:
                continue
            if self.config.min_severity:
                sev_order = {Severity.ERROR: 3, Severity.WARNING: 2, Severity.INFO: 1}
                if sev_order.get(effective_sev, 0) < sev_order.get(self.config.min_severity, 0):
                    continue

            updated_diag = diag.model_copy(update={"severity": effective_sev})
            filtered_diagnostics.append(updated_diag)

        # Correlate root causes
        root_causes = self._correlate_root_causes(filtered_diagnostics)

        # Calculate passed checks approximation
        passed_count = max(0, 30 + checks_evaluated * 5 - len(filtered_diagnostics))

        return ScanResult.create(
            project_name=context.project_name,
            project_path=str(context.project_root),
            python_version=context.python_runtime.version_str,
            package_manager=context.package_manager,
            diagnostics=filtered_diagnostics,
            checks_passed=passed_count,
            root_causes=root_causes,
            analyzer_results=analyzer_results,
        )

    def _correlate_root_causes(self, diagnostics: list[Diagnostic]) -> list[RootCause]:
        """Group related diagnostics by affected packages or rule categories."""
        root_causes: list[RootCause] = []
        package_groups: dict[str, list[Diagnostic]] = {}

        for diag in diagnostics:
            if diag.affected_packages:
                for pkg in diag.affected_packages:
                    package_groups.setdefault(pkg.lower(), []).append(diag)

        seen_diags: set[str] = set()
        rc_counter = 1

        for pkg, group in package_groups.items():
            if len(group) > 1:
                group_ids = [d.id for d in group]
                if any(gid in seen_diags for gid in group_ids):
                    continue

                primary = group[0]
                primary_suggestion = (
                    primary.suggestions[0]
                    if primary.suggestions
                    else Suggestion(description=f"Resolve dependencies for {pkg}")
                )

                root_causes.append(
                    RootCause(
                        id=f"ROOT-{rc_counter:03d}",
                        title=f"Package integrity issue with '{pkg}'",
                        summary=f"Found {len(group)} related findings affecting package '{pkg}'.",
                        primary_diagnostic=primary,
                        related_diagnostics=group[1:],
                        recommendation=primary_suggestion,
                    )
                )
                rc_counter += 1
                for d in group:
                    seen_diags.add(d.id)

        return root_causes
