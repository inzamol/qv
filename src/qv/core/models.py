"""Core diagnostic and scan result models."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"

    @property
    def rank(self) -> int:
        return {"info": 1, "warning": 2, "error": 3}[self.value]


class Evidence(BaseModel):
    """Fact supporting a diagnostic finding."""

    fact: str
    source: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class Suggestion(BaseModel):
    """Safe, actionable remediation recommendation."""

    description: str
    command: str | None = None
    code_snippet: str | None = None
    is_safe: bool = True


class Diagnostic(BaseModel):
    """Standardized diagnostic finding emitted by all analyzers."""

    id: str
    severity: Severity
    category: str
    title: str
    message: str
    evidence: list[Evidence] = Field(default_factory=list)
    suggestions: list[Suggestion] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    affected_packages: list[str] = Field(default_factory=list)
    file: str | None = None
    line: int | None = None
    column: int | None = None
    dependency_chain: list[str] = Field(default_factory=list)
    doc_url: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RootCause(BaseModel):
    """Group of related symptoms belonging to one underlying root cause."""

    id: str
    title: str
    summary: str
    primary_diagnostic: Diagnostic
    related_diagnostics: list[Diagnostic] = Field(default_factory=list)
    recommendation: Suggestion


class ScanSummary(BaseModel):
    """High-level summary of a scan run."""

    errors_count: int = 0
    warnings_count: int = 0
    info_count: int = 0
    checks_passed: int = 0
    health_score: int = 100


class ScanResult(BaseModel):
    """Complete output of a qv scan."""

    project_name: str
    project_path: str
    python_version: str
    package_manager: str
    summary: ScanSummary
    diagnostics: list[Diagnostic] = Field(default_factory=list)
    root_causes: list[RootCause] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def has_blocking_errors(self) -> bool:
        return self.summary.errors_count > 0

    @classmethod
    def create(
        cls,
        project_name: str,
        project_path: str,
        python_version: str,
        package_manager: str,
        diagnostics: list[Diagnostic],
        checks_passed: int = 0,
        root_causes: list[RootCause] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ScanResult:
        errors = sum(1 for d in diagnostics if d.severity == Severity.ERROR)
        warnings = sum(1 for d in diagnostics if d.severity == Severity.WARNING)
        infos = sum(1 for d in diagnostics if d.severity == Severity.INFO)

        # Health score calculation (100 base, deductions for errors and warnings)
        penalty = (errors * 15) + (warnings * 5)
        health_score = max(0, min(100, 100 - penalty))

        summary = ScanSummary(
            errors_count=errors,
            warnings_count=warnings,
            info_count=infos,
            checks_passed=checks_passed,
            health_score=health_score,
        )

        return cls(
            project_name=project_name,
            project_path=project_path,
            python_version=python_version,
            package_manager=package_manager,
            summary=summary,
            diagnostics=diagnostics,
            root_causes=root_causes or [],
            metadata=metadata or {},
        )
