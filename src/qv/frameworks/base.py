"""Base protocol and registry for framework-specific analyzers."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from qv.core.context import ProjectContext
from qv.core.models import Diagnostic


@runtime_checkable
class FrameworkPlugin(Protocol):
    """Protocol for framework-specific diagnostic plugins."""

    id: str
    name: str
    description: str

    def detect(self, context: ProjectContext) -> bool:
        """Detect if this framework is actively used in the project."""
        ...

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        """Analyze the project context for framework-specific issues."""
        ...
