"""Analyzer protocol and base classes."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from qv.core.context import ProjectContext
from qv.core.models import Diagnostic


@runtime_checkable
class Analyzer(Protocol):
    """Protocol for all diagnostic analyzers."""

    id: str
    name: str
    description: str

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        """Analyze project context and return list of diagnostics."""
        ...
