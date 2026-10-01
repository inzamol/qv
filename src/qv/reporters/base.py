"""Base reporter interface."""

from __future__ import annotations

from typing import Protocol

from qv.core.models import ScanResult


class Reporter(Protocol):
    """Protocol for diagnostic output formatters."""

    def render(self, result: ScanResult) -> str:
        """Render scan result to string output."""
        ...
