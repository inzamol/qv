"""JSON reporter for machine-readable diagnostic outputs."""

from __future__ import annotations

from qv.core.models import ScanResult


class JsonReporter:
    """Serializes scan result to formatted JSON string."""

    def __init__(self, indent: int = 2) -> None:
        self.indent = indent

    def render(self, result: ScanResult) -> str:
        """Render scan result as JSON."""
        return result.model_dump_json(indent=self.indent)
