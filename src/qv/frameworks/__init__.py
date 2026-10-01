"""Framework analyzers for qv."""

from __future__ import annotations

from qv.frameworks.base import FrameworkPlugin
from qv.frameworks.fastapi import FastApiAnalyzer

AVAILABLE_FRAMEWORK_ANALYZERS: list[type[FrameworkPlugin]] = [
    FastApiAnalyzer,
]

__all__ = [
    "FrameworkPlugin",
    "FastApiAnalyzer",
    "AVAILABLE_FRAMEWORK_ANALYZERS",
]
