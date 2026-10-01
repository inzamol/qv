"""Framework analyzers for qv."""

from __future__ import annotations

from qv.frameworks.base import FrameworkPlugin
from qv.frameworks.fastapi import FastApiAnalyzer
from qv.frameworks.sqlalchemy import SqlAlchemyAnalyzer

AVAILABLE_FRAMEWORK_ANALYZERS: list[type[FrameworkPlugin]] = [
    FastApiAnalyzer,
    SqlAlchemyAnalyzer,
]

__all__ = [
    "FrameworkPlugin",
    "FastApiAnalyzer",
    "SqlAlchemyAnalyzer",
    "AVAILABLE_FRAMEWORK_ANALYZERS",
]
