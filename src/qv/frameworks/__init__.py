"""Framework analyzers for qv."""

from __future__ import annotations

from qv.frameworks.base import FrameworkPlugin
from qv.frameworks.celery import CeleryAnalyzer
from qv.frameworks.django import DjangoAnalyzer
from qv.frameworks.fastapi import FastApiAnalyzer
from qv.frameworks.sqlalchemy import SqlAlchemyAnalyzer

AVAILABLE_FRAMEWORK_ANALYZERS: list[type[FrameworkPlugin]] = [
    FastApiAnalyzer,
    SqlAlchemyAnalyzer,
    DjangoAnalyzer,
    CeleryAnalyzer,
]

__all__ = [
    "FrameworkPlugin",
    "FastApiAnalyzer",
    "SqlAlchemyAnalyzer",
    "DjangoAnalyzer",
    "CeleryAnalyzer",
    "AVAILABLE_FRAMEWORK_ANALYZERS",
]
