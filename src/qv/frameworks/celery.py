"""Celery Background Tasks Analyzer implementing rules CEL-001 through CEL-004."""

from __future__ import annotations

import ast

from qv.core.context import ProjectContext
from qv.core.models import AnalyzerStatus, Diagnostic, Evidence, Severity, Suggestion
from qv.frameworks.base import FrameworkPlugin
from qv.rules.registry import get_rule_definition

TASK_DECORATOR_NAMES = frozenset({"task", "shared_task"})


class CeleryAnalyzer(FrameworkPlugin):
    """Analyzes Celery configurations and background tasks for reliability and security anti-patterns."""

    id = "celery"
    name = "Celery Analyzer"
    description = (
        "Diagnostic analyzer for Celery applications checking serializer security (pickle), "
        "task execution limits (time_limit/soft_time_limit), unbounded retries, and blocking calls."
    )
    rules: tuple[str, ...] = (
        "CEL-001",
        "CEL-002",
        "CEL-003",
        "CEL-004",
    )

    def __init__(self) -> None:
        self.status: AnalyzerStatus = AnalyzerStatus.OK

    def detect(self, context: ProjectContext) -> bool:
        """Check if Celery is used in the project."""
        for dep in context.dependencies:
            if dep.name.lower() == "celery":
                return True

        if "celery" in context.installed_packages:
            return True

        for imp in context.imports:
            if imp.module_name == "celery" or imp.module_name.startswith("celery."):
                return True

        for sf in context.source_files:
            if "from celery" in sf.content or "import celery" in sf.content:
                return True

        return False

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        """Analyze Celery tasks and configurations."""
        if not self.detect(context):
            self.status = AnalyzerStatus.SKIPPED
            return []

        self.status = AnalyzerStatus.OK
        diagnostics: list[Diagnostic] = []

        for sf in context.source_files:
            try:
                tree = ast.parse(sf.content, filename=str(sf.path))
            except SyntaxError:
                continue

            file_rel = str(sf.relative_path).replace("\\", "/")
            diagnostics.extend(self._check_serializers(tree, file_rel))
            diagnostics.extend(self._check_tasks(tree, file_rel))

        return diagnostics

    def _check_serializers(self, tree: ast.AST, file_rel: str) -> list[Diagnostic]:
        """CEL-001: Insecure pickle serializer configuration."""
        diagnostics: list[Diagnostic] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    target_name = target.id if isinstance(target, ast.Name) else ""
                    if target_name in (
                        "task_serializer",
                        "result_serializer",
                        "accept_content",
                        "CELERY_TASK_SERIALIZER",
                        "CELERY_RESULT_SERIALIZER",
                        "CELERY_ACCEPT_CONTENT",
                    ):
                        is_pickle = False
                        if isinstance(node.value, ast.Constant) and node.value.value == "pickle":
                            is_pickle = True
                        elif isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                            for elt in node.value.elts:
                                if isinstance(elt, ast.Constant) and elt.value == "pickle":
                                    is_pickle = True

                        if is_pickle:
                            rule_def = get_rule_definition("CEL-001")
                            doc_url = rule_def.doc_url if rule_def else ""
                            diagnostics.append(
                                Diagnostic(
                                    id="CEL-001",
                                    severity=Severity.ERROR,
                                    category="framework",
                                    title="Insecure Celery pickle serializer enabled",
                                    message=(
                                        f"Celery serializer setting '{target_name}' uses 'pickle', which allows "
                                        f"arbitrary code execution if message brokers are compromised."
                                    ),
                                    file=file_rel,
                                    line=node.lineno,
                                    evidence=[
                                        Evidence(
                                            fact=f"'{target_name}' configured with pickle on line {node.lineno}.",
                                            source=file_rel,
                                        )
                                    ],
                                    suggestions=[
                                        Suggestion(
                                            description="Use secure serialization formats like 'json' or 'msgpack'.",
                                            code_snippet=f"{target_name} = 'json'",
                                        )
                                    ],
                                    doc_url=doc_url,
                                )
                            )
        return diagnostics

    def _check_tasks(self, tree: ast.AST, file_rel: str) -> list[Diagnostic]:
        """CEL-002, CEL-003, CEL-004: Task timeouts, retry limits, and blocking calls."""
        diagnostics: list[Diagnostic] = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            is_task = False
            task_has_timeout = False
            task_has_unbounded_retries = False

            for dec in node.decorator_list:
                if isinstance(dec, ast.Call):
                    func_name = ""
                    if isinstance(dec.func, ast.Name):
                        func_name = dec.func.id
                    elif isinstance(dec.func, ast.Attribute):
                        func_name = dec.func.attr

                    if func_name in TASK_DECORATOR_NAMES:
                        is_task = True
                        for kw in dec.keywords:
                            if kw.arg in ("time_limit", "soft_time_limit"):
                                task_has_timeout = True
                            elif kw.arg == "max_retries":
                                if isinstance(kw.value, ast.Constant) and kw.value.value is None:
                                    task_has_unbounded_retries = True
                            elif kw.arg == "autoretry_for":
                                has_max_retries = any(k.arg == "max_retries" for k in dec.keywords)
                                if not has_max_retries:
                                    task_has_unbounded_retries = True

                elif isinstance(dec, ast.Name) and dec.id in TASK_DECORATOR_NAMES:
                    is_task = True
                elif isinstance(dec, ast.Attribute) and dec.attr in TASK_DECORATOR_NAMES:
                    is_task = True

            if not is_task:
                continue

            # CEL-002: Missing task timeout
            if not task_has_timeout:
                rule_def = get_rule_definition("CEL-002")
                doc_url = rule_def.doc_url if rule_def else ""
                diagnostics.append(
                    Diagnostic(
                        id="CEL-002",
                        severity=Severity.WARNING,
                        category="framework",
                        title="Missing task timeout limits in Celery task",
                        message=(
                            f"Celery task '{node.name}' has no 'time_limit' or 'soft_time_limit' configured, "
                            f"risking hung worker processes if external operations block."
                        ),
                        file=file_rel,
                        line=node.lineno,
                        evidence=[
                            Evidence(
                                fact=f"Task '{node.name}' defined without time_limit on line {node.lineno}.",
                                source=file_rel,
                            )
                        ],
                        suggestions=[
                            Suggestion(
                                description="Specify 'time_limit' and 'soft_time_limit' on task decorator: @shared_task(time_limit=300, soft_time_limit=240)",
                            )
                        ],
                        doc_url=doc_url,
                    )
                )

            # CEL-003: Unbounded task retries
            if task_has_unbounded_retries:
                rule_def = get_rule_definition("CEL-003")
                doc_url = rule_def.doc_url if rule_def else ""
                diagnostics.append(
                    Diagnostic(
                        id="CEL-003",
                        severity=Severity.WARNING,
                        category="framework",
                        title="Unbounded retry policy on Celery task",
                        message=f"Celery task '{node.name}' permits unlimited retries, risking broker congestion and infinite retry loops.",
                        file=file_rel,
                        line=node.lineno,
                        evidence=[
                            Evidence(
                                fact=f"Unbounded retry policy on task '{node.name}'.",
                                source=file_rel,
                            )
                        ],
                        suggestions=[
                            Suggestion(
                                description="Set explicit 'max_retries' (e.g. max_retries=3, default_retry_delay=60).",
                            )
                        ],
                        doc_url=doc_url,
                    )
                )

            # CEL-004: Blocking synchronous call inside async task
            if isinstance(node, ast.AsyncFunctionDef):
                for child in ast.walk(node):
                    if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                        if (
                            isinstance(child.func.value, ast.Name)
                            and child.func.value.id == "time"
                            and child.func.attr == "sleep"
                        ):
                            rule_def = get_rule_definition("CEL-004")
                            doc_url = rule_def.doc_url if rule_def else ""
                            diagnostics.append(
                                Diagnostic(
                                    id="CEL-004",
                                    severity=Severity.WARNING,
                                    category="framework",
                                    title="Blocking time.sleep() in asynchronous Celery task",
                                    message=f"Async Celery task '{node.name}' invokes 'time.sleep()', blocking the async event loop.",
                                    file=file_rel,
                                    line=child.lineno,
                                    evidence=[
                                        Evidence(
                                            fact=f"time.sleep() call on line {child.lineno}.",
                                            source=file_rel,
                                        )
                                    ],
                                    suggestions=[
                                        Suggestion(
                                            description="Use 'await asyncio.sleep()' instead of 'time.sleep()'.",
                                        )
                                    ],
                                    doc_url=doc_url,
                                )
                            )
        return diagnostics
