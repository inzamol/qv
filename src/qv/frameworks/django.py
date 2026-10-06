"""Django Framework Analyzer implementing rules DJG-001 through DJG-006."""

from __future__ import annotations

import ast

from qv.core.context import ProjectContext
from qv.core.models import AnalyzerStatus, Diagnostic, Evidence, Severity, Suggestion
from qv.frameworks.base import FrameworkPlugin
from qv.rules.registry import get_rule_definition


class DjangoAnalyzer(FrameworkPlugin):
    """Analyzes Django applications for security misconfigurations, ORM pitfalls, and settings vulnerabilities."""

    id = "django"
    name = "Django Analyzer"
    description = (
        "Comprehensive diagnostic analyzer for Django projects checking settings security (DEBUG, SECRET_KEY, "
        "ALLOWED_HOSTS, CSRF), ORM N+1 query patterns, and ForeignKey configurations."
    )
    rules: tuple[str, ...] = (
        "DJG-001",
        "DJG-002",
        "DJG-003",
        "DJG-004",
        "DJG-005",
        "DJG-006",
    )

    def __init__(self) -> None:
        self.status: AnalyzerStatus = AnalyzerStatus.OK

    def detect(self, context: ProjectContext) -> bool:
        """Check if Django is in dependencies, installed packages, or source files."""
        for dep in context.dependencies:
            if dep.name.lower() == "django":
                return True

        if "django" in context.installed_packages:
            return True

        for imp in context.imports:
            if imp.module_name == "django" or imp.module_name.startswith("django."):
                return True

        for sf in context.source_files:
            if (
                "from django" in sf.content
                or "import django" in sf.content
                or "DJANGO_SETTINGS_MODULE" in sf.content
            ):
                return True

        return False

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        """Analyze Django source files for security, settings, and ORM issues."""
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
            is_settings = "setting" in file_rel.lower() or sf.path.name == "settings.py"

            if is_settings:
                diagnostics.extend(self._check_settings(tree, file_rel, sf.content))

            diagnostics.extend(self._check_models_and_queries(tree, file_rel))

        return diagnostics

    def _check_settings(self, tree: ast.AST, file_rel: str, content: str) -> list[Diagnostic]:
        """Check settings.py for DJG-001, DJG-002, DJG-003, DJG-006."""
        diagnostics: list[Diagnostic] = []
        has_middleware_def = False
        has_csrf_middleware = False
        middleware_lineno = 1

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        # DJG-001: Insecure hardcoded DEBUG = True
                        if target.id == "DEBUG":
                            if isinstance(node.value, ast.Constant) and node.value.value is True:
                                rule_def = get_rule_definition("DJG-001")
                                doc_url = rule_def.doc_url if rule_def else ""
                                diagnostics.append(
                                    Diagnostic(
                                        id="DJG-001",
                                        severity=Severity.ERROR,
                                        category="framework",
                                        title="Insecure hardcoded DEBUG = True in Django settings",
                                        message=(
                                            "Django settings hardcodes 'DEBUG = True' without environment variable "
                                            "fallback, risking sensitive traceback exposure in production."
                                        ),
                                        file=file_rel,
                                        line=node.lineno,
                                        evidence=[
                                            Evidence(
                                                fact=f"Hardcoded 'DEBUG = True' on line {node.lineno}.",
                                                source=file_rel,
                                            )
                                        ],
                                        suggestions=[
                                            Suggestion(
                                                description="Load DEBUG dynamically from an environment variable: os.getenv('DJANGO_DEBUG', 'False').lower() == 'true'",
                                                code_snippet="DEBUG = os.getenv('DJANGO_DEBUG', 'False').lower() == 'true'",
                                            )
                                        ],
                                        doc_url=doc_url,
                                    )
                                )

                        # DJG-002: Hardcoded SECRET_KEY literal
                        elif target.id == "SECRET_KEY":
                            if isinstance(node.value, ast.Constant) and isinstance(
                                node.value.value, str
                            ):
                                if len(node.value.value) > 5 and not node.value.value.startswith(
                                    "env:"
                                ):
                                    rule_def = get_rule_definition("DJG-002")
                                    doc_url = rule_def.doc_url if rule_def else ""
                                    diagnostics.append(
                                        Diagnostic(
                                            id="DJG-002",
                                            severity=Severity.ERROR,
                                            category="framework",
                                            title="Hardcoded SECRET_KEY in Django settings",
                                            message="Hardcoded SECRET_KEY literal detected in settings. Secrets must be loaded from environment variables or a vault.",
                                            file=file_rel,
                                            line=node.lineno,
                                            evidence=[
                                                Evidence(
                                                    fact=f"Literal SECRET_KEY assigned on line {node.lineno}.",
                                                    source=file_rel,
                                                )
                                            ],
                                            suggestions=[
                                                Suggestion(
                                                    description="Load SECRET_KEY from environment: os.environ['DJANGO_SECRET_KEY']",
                                                    code_snippet="SECRET_KEY = os.environ['DJANGO_SECRET_KEY']",
                                                )
                                            ],
                                            doc_url=doc_url,
                                        )
                                    )

                        # DJG-003: Wildcard ALLOWED_HOSTS = ['*']
                        elif target.id == "ALLOWED_HOSTS":
                            if isinstance(node.value, (ast.List, ast.Tuple)):
                                for elt in node.value.elts:
                                    if isinstance(elt, ast.Constant) and elt.value == "*":
                                        rule_def = get_rule_definition("DJG-003")
                                        doc_url = rule_def.doc_url if rule_def else ""
                                        diagnostics.append(
                                            Diagnostic(
                                                id="DJG-003",
                                                severity=Severity.WARNING,
                                                category="framework",
                                                title="Insecure wildcard ALLOWED_HOSTS in Django settings",
                                                message=(
                                                    "ALLOWED_HOSTS contains wildcard '*' allowing Host header poisoning and "
                                                    "cross-site scripting vulnerabilities in production."
                                                ),
                                                file=file_rel,
                                                line=node.lineno,
                                                evidence=[
                                                    Evidence(
                                                        fact="ALLOWED_HOSTS includes '*' wildcard.",
                                                        source=file_rel,
                                                    )
                                                ],
                                                suggestions=[
                                                    Suggestion(
                                                        description="Explicitly define allowed domain names or load from environment.",
                                                        code_snippet="ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')",
                                                    )
                                                ],
                                                doc_url=doc_url,
                                            )
                                        )

                        # DJG-006: Missing CSRF Middleware in MIDDLEWARE
                        elif target.id in ("MIDDLEWARE", "MIDDLEWARE_CLASSES"):
                            has_middleware_def = True
                            middleware_lineno = node.lineno
                            if isinstance(node.value, (ast.List, ast.Tuple)):
                                for elt in node.value.elts:
                                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                        if "CsrfViewMiddleware" in elt.value:
                                            has_csrf_middleware = True

        if has_middleware_def and not has_csrf_middleware:
            rule_def = get_rule_definition("DJG-006")
            doc_url = rule_def.doc_url if rule_def else ""
            diagnostics.append(
                Diagnostic(
                    id="DJG-006",
                    severity=Severity.WARNING,
                    category="framework",
                    title="Missing CSRF Protection Middleware",
                    message="MIDDLEWARE list is missing 'django.middleware.csrf.CsrfViewMiddleware', leaving forms vulnerable to CSRF attacks.",
                    file=file_rel,
                    line=middleware_lineno,
                    evidence=[
                        Evidence(
                            fact="CsrfViewMiddleware missing from MIDDLEWARE setting.",
                            source=file_rel,
                        )
                    ],
                    suggestions=[
                        Suggestion(
                            description="Add 'django.middleware.csrf.CsrfViewMiddleware' to MIDDLEWARE.",
                        )
                    ],
                    doc_url=doc_url,
                )
            )

        return diagnostics

    def _check_models_and_queries(self, tree: ast.AST, file_rel: str) -> list[Diagnostic]:
        """Check for DJG-004 (N+1 in loop) and DJG-005 (ForeignKey missing on_delete/db_index)."""
        diagnostics: list[Diagnostic] = []

        for node in ast.walk(tree):
            # DJG-005: ForeignKey without explicit on_delete
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Attribute) and node.func.attr == "ForeignKey":
                    func_name = "ForeignKey"
                elif isinstance(node.func, ast.Name) and node.func.id == "ForeignKey":
                    func_name = "ForeignKey"

                if func_name == "ForeignKey":
                    has_on_delete = any(kw.arg == "on_delete" for kw in node.keywords)
                    if not has_on_delete:
                        rule_def = get_rule_definition("DJG-005")
                        doc_url = rule_def.doc_url if rule_def else ""
                        diagnostics.append(
                            Diagnostic(
                                id="DJG-005",
                                severity=Severity.WARNING,
                                category="framework",
                                title="Django ForeignKey missing explicit on_delete",
                                message="models.ForeignKey declared without required 'on_delete' argument.",
                                file=file_rel,
                                line=node.lineno,
                                evidence=[
                                    Evidence(
                                        fact=f"ForeignKey missing on_delete on line {node.lineno}.",
                                        source=file_rel,
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description="Specify explicit on_delete behavior: models.CASCADE, models.PROTECT, or models.SET_NULL.",
                                    )
                                ],
                                doc_url=doc_url,
                            )
                        )

            # DJG-004: N+1 ORM query inside for loop
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                for child in ast.walk(node):
                    if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                        if child.func.attr in (
                            "all",
                            "filter",
                            "exclude",
                            "first",
                            "values",
                            "values_list",
                        ):
                            # Check if calling on loop target attribute e.g. item.comments.all()
                            if isinstance(child.func.value, ast.Attribute):
                                target_var = (
                                    node.target.id if isinstance(node.target, ast.Name) else ""
                                )
                                root_val = child.func.value
                                while isinstance(root_val, ast.Attribute):
                                    root_val = root_val.value
                                if isinstance(root_val, ast.Name) and root_val.id == target_var:
                                    rule_def = get_rule_definition("DJG-004")
                                    doc_url = rule_def.doc_url if rule_def else ""
                                    diagnostics.append(
                                        Diagnostic(
                                            id="DJG-004",
                                            severity=Severity.WARNING,
                                            category="framework",
                                            title="Potential N+1 database query in loop",
                                            message=(
                                                f"QuerySet execution '{child.func.attr}()' inside loop over '{target_var}' "
                                                f"causes N+1 query overhead. Use 'prefetch_related()' or 'select_related()' beforehand."
                                            ),
                                            file=file_rel,
                                            line=child.lineno,
                                            evidence=[
                                                Evidence(
                                                    fact=f"ORM query call inside loop on line {child.lineno}.",
                                                    source=file_rel,
                                                )
                                            ],
                                            suggestions=[
                                                Suggestion(
                                                    description="Prefetch related relations before looping: queryset.prefetch_related('...')",
                                                )
                                            ],
                                            doc_url=doc_url,
                                        )
                                    )
                                    break
        return diagnostics
