"""FastAPI Framework Analyzer implementing FAP-001 through FAP-038."""

from __future__ import annotations

import ast
import re

from qv.core.context import ProjectContext
from qv.core.models import AnalyzerStatus, Diagnostic, Evidence, Severity, Suggestion
from qv.frameworks.base import FrameworkPlugin
from qv.rules.registry import get_rule_definition

ROUTE_METHODS = frozenset(
    {"get", "post", "put", "delete", "patch", "options", "head", "trace", "api_route", "websocket"}
)
MUTATING_METHODS = frozenset({"post", "put", "patch"})

BLOCKING_CALL_PATTERNS = {
    # Synchronous Blocking I/O
    ("time", "sleep"): "time.sleep() blocks the asyncio event loop.",
    ("requests", "get"): "requests.get() performs blocking synchronous network I/O.",
    ("requests", "post"): "requests.post() performs blocking synchronous network I/O.",
    ("requests", "put"): "requests.put() performs blocking synchronous network I/O.",
    ("requests", "delete"): "requests.delete() performs blocking synchronous network I/O.",
    ("requests", "patch"): "requests.patch() performs blocking synchronous network I/O.",
    ("requests", "request"): "requests.request() performs blocking synchronous network I/O.",
    ("urllib", "request", "urlopen"): "urllib.request.urlopen() performs blocking synchronous I/O.",
    ("subprocess", "run"): "subprocess.run() executes a blocking synchronous process.",
    ("subprocess", "call"): "subprocess.call() executes a blocking synchronous process.",
    (
        "subprocess",
        "check_call",
    ): "subprocess.check_call() executes a blocking synchronous process.",
    (
        "subprocess",
        "check_output",
    ): "subprocess.check_output() executes a blocking synchronous process.",
    ("subprocess", "Popen"): "subprocess.Popen() without async process management can block.",
    ("os", "system"): "os.system() executes a blocking synchronous shell command.",
    ("os", "popen"): "os.popen() performs blocking synchronous subprocess I/O.",
    # CPU-bound hashing
    (
        "bcrypt",
        "hashpw",
    ): "bcrypt.hashpw() is a heavy CPU-bound operation that stalls async workers.",
    (
        "bcrypt",
        "checkpw",
    ): "bcrypt.checkpw() is a heavy CPU-bound operation that stalls async workers.",
    ("hashlib", "pbkdf2_hmac"): "hashlib.pbkdf2_hmac() is a heavy CPU-bound hashing operation.",
}

SENSITIVE_FIELD_NAMES = frozenset(
    {
        "password",
        "password_hash",
        "hashed_password",
        "secret",
        "secret_key",
        "token_secret",
        "api_secret",
        "private_key",
    }
)


class FastApiAnalyzer(FrameworkPlugin):
    """Analyzes FastAPI projects for performance bottlenecks, security risks, routing bugs, and best practices."""

    id = "fastapi"
    name = "FastAPI Analyzer"
    description = (
        "Comprehensive diagnostic suite for FastAPI applications covering async blocking calls, "
        "type safety, routing integrity, security configurations, cookie safety, and resource lifecycles."
    )
    rules: tuple[str, ...] = tuple(f"FAP-{i:03d}" for i in range(1, 39))

    def __init__(self) -> None:
        """Initialize the analyzer with an OK status until analysis determines otherwise."""
        self.status: AnalyzerStatus = AnalyzerStatus.OK

    def detect(self, context: ProjectContext) -> bool:
        """Check if FastAPI is used in dependencies, installed packages, or source imports."""
        for dep in context.dependencies:
            if dep.name.lower() == "fastapi":
                return True

        if "fastapi" in context.installed_packages:
            return True

        for imp in context.imports:
            if imp.module_name == "fastapi" or imp.module_name.startswith("fastapi."):
                return True

        for sf in context.source_files:
            if "fastapi" in sf.content.lower():
                return True

        return False

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        """Analyze all source files in the project context for FastAPI diagnostics."""
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

            func_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
            module_globals: set[str] = set()

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_defs[node.name] = node
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            module_globals.add(target.id)

            diagnostics.extend(
                self._check_routes_and_calls(tree, file_rel, func_defs, module_globals)
            )
            diagnostics.extend(self._check_cors_and_security(tree, file_rel))
            diagnostics.extend(self._check_client_timeouts(tree, file_rel))
            diagnostics.extend(self._check_yield_dependencies(tree, file_rel))
            diagnostics.extend(self._check_lifecycle_events(tree, file_rel))
            diagnostics.extend(self._check_exception_handlers(tree, file_rel))
            diagnostics.extend(self._check_pydantic_models(tree, file_rel))
            diagnostics.extend(self._check_router_includes(tree, file_rel))

        return diagnostics

    def _is_route_decorator(
        self, decorator: ast.expr
    ) -> tuple[bool, str | None, bool, str | None, str | None, int | None]:
        """
        Check if a decorator is a FastAPI route decorator.
        Returns (is_route, method_name, has_response_model, path_template, router_var, status_code).
        """
        if isinstance(decorator, ast.Call):
            func = decorator.func
            has_response_model = any(
                kw.arg in ("response_model", "response_class") for kw in decorator.keywords
            )
            path_template = None
            if (
                decorator.args
                and isinstance(decorator.args[0], ast.Constant)
                and isinstance(decorator.args[0].value, str)
            ):
                path_template = decorator.args[0].value

            status_code = None
            for kw in decorator.keywords:
                if (
                    kw.arg == "status_code"
                    and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, int)
                ):
                    status_code = kw.value.value

            router_var = None
            if isinstance(func, ast.Attribute):
                if isinstance(func.value, ast.Name):
                    router_var = func.value.id
                if func.attr.lower() in ROUTE_METHODS:
                    return (
                        True,
                        func.attr.lower(),
                        has_response_model,
                        path_template,
                        router_var,
                        status_code,
                    )
            elif isinstance(func, ast.Name) and func.id.lower() in ROUTE_METHODS:
                return (
                    True,
                    func.id.lower(),
                    has_response_model,
                    path_template,
                    router_var,
                    status_code,
                )
        elif isinstance(decorator, ast.Attribute) and decorator.attr.lower() in ROUTE_METHODS:
            router_var = decorator.value.id if isinstance(decorator.value, ast.Name) else None
            return True, decorator.attr.lower(), False, None, router_var, None
        return False, None, False, None, None, None

    def _extract_call_tuple(self, node: ast.Call) -> tuple[str, ...] | None:
        """Extract dotted chain from a call func (e.g. time.sleep -> ('time', 'sleep'))."""
        parts: list[str] = []
        curr: ast.expr = node.func
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
            return tuple(reversed(parts))
        return None

    def _find_blocking_calls(self, root_node: ast.AST) -> list[tuple[ast.Call, str]]:
        """Find blocking synchronous calls within an AST subtree."""
        blocking_found: list[tuple[ast.Call, str]] = []
        for n in ast.walk(root_node):
            if isinstance(n, ast.Call):
                call_tuple = self._extract_call_tuple(n)
                if call_tuple:
                    for pattern, reason in BLOCKING_CALL_PATTERNS.items():
                        if call_tuple == pattern or (
                            len(call_tuple) >= len(pattern)
                            and call_tuple[-len(pattern) :] == pattern
                        ):
                            blocking_found.append((n, reason))
                            break
        return blocking_found

    def _extract_annotation_name(self, node: ast.AST | None) -> str:
        """Extract simple type name from annotation node."""
        if node is None:
            return ""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        if isinstance(node, ast.Subscript):
            base = self._extract_annotation_name(node.value)
            return f"{base}[...]"
        return ""

    def _check_routes_and_calls(
        self,
        tree: ast.AST,
        file_path: str,
        func_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
        module_globals: set[str],
    ) -> list[Diagnostic]:
        """Check for FAP-001, FAP-002, FAP-003, FAP-006, FAP-009..011, FAP-013..015, FAP-017..020, FAP-022, FAP-024."""
        diagnostics: list[Diagnostic] = []
        seen_routes: dict[tuple[str, str, str], tuple[str, int]] = {}

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            is_route = False
            route_method = None
            has_response_model = False
            route_path = None
            router_var = None
            status_code = None

            for dec in node.decorator_list:
                matched, method, resp_model, path_tmpl, rvar, scode = self._is_route_decorator(dec)
                if matched:
                    is_route = True
                    route_method = method
                    if resp_model:
                        has_response_model = True
                    if path_tmpl:
                        route_path = path_tmpl
                    if rvar:
                        router_var = rvar
                    if scode:
                        status_code = scode

            if not is_route:
                continue

            # FAP-010: Shadowed / Duplicate Route Endpoints
            if route_path and route_method:
                route_key = (router_var or "app", route_method, route_path)
                if route_key in seen_routes:
                    prev_func, prev_line = seen_routes[route_key]
                    rule_def = get_rule_definition("FAP-010")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-010"
                    )
                    diagnostics.append(
                        Diagnostic(
                            id="FAP-010",
                            severity=Severity.ERROR,
                            category="framework",
                            title="Shadowed or duplicate route endpoint",
                            message=(
                                f"Duplicate route '{route_method.upper()} {route_path}' detected on '{node.name}'. "
                                f"This endpoint shadows the earlier handler '{prev_func}' on line {prev_line}."
                            ),
                            evidence=[
                                Evidence(
                                    fact=f"'{route_method.upper()} {route_path}' previously defined by '{prev_func}' on line {prev_line}.",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description="Change the route path/method or consolidate logic into a single handler.",
                                )
                            ],
                            file=file_path,
                            line=node.lineno,
                            column=getattr(node, "col_offset", None),
                            doc_url=doc_url,
                        )
                    )
                else:
                    seen_routes[route_key] = (node.name, node.lineno)

            # FAP-006: Route path parameter template mismatch
            func_arg_names = {a.arg for a in node.args.args + node.args.kwonlyargs}
            if route_path:
                path_params = set(re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", route_path))
                missing_params = path_params - func_arg_names
                if missing_params:
                    rule_def = get_rule_definition("FAP-006")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-006"
                    )
                    missing_str = ", ".join(f"'{p}'" for p in sorted(missing_params))
                    diagnostics.append(
                        Diagnostic(
                            id="FAP-006",
                            severity=Severity.ERROR,
                            category="framework",
                            title="Route path parameter template mismatch",
                            message=(
                                f"Route '{route_path}' declares path parameter(s) {missing_str}, "
                                f"which are missing from function '{node.name}' parameters."
                            ),
                            evidence=[
                                Evidence(
                                    fact=f"Path parameters {missing_str} not found in ({', '.join(sorted(func_arg_names))}).",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description=f"Add {missing_str} as parameter(s) in 'def {node.name}(...)' with appropriate type annotations.",
                                )
                            ],
                            file=file_path,
                            line=node.lineno,
                            column=getattr(node, "col_offset", None),
                            doc_url=doc_url,
                        )
                    )

            # FAP-017: Non-standard status code on POST or DELETE
            path_display = route_path or "/"
            if route_method == "post" and status_code is None:
                rule_def = get_rule_definition("FAP-017")
                doc_url = (
                    rule_def.doc_url
                    if rule_def
                    else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-017"
                )
                diagnostics.append(
                    Diagnostic(
                        id="FAP-017",
                        severity=Severity.WARNING,
                        category="framework",
                        title="Non-standard HTTP status code on POST route",
                        message=f"POST route '{node.name}' defaults to 200 OK instead of explicit 'status_code=status.HTTP_201_CREATED'.",
                        evidence=[
                            Evidence(
                                fact=f"POST route '{node.name}' declared without status_code parameter.",
                                source=file_path,
                            )
                        ],
                        suggestions=[
                            Suggestion(
                                description="Add 'status_code=status.HTTP_201_CREATED' to the route decorator.",
                                code_snippet=f"@app.post('{path_display}', status_code=201)",
                            )
                        ],
                        file=file_path,
                        line=node.lineno,
                        column=getattr(node, "col_offset", None),
                        doc_url=doc_url,
                    )
                )
            elif route_method == "delete" and status_code is None:
                rule_def = get_rule_definition("FAP-017")
                doc_url = (
                    rule_def.doc_url
                    if rule_def
                    else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-017"
                )
                diagnostics.append(
                    Diagnostic(
                        id="FAP-017",
                        severity=Severity.WARNING,
                        category="framework",
                        title="Non-standard HTTP status code on DELETE route",
                        message=f"DELETE route '{node.name}' defaults to 200 OK instead of 'status_code=status.HTTP_204_NO_CONTENT'.",
                        evidence=[
                            Evidence(
                                fact=f"DELETE route '{node.name}' declared without status_code parameter.",
                                source=file_path,
                            )
                        ],
                        suggestions=[
                            Suggestion(
                                description="Add 'status_code=status.HTTP_204_NO_CONTENT' to the route decorator.",
                                code_snippet=f"@app.delete('{path_display}', status_code=204)",
                            )
                        ],
                        file=file_path,
                        line=node.lineno,
                        column=getattr(node, "col_offset", None),
                        doc_url=doc_url,
                    )
                )

            # FAP-038: Hardcoded HTTP status code integer
            if status_code is not None and status_code != 200:
                rule_def = get_rule_definition("FAP-038")
                doc_url = (
                    rule_def.doc_url
                    if rule_def
                    else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-038"
                )
                diagnostics.append(
                    Diagnostic(
                        id="FAP-038",
                        severity=Severity.INFO,
                        category="framework",
                        title="Hardcoded HTTP status code integer",
                        message=f"Route '{node.name}' uses literal integer 'status_code={status_code}' instead of named 'status.HTTP_*' constant.",
                        evidence=[
                            Evidence(
                                fact=f"Literal status_code={status_code} in route decorator on line {node.lineno}.",
                                source=file_path,
                            )
                        ],
                        suggestions=[
                            Suggestion(
                                description=f"Use 'status.HTTP_{status_code}_...' from fastapi instead of integer literal {status_code}.",
                                code_snippet=f"from fastapi import status\n# status_code=status.HTTP_{status_code}_...",
                            )
                        ],
                        file=file_path,
                        line=node.lineno,
                        column=getattr(node, "col_offset", None),
                        doc_url=doc_url,
                    )
                )

            # FAP-009 & FAP-011: Parameter checks (Untyped Body & Mutable Defaults)
            seen_dependencies: set[str] = set()
            for arg in node.args.args + node.args.kwonlyargs:
                if arg.arg in (
                    "self",
                    "cls",
                    "request",
                    "response",
                    "db",
                    "auth",
                    "background_tasks",
                ):
                    continue

                type_name = self._extract_annotation_name(arg.annotation)
                if route_method in MUTATING_METHODS and (
                    type_name in ("dict", "Dict", "Any")
                    or (arg.annotation is None and arg.arg == "payload")
                ):
                    rule_def = get_rule_definition("FAP-009")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-009"
                    )
                    diagnostics.append(
                        Diagnostic(
                            id="FAP-009",
                            severity=Severity.WARNING,
                            category="framework",
                            title="Untyped or unvalidated request body payload",
                            message=(
                                f"Route handler '{node.name}' accepts untyped request parameter '{arg.arg}: {type_name or 'untyped'}', "
                                f"bypassing Pydantic validation."
                            ),
                            evidence=[
                                Evidence(
                                    fact=f"Parameter '{arg.arg}' annotated with '{type_name or 'None'}' on {route_method.upper()} route.",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description=f"Create a Pydantic schema (e.g. '{arg.arg.title()}Schema') and type annotate '{arg.arg}'.",
                                    code_snippet=f"class {arg.arg.title()}Schema(BaseModel):\n    ...\n\ndef {node.name}({arg.arg}: {arg.arg.title()}Schema):",
                                )
                            ],
                            file=file_path,
                            line=arg.lineno,
                            column=getattr(arg, "col_offset", None),
                            doc_url=doc_url,
                        )
                    )

            # FAP-011, FAP-024 & FAP-027: Default value & Dependency annotation checks
            num_pos = len(node.args.args)
            num_defaults = len(node.args.defaults)
            offset = num_pos - num_defaults
            all_arg_defaults: list[tuple[ast.arg, ast.expr | None]] = []
            for idx, arg in enumerate(node.args.args):
                default_expr = node.args.defaults[idx - offset] if idx >= offset else None
                all_arg_defaults.append((arg, default_expr))
            for arg, default_expr in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=False):
                all_arg_defaults.append((arg, default_expr))

            for arg, default_val in all_arg_defaults:
                if default_val is None:
                    continue
                is_mutable = False
                if isinstance(default_val, (ast.List, ast.Dict, ast.Set)):
                    is_mutable = True
                elif isinstance(default_val, ast.Call):
                    # Check Query([]), Body({}), etc.
                    for inner_arg in default_val.args:
                        if isinstance(inner_arg, (ast.List, ast.Dict, ast.Set)):
                            is_mutable = True

                    # FAP-024: Duplicate dependency check
                    if isinstance(default_val.func, ast.Name) and default_val.func.id == "Depends":
                        if default_val.args and isinstance(default_val.args[0], ast.Name):
                            dep_call_name = default_val.args[0].id
                            if dep_call_name in seen_dependencies:
                                rule_def = get_rule_definition("FAP-024")
                                doc_url = (
                                    rule_def.doc_url
                                    if rule_def
                                    else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-024"
                                )
                                diagnostics.append(
                                    Diagnostic(
                                        id="FAP-024",
                                        severity=Severity.WARNING,
                                        category="framework",
                                        title="Redundant duplicate dependency declaration",
                                        message=f"Route '{node.name}' declares multiple parameters resolving the exact same dependency '{dep_call_name}'.",
                                        evidence=[
                                            Evidence(
                                                fact=f"Duplicate Depends({dep_call_name}) on line {default_val.lineno}.",
                                                source=file_path,
                                            )
                                        ],
                                        suggestions=[
                                            Suggestion(
                                                description=f"Consolidate duplicate Depends({dep_call_name}) into a single parameter."
                                            )
                                        ],
                                        file=file_path,
                                        line=default_val.lineno,
                                        column=getattr(default_val, "col_offset", None),
                                        doc_url=doc_url,
                                    )
                                )
                            else:
                                seen_dependencies.add(dep_call_name)

                    # FAP-027 & FAP-031: Type annotation & Annotated usage on Depends/Query/Path parameter
                    if isinstance(default_val.func, ast.Name) and default_val.func.id in (
                        "Depends",
                        "Query",
                        "Path",
                        "Header",
                        "Cookie",
                        "Body",
                        "Form",
                        "File",
                        "Security",
                    ):
                        if arg.annotation is None:
                            rule_def = get_rule_definition("FAP-027")
                            doc_url = (
                                rule_def.doc_url
                                if rule_def
                                else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-027"
                            )
                            diagnostics.append(
                                Diagnostic(
                                    id="FAP-027",
                                    severity=Severity.WARNING,
                                    category="framework",
                                    title="Dependency parameter missing type annotation",
                                    message=f"Route parameter '{arg.arg}' specifies '{default_val.func.id}(...)' without an explicit type annotation.",
                                    evidence=[
                                        Evidence(
                                            fact=f"Parameter '{arg.arg} = {default_val.func.id}(...)' lacks type annotation on line {arg.lineno}.",
                                            source=file_path,
                                        )
                                    ],
                                    suggestions=[
                                        Suggestion(
                                            description=f"Add type annotation: '{arg.arg}: Type = {default_val.func.id}(...)'.",
                                            code_snippet=f"{arg.arg}: Any = {default_val.func.id}(...)",
                                        )
                                    ],
                                    file=file_path,
                                    line=arg.lineno,
                                    column=getattr(arg, "col_offset", None),
                                    doc_url=doc_url,
                                )
                            )
                        else:
                            is_annotated = False
                            if isinstance(arg.annotation, ast.Subscript):
                                if (
                                    isinstance(arg.annotation.value, ast.Name)
                                    and arg.annotation.value.id == "Annotated"
                                ) or (
                                    isinstance(arg.annotation.value, ast.Attribute)
                                    and arg.annotation.value.attr == "Annotated"
                                ):
                                    is_annotated = True
                            if not is_annotated:
                                rule_def = get_rule_definition("FAP-031")
                                doc_url = (
                                    rule_def.doc_url
                                    if rule_def
                                    else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-031"
                                )
                                diagnostics.append(
                                    Diagnostic(
                                        id="FAP-031",
                                        severity=Severity.INFO,
                                        category="framework",
                                        title="Prefer typing.Annotated over parameter default assignment",
                                        message=f"Parameter '{arg.arg}' uses default assignment for '{default_val.func.id}(...)'. Prefer modern 'Annotated[..., {default_val.func.id}(...)]'.",
                                        evidence=[
                                            Evidence(
                                                fact=f"Default assignment for {default_val.func.id}(...) on line {arg.lineno}.",
                                                source=file_path,
                                            )
                                        ],
                                        suggestions=[
                                            Suggestion(
                                                description="Refactor to 'typing.Annotated' syntax.",
                                                code_snippet=f"{arg.arg}: Annotated[..., {default_val.func.id}(...)]",
                                            )
                                        ],
                                        file=file_path,
                                        line=arg.lineno,
                                        column=getattr(arg, "col_offset", None),
                                        doc_url=doc_url,
                                    )
                                )

                    # FAP-037: SecurityScopes declared with Depends instead of Security
                    type_name = self._extract_annotation_name(arg.annotation)
                    if type_name == "SecurityScopes":
                        if (
                            isinstance(default_val.func, ast.Name)
                            and default_val.func.id == "Depends"
                        ):
                            rule_def = get_rule_definition("FAP-037")
                            doc_url = (
                                rule_def.doc_url
                                if rule_def
                                else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-037"
                            )
                            diagnostics.append(
                                Diagnostic(
                                    id="FAP-037",
                                    severity=Severity.WARNING,
                                    category="framework",
                                    title="SecurityScopes declared with Depends instead of Security",
                                    message=f"Parameter '{arg.arg}' of type SecurityScopes is passed to 'Depends(...)'. Use 'Security(..., scopes=[...])' to enforce scopes.",
                                    evidence=[
                                        Evidence(
                                            fact=f"SecurityScopes with Depends() on line {arg.lineno}.",
                                            source=file_path,
                                        )
                                    ],
                                    suggestions=[
                                        Suggestion(
                                            description="Use 'Security(dependency, scopes=[...])' instead of 'Depends(...)'.",
                                            code_snippet=f"Security({default_val.args[0].id if default_val.args and isinstance(default_val.args[0], ast.Name) else 'dependency'}, scopes=['read'])",
                                        )
                                    ],
                                    file=file_path,
                                    line=arg.lineno,
                                    column=getattr(arg, "col_offset", None),
                                    doc_url=doc_url,
                                )
                            )

                if is_mutable:
                    rule_def = get_rule_definition("FAP-011")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-011"
                    )
                    diagnostics.append(
                        Diagnostic(
                            id="FAP-011",
                            severity=Severity.WARNING,
                            category="framework",
                            title="Mutable default value in route parameter",
                            message=(
                                f"Route handler '{node.name}' uses a mutable default value (list/dict/set), "
                                f"which can leak state across concurrent requests."
                            ),
                            evidence=[
                                Evidence(
                                    fact=f"Mutable default value found on line {default_val.lineno}.",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description="Use 'None' as default (e.g. 'filters: list[str] | None = None') or use Field(default_factory=list).",
                                )
                            ],
                            file=file_path,
                            line=default_val.lineno,
                            column=getattr(default_val, "col_offset", None),
                            doc_url=doc_url,
                        )
                    )

            # FAP-018: Global state mutation in route handler
            for child in ast.walk(node):
                if isinstance(child, ast.Global):
                    rule_def = get_rule_definition("FAP-018")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-018"
                    )
                    diagnostics.append(
                        Diagnostic(
                            id="FAP-018",
                            severity=Severity.ERROR,
                            category="framework",
                            title="Global in-memory state mutation in route handler",
                            message=f"Route '{node.name}' uses 'global {', '.join(child.names)}', introducing race conditions.",
                            evidence=[
                                Evidence(
                                    fact=f"global statement on line {child.lineno} inside route handler.",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description="Store shared state in a database, Redis cache, or manage via thread-safe state dependencies."
                                )
                            ],
                            file=file_path,
                            line=child.lineno,
                            column=getattr(child, "col_offset", None),
                            doc_url=doc_url,
                        )
                    )
                elif isinstance(child, ast.Subscript) and isinstance(child.ctx, ast.Store):
                    # Check CACHE[key] = value where CACHE is in module_globals
                    if isinstance(child.value, ast.Name) and child.value.id in module_globals:
                        rule_def = get_rule_definition("FAP-018")
                        doc_url = (
                            rule_def.doc_url
                            if rule_def
                            else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-018"
                        )
                        diagnostics.append(
                            Diagnostic(
                                id="FAP-018",
                                severity=Severity.ERROR,
                                category="framework",
                                title="Global in-memory state mutation in route handler",
                                message=f"Route '{node.name}' mutates module-level global dictionary/collection '{child.value.id}'.",
                                evidence=[
                                    Evidence(
                                        fact=f"Mutation of '{child.value.id}' on line {child.lineno}.",
                                        source=file_path,
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description="Use Redis, a database, or an explicit thread-safe cache."
                                    )
                                ],
                                file=file_path,
                                line=child.lineno,
                                column=getattr(child, "col_offset", None),
                                doc_url=doc_url,
                            )
                        )

            # FAP-022: WebSocket route missing await websocket.accept()
            if route_method == "websocket":
                has_accept = False
                for child in ast.walk(node):
                    if isinstance(child, ast.Await) and isinstance(child.value, ast.Call):
                        call_tup = self._extract_call_tuple(child.value)
                        if call_tup and call_tup[-1] == "accept":
                            has_accept = True
                if not has_accept:
                    rule_def = get_rule_definition("FAP-022")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-022"
                    )
                    diagnostics.append(
                        Diagnostic(
                            id="FAP-022",
                            severity=Severity.ERROR,
                            category="framework",
                            title="WebSocket route missing await websocket.accept()",
                            message=f"WebSocket route '{node.name}' does not call 'await websocket.accept()' before processing messages.",
                            evidence=[
                                Evidence(
                                    fact=f"WebSocket handler '{node.name}' on line {node.lineno} missing accept handshake.",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description="Add 'await websocket.accept()' at the beginning of the handler function.",
                                    code_snippet="await websocket.accept()",
                                )
                            ],
                            file=file_path,
                            line=node.lineno,
                            column=getattr(node, "col_offset", None),
                            doc_url=doc_url,
                        )
                    )

            # FAP-001 & FAP-015: Blocking calls / CPU hashing & Synchronous file I/O in async endpoint
            if isinstance(node, ast.AsyncFunctionDef):
                for child in node.body:
                    for call_node, reason in self._find_blocking_calls(child):
                        call_tuple = self._extract_call_tuple(call_node)
                        call_str = ".".join(call_tuple) if call_tuple else "blocking call"
                        rule_def = get_rule_definition("FAP-001")
                        doc_url = (
                            rule_def.doc_url
                            if rule_def
                            else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-001"
                        )

                        diagnostics.append(
                            Diagnostic(
                                id="FAP-001",
                                severity=Severity.ERROR,
                                category="framework",
                                title="Blocking call or CPU-bound operation in async endpoint",
                                message=(
                                    f"Async route handler '{node.name}' calls synchronous blocking/CPU function "
                                    f"'{call_str}', which stalls the asyncio event loop."
                                ),
                                evidence=[
                                    Evidence(
                                        fact=f"{reason} Called on line {call_node.lineno} inside async def {node.name}().",
                                        source=file_path,
                                        details={
                                            "function": node.name,
                                            "call": call_str,
                                            "line": call_node.lineno,
                                        },
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description=(
                                            f"Replace '{call_str}' with an async non-blocking equivalent (e.g. 'asyncio.sleep', "
                                            f"'httpx.AsyncClient'), run in worker thread via 'anyio.to_thread.run_sync', or declare the route as synchronous 'def {node.name}()'."
                                        ),
                                        code_snippet=(
                                            f"# Option A: Change to regular synchronous def (runs in threadpool)\ndef {node.name}(...):\n    ..."
                                            if call_str.startswith("requests")
                                            or "bcrypt" in call_str
                                            else "# Option B: Use non-blocking async alternative\nawait asyncio.sleep(...)"
                                        ),
                                    )
                                ],
                                file=file_path,
                                line=call_node.lineno,
                                column=getattr(call_node, "col_offset", None),
                                doc_url=doc_url,
                            )
                        )

                    # FAP-015: Synchronous open() in async route
                    for sub in ast.walk(child):
                        if (
                            isinstance(sub, ast.Call)
                            and isinstance(sub.func, ast.Name)
                            and sub.func.id == "open"
                        ):
                            rule_def = get_rule_definition("FAP-015")
                            doc_url = (
                                rule_def.doc_url
                                if rule_def
                                else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-015"
                            )
                            diagnostics.append(
                                Diagnostic(
                                    id="FAP-015",
                                    severity=Severity.ERROR,
                                    category="framework",
                                    title="Blocking file I/O in async endpoint",
                                    message=f"Synchronous 'open()' called on line {sub.lineno} inside async route handler '{node.name}'.",
                                    evidence=[
                                        Evidence(
                                            fact=f"Synchronous file I/O inside async def {node.name}().",
                                            source=file_path,
                                        )
                                    ],
                                    suggestions=[
                                        Suggestion(
                                            description="Use 'aiofiles.open()' or 'anyio.Path', or change route handler to regular synchronous 'def'.",
                                            code_snippet="async with aiofiles.open(filepath, 'r') as f:\n    content = await f.read()",
                                        )
                                    ],
                                    file=file_path,
                                    line=sub.lineno,
                                    column=getattr(sub, "col_offset", None),
                                    doc_url=doc_url,
                                )
                            )

                # FAP-002: Blocking dependency in async path
                for default_val in node.args.defaults + node.args.kw_defaults:
                    if (
                        default_val is not None
                        and isinstance(default_val, ast.Call)
                        and isinstance(default_val.func, ast.Name)
                        and default_val.func.id == "Depends"
                    ):
                        if default_val.args:
                            dep_target = default_val.args[0]
                            dep_name = None
                            if isinstance(dep_target, ast.Name):
                                dep_name = dep_target.id
                            elif isinstance(dep_target, ast.Attribute):
                                dep_name = dep_target.attr

                            if dep_name and dep_name in func_defs:
                                target_func = func_defs[dep_name]
                                for call_node, _reason in self._find_blocking_calls(target_func):
                                    call_tuple = self._extract_call_tuple(call_node)
                                    call_str = (
                                        ".".join(call_tuple) if call_tuple else "blocking call"
                                    )
                                    rule_def = get_rule_definition("FAP-002")
                                    doc_url = (
                                        rule_def.doc_url
                                        if rule_def
                                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-002"
                                    )

                                    diagnostics.append(
                                        Diagnostic(
                                            id="FAP-002",
                                            severity=Severity.WARNING,
                                            category="framework",
                                            title="Blocking dependency in async path",
                                            message=(
                                                f"Async route handler '{node.name}' depends on '{dep_name}', "
                                                f"which contains blocking call '{call_str}'."
                                            ),
                                            evidence=[
                                                Evidence(
                                                    fact=f"Dependency '{dep_name}' invoked on line {default_val.lineno} executes '{call_str}' on line {call_node.lineno}.",
                                                    source=file_path,
                                                )
                                            ],
                                            suggestions=[
                                                Suggestion(
                                                    description=f"Refactor '{dep_name}' to use async non-blocking operations or run inside a threadpool worker.",
                                                )
                                            ],
                                            file=file_path,
                                            line=default_val.lineno,
                                            column=getattr(default_val, "col_offset", None),
                                            doc_url=doc_url,
                                        )
                                    )

            # FAP-013: Untracked asyncio.create_task in route handler
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    call_tuple = self._extract_call_tuple(child)
                    if call_tuple == ("asyncio", "create_task"):
                        rule_def = get_rule_definition("FAP-013")
                        doc_url = (
                            rule_def.doc_url
                            if rule_def
                            else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-013"
                        )
                        diagnostics.append(
                            Diagnostic(
                                id="FAP-013",
                                severity=Severity.WARNING,
                                category="framework",
                                title="Untracked asyncio.create_task in route handler",
                                message=(
                                    f"Route '{node.name}' spawns untracked 'asyncio.create_task()'. "
                                    f"Unmanaged tasks can fail silently or get garbage-collected prematurely."
                                ),
                                evidence=[
                                    Evidence(
                                        fact=f"asyncio.create_task() invoked on line {child.lineno} inside route '{node.name}'.",
                                        source=file_path,
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description="Use FastAPI's 'BackgroundTasks' dependency ('background_tasks.add_task(...)') for reliable background execution.",
                                        code_snippet=f"def {node.name}(..., background_tasks: BackgroundTasks):\n    background_tasks.add_task(task_func, ...)",
                                    )
                                ],
                                file=file_path,
                                line=child.lineno,
                                column=getattr(child, "col_offset", None),
                                doc_url=doc_url,
                            )
                        )

            # FAP-014: Potential path traversal in FileResponse
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    call_tuple = self._extract_call_tuple(child)
                    if call_tuple and call_tuple[-1] == "FileResponse":
                        if child.args and isinstance(child.args[0], ast.Name):
                            arg_name = child.args[0].id
                            if arg_name in func_arg_names:
                                rule_def = get_rule_definition("FAP-014")
                                doc_url = (
                                    rule_def.doc_url
                                    if rule_def
                                    else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-014"
                                )
                                diagnostics.append(
                                    Diagnostic(
                                        id="FAP-014",
                                        severity=Severity.WARNING,
                                        category="framework",
                                        title="Potential path traversal in FileResponse",
                                        message=(
                                            f"FileResponse on line {child.lineno} passes route parameter '{arg_name}' directly "
                                            f"without visible path boundary sanitization."
                                        ),
                                        evidence=[
                                            Evidence(
                                                fact=f"FileResponse({arg_name}) called with raw route parameter on line {child.lineno}.",
                                                source=file_path,
                                            )
                                        ],
                                        suggestions=[
                                            Suggestion(
                                                description="Resolve path against a base directory and verify 'path.is_relative_to(base_dir)'.",
                                                code_snippet=f"target = (BASE_DIR / {arg_name}).resolve()\nif not target.is_relative_to(BASE_DIR):\n    raise HTTPException(400, 'Invalid path')",
                                            )
                                        ],
                                        file=file_path,
                                        line=child.lineno,
                                        column=getattr(child, "col_offset", None),
                                        doc_url=doc_url,
                                    )
                                )

            # FAP-019: Insecure cookie configuration
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    call_tuple = self._extract_call_tuple(child)
                    if call_tuple and call_tuple[-1] == "set_cookie":
                        httponly_false = False
                        secure_false = False
                        for kw in child.keywords:
                            if (
                                kw.arg == "httponly"
                                and isinstance(kw.value, ast.Constant)
                                and kw.value.value is False
                            ):
                                httponly_false = True
                            if (
                                kw.arg == "secure"
                                and isinstance(kw.value, ast.Constant)
                                and kw.value.value is False
                            ):
                                secure_false = True

                        if httponly_false or secure_false:
                            rule_def = get_rule_definition("FAP-019")
                            doc_url = (
                                rule_def.doc_url
                                if rule_def
                                else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-019"
                            )
                            diagnostics.append(
                                Diagnostic(
                                    id="FAP-019",
                                    severity=Severity.ERROR,
                                    category="framework",
                                    title="Insecure cookie configuration",
                                    message=f"set_cookie() called on line {child.lineno} with httponly=False or secure=False.",
                                    evidence=[
                                        Evidence(
                                            fact=f"Insecure cookie flags on line {child.lineno}.",
                                            source=file_path,
                                        )
                                    ],
                                    suggestions=[
                                        Suggestion(
                                            description="Set 'httponly=True' and 'secure=True' when configuring cookies in production."
                                        )
                                    ],
                                    file=file_path,
                                    line=child.lineno,
                                    column=getattr(child, "col_offset", None),
                                    doc_url=doc_url,
                                )
                            )

            # FAP-020: Potential open redirect in RedirectResponse
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    call_tuple = self._extract_call_tuple(child)
                    if call_tuple and call_tuple[-1] == "RedirectResponse":
                        if (
                            child.args
                            and isinstance(child.args[0], ast.Name)
                            and child.args[0].id in func_arg_names
                        ):
                            rule_def = get_rule_definition("FAP-020")
                            doc_url = (
                                rule_def.doc_url
                                if rule_def
                                else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-020"
                            )
                            diagnostics.append(
                                Diagnostic(
                                    id="FAP-020",
                                    severity=Severity.WARNING,
                                    category="framework",
                                    title="Potential open redirect in RedirectResponse",
                                    message=f"RedirectResponse on line {child.lineno} uses raw parameter '{child.args[0].id}' without URL validation.",
                                    evidence=[
                                        Evidence(
                                            fact=f"RedirectResponse({child.args[0].id}) called on line {child.lineno}.",
                                            source=file_path,
                                        )
                                    ],
                                    suggestions=[
                                        Suggestion(
                                            description="Validate that the redirect target is a relative path or matches a domain whitelist."
                                        )
                                    ],
                                    file=file_path,
                                    line=child.lineno,
                                    column=getattr(child, "col_offset", None),
                                    doc_url=doc_url,
                                )
                            )

            # FAP-003: Missing response model or return type annotation
            has_return_type = node.returns is not None
            if not has_response_model and not has_return_type and route_method != "websocket":
                rule_def = get_rule_definition("FAP-003")
                doc_url = (
                    rule_def.doc_url
                    if rule_def
                    else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-003"
                )

                diagnostics.append(
                    Diagnostic(
                        id="FAP-003",
                        severity=Severity.WARNING,
                        category="framework",
                        title="Missing response model or return type annotation",
                        message=(
                            f"FastAPI route handler '{node.name}' does not specify a 'response_model' in its decorator "
                            f"or a return type annotation."
                        ),
                        evidence=[
                            Evidence(
                                fact=f"Route '{node.name}' declared without response_model or return annotation.",
                                source=file_path,
                            )
                        ],
                        suggestions=[
                            Suggestion(
                                description=f"Add a return type annotation (e.g. '-> ItemResponse') or 'response_model=ItemResponse' to the @app.{route_method or 'get'} decorator.",
                                code_snippet=f"@{route_method or 'get'}(..., response_model=ItemResponse)\ndef {node.name}(...) -> ItemResponse:\n    ...",
                            )
                        ],
                        file=file_path,
                        line=node.lineno,
                        column=getattr(node, "col_offset", None),
                        doc_url=doc_url,
                    )
                )

            # FAP-025: Returned HTTPException instead of raise
            for child in ast.walk(node):
                if isinstance(child, ast.Return) and isinstance(child.value, ast.Call):
                    call_name = ""
                    if isinstance(child.value.func, ast.Name):
                        call_name = child.value.func.id
                    elif isinstance(child.value.func, ast.Attribute):
                        call_name = child.value.func.attr
                    if call_name == "HTTPException":
                        rule_def = get_rule_definition("FAP-025")
                        doc_url = (
                            rule_def.doc_url
                            if rule_def
                            else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-025"
                        )
                        diagnostics.append(
                            Diagnostic(
                                id="FAP-025",
                                severity=Severity.ERROR,
                                category="framework",
                                title="Returned HTTPException instance instead of raise",
                                message=f"Route '{node.name}' returns an HTTPException instance on line {child.lineno} instead of raising it, which causes FastAPI to return HTTP 200 OK.",
                                evidence=[
                                    Evidence(
                                        fact=f"return HTTPException(...) on line {child.lineno}.",
                                        source=file_path,
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description="Change 'return HTTPException(...)' to 'raise HTTPException(...)'.",
                                        code_snippet="raise HTTPException(status_code=404, detail='Not found')",
                                    )
                                ],
                                file=file_path,
                                line=child.lineno,
                                column=getattr(child, "col_offset", None),
                                doc_url=doc_url,
                            )
                        )

            # FAP-028: Raw json.loads on request body
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    call_tup = self._extract_call_tuple(child)
                    if call_tup == ("json", "loads") and child.args:
                        first_arg = child.args[0]
                        is_req_body = False
                        if isinstance(first_arg, ast.Await) and isinstance(
                            first_arg.value, ast.Call
                        ):
                            inner_tup = self._extract_call_tuple(first_arg.value)
                            if inner_tup and inner_tup[-1] == "body":
                                is_req_body = True
                        elif isinstance(first_arg, ast.Call):
                            inner_tup = self._extract_call_tuple(first_arg)
                            if inner_tup and inner_tup[-1] == "body":
                                is_req_body = True
                        elif isinstance(first_arg, ast.Attribute) and first_arg.attr == "body":
                            is_req_body = True
                        if is_req_body:
                            rule_def = get_rule_definition("FAP-028")
                            doc_url = (
                                rule_def.doc_url
                                if rule_def
                                else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-028"
                            )
                            diagnostics.append(
                                Diagnostic(
                                    id="FAP-028",
                                    severity=Severity.WARNING,
                                    category="framework",
                                    title="Raw json.loads called on request body",
                                    message=f"Route '{node.name}' calls 'json.loads()' on request body instead of using 'await request.json()'.",
                                    evidence=[
                                        Evidence(
                                            fact=f"json.loads(...) on request body on line {child.lineno}.",
                                            source=file_path,
                                        )
                                    ],
                                    suggestions=[
                                        Suggestion(
                                            description="Replace with 'await request.json()'.",
                                            code_snippet="data = await request.json()",
                                        )
                                    ],
                                    file=file_path,
                                    line=child.lineno,
                                    column=getattr(child, "col_offset", None),
                                    doc_url=doc_url,
                                )
                            )

            # FAP-029: StreamingResponse missing media_type
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    call_name = ""
                    if isinstance(child.func, ast.Name):
                        call_name = child.func.id
                    elif isinstance(child.func, ast.Attribute):
                        call_name = child.func.attr
                    if call_name == "StreamingResponse":
                        has_media_type = any(kw.arg == "media_type" for kw in child.keywords)
                        if not has_media_type:
                            rule_def = get_rule_definition("FAP-029")
                            doc_url = (
                                rule_def.doc_url
                                if rule_def
                                else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-029"
                            )
                            diagnostics.append(
                                Diagnostic(
                                    id="FAP-029",
                                    severity=Severity.WARNING,
                                    category="framework",
                                    title="StreamingResponse initialized without media_type",
                                    message=f"StreamingResponse instantiated on line {child.lineno} without an explicit 'media_type' argument.",
                                    evidence=[
                                        Evidence(
                                            fact=f"StreamingResponse(...) without media_type on line {child.lineno}.",
                                            source=file_path,
                                        )
                                    ],
                                    suggestions=[
                                        Suggestion(
                                            description="Specify media_type (e.g. media_type='text/event-stream' or 'application/octet-stream').",
                                            code_snippet="StreamingResponse(stream(), media_type='text/event-stream')",
                                        )
                                    ],
                                    file=file_path,
                                    line=child.lineno,
                                    column=getattr(child, "col_offset", None),
                                    doc_url=doc_url,
                                )
                            )

            # FAP-030: Missing route summary or docstring
            has_docstring = ast.get_docstring(node) is not None
            has_summary = False
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call):
                    for kw in dec.keywords:
                        if kw.arg in ("summary", "description"):
                            has_summary = True
            if not has_docstring and not has_summary and route_method != "websocket":
                rule_def = get_rule_definition("FAP-030")
                doc_url = (
                    rule_def.doc_url
                    if rule_def
                    else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-030"
                )
                diagnostics.append(
                    Diagnostic(
                        id="FAP-030",
                        severity=Severity.WARNING,
                        category="framework",
                        title="Missing route summary or docstring for OpenAPI documentation",
                        message=f"Route '{node.name}' has neither a docstring nor a 'summary'/'description' in its decorator.",
                        evidence=[
                            Evidence(
                                fact=f"Route '{node.name}' on line {node.lineno} missing OpenAPI documentation metadata.",
                                source=file_path,
                            )
                        ],
                        suggestions=[
                            Suggestion(
                                description="Add a docstring or 'summary=...' parameter to the route decorator.",
                                code_snippet=f'"""Retrieve or process {node.name}."""',
                            )
                        ],
                        file=file_path,
                        line=node.lineno,
                        column=getattr(node, "col_offset", None),
                        doc_url=doc_url,
                    )
                )

            # FAP-032: Redundant jsonable_encoder with response_model
            if has_response_model:
                for child in ast.walk(node):
                    if isinstance(child, ast.Return) and isinstance(child.value, ast.Call):
                        call_name = ""
                        if isinstance(child.value.func, ast.Name):
                            call_name = child.value.func.id
                        elif isinstance(child.value.func, ast.Attribute):
                            call_name = child.value.func.attr
                        if call_name == "jsonable_encoder":
                            rule_def = get_rule_definition("FAP-032")
                            doc_url = (
                                rule_def.doc_url
                                if rule_def
                                else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-032"
                            )
                            diagnostics.append(
                                Diagnostic(
                                    id="FAP-032",
                                    severity=Severity.WARNING,
                                    category="framework",
                                    title="Redundant jsonable_encoder with response_model",
                                    message=f"Route '{node.name}' returns jsonable_encoder() while declaring response_model, causing redundant double serialization.",
                                    evidence=[
                                        Evidence(
                                            fact=f"return jsonable_encoder(...) on line {child.lineno} with response_model configured.",
                                            source=file_path,
                                        )
                                    ],
                                    suggestions=[
                                        Suggestion(
                                            description="Return the raw object or dictionary directly; FastAPI will validate and serialize it via response_model.",
                                            code_snippet="return user_obj",
                                        )
                                    ],
                                    file=file_path,
                                    line=child.lineno,
                                    column=getattr(child, "col_offset", None),
                                    doc_url=doc_url,
                                )
                            )

            # FAP-034: Missing await on request.json() or request.body()
            if isinstance(node, ast.AsyncFunctionDef):
                awaited_calls = {
                    n.value
                    for n in ast.walk(node)
                    if isinstance(n, ast.Await) and isinstance(n.value, ast.Call)
                }
                for child in ast.walk(node):
                    if isinstance(child, ast.Call) and child not in awaited_calls:
                        call_tup = self._extract_call_tuple(child)
                        if (
                            call_tup
                            and len(call_tup) >= 2
                            and call_tup[-2] == "request"
                            and call_tup[-1] in ("json", "body")
                        ):
                            rule_def = get_rule_definition("FAP-034")
                            doc_url = (
                                rule_def.doc_url
                                if rule_def
                                else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-034"
                            )
                            diagnostics.append(
                                Diagnostic(
                                    id="FAP-034",
                                    severity=Severity.ERROR,
                                    category="framework",
                                    title="Missing await on request.json() or request.body()",
                                    message=f"Calling 'request.{call_tup[-1]}()' on line {child.lineno} without 'await' in async handler '{node.name}' assigns a coroutine object.",
                                    evidence=[
                                        Evidence(
                                            fact=f"Missing await on request.{call_tup[-1]}() on line {child.lineno}.",
                                            source=file_path,
                                        )
                                    ],
                                    suggestions=[
                                        Suggestion(
                                            description=f"Add 'await' before 'request.{call_tup[-1]}()'.",
                                            code_snippet=f"data = await request.{call_tup[-1]}()",
                                        )
                                    ],
                                    file=file_path,
                                    line=child.lineno,
                                    column=getattr(child, "col_offset", None),
                                    doc_url=doc_url,
                                )
                            )

            # FAP-035: Raw Exception raised instead of HTTPException
            for child in ast.walk(node):
                if isinstance(child, ast.Raise) and isinstance(child.exc, ast.Call):
                    exc_name = ""
                    if isinstance(child.exc.func, ast.Name):
                        exc_name = child.exc.func.id
                    elif isinstance(child.exc.func, ast.Attribute):
                        exc_name = child.exc.func.attr
                    if exc_name in (
                        "Exception",
                        "ValueError",
                        "RuntimeError",
                        "KeyError",
                        "TypeError",
                        "IndexError",
                    ):
                        rule_def = get_rule_definition("FAP-035")
                        doc_url = (
                            rule_def.doc_url
                            if rule_def
                            else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-035"
                        )
                        diagnostics.append(
                            Diagnostic(
                                id="FAP-035",
                                severity=Severity.WARNING,
                                category="framework",
                                title="Raw Exception raised instead of HTTPException",
                                message=f"Route '{node.name}' raises generic '{exc_name}' on line {child.lineno} instead of 'HTTPException', returning an unhandled 500 error.",
                                evidence=[
                                    Evidence(
                                        fact=f"raise {exc_name}(...) on line {child.lineno}.",
                                        source=file_path,
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description="Raise 'HTTPException(status_code=..., detail=...)' instead.",
                                        code_snippet="raise HTTPException(status_code=400, detail='Invalid request')",
                                    )
                                ],
                                file=file_path,
                                line=child.lineno,
                                column=getattr(child, "col_offset", None),
                                doc_url=doc_url,
                            )
                        )

            # FAP-036: Mutating app.state inside route handler
            for child in ast.walk(node):
                if isinstance(child, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                    for tgt in targets:
                        if isinstance(tgt, ast.Attribute):
                            parts: list[str] = []
                            curr: ast.expr = tgt
                            while isinstance(curr, ast.Attribute):
                                parts.append(curr.attr)
                                curr = curr.value
                            if isinstance(curr, ast.Name):
                                parts.append(curr.id)
                            parts = list(reversed(parts))
                            if (
                                len(parts) >= 3
                                and parts[-2] == "state"
                                and parts[-3] in ("app", "state")
                            ) or (
                                len(parts) >= 3
                                and parts[0] in ("request", "app")
                                and "state" in parts[:-1]
                            ):
                                rule_def = get_rule_definition("FAP-036")
                                doc_url = (
                                    rule_def.doc_url
                                    if rule_def
                                    else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-036"
                                )
                                diagnostics.append(
                                    Diagnostic(
                                        id="FAP-036",
                                        severity=Severity.WARNING,
                                        category="framework",
                                        title="Mutating app.state inside route handler",
                                        message=f"Route '{node.name}' mutates '{'.'.join(parts)}' on line {tgt.lineno}. Shared state should be initialized during lifespan startup.",
                                        evidence=[
                                            Evidence(
                                                fact=f"Mutation of app.state on line {tgt.lineno}.",
                                                source=file_path,
                                            )
                                        ],
                                        suggestions=[
                                            Suggestion(
                                                description="Initialize shared state inside the lifespan context manager rather than in route handlers."
                                            )
                                        ],
                                        file=file_path,
                                        line=tgt.lineno,
                                        column=getattr(tgt, "col_offset", None),
                                        doc_url=doc_url,
                                    )
                                )

        return diagnostics

    def _check_cors_and_security(self, tree: ast.AST, file_path: str) -> list[Diagnostic]:
        """Check for FAP-004: Insecure CORS, debug mode, or insecure token URLs."""
        diagnostics: list[Diagnostic] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # CORSMiddleware
                is_cors = False
                if isinstance(node.func, ast.Attribute) and node.func.attr == "add_middleware":
                    if node.args and any(
                        isinstance(a, ast.Name) and a.id == "CORSMiddleware" for a in node.args
                    ):
                        is_cors = True
                elif isinstance(node.func, ast.Name) and node.func.id == "CORSMiddleware":
                    is_cors = True

                if is_cors:
                    wildcard_origin = False
                    allow_credentials = False

                    for kw in node.keywords:
                        if kw.arg == "allow_origins":
                            if isinstance(kw.value, (ast.List, ast.Tuple)):
                                for elt in kw.value.elts:
                                    if isinstance(elt, ast.Constant) and elt.value == "*":
                                        wildcard_origin = True
                        elif kw.arg == "allow_credentials":
                            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                allow_credentials = True

                    if wildcard_origin and allow_credentials:
                        rule_def = get_rule_definition("FAP-004")
                        doc_url = (
                            rule_def.doc_url
                            if rule_def
                            else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-004"
                        )
                        diagnostics.append(
                            Diagnostic(
                                id="FAP-004",
                                severity=Severity.ERROR,
                                category="framework",
                                title="Insecure CORS configuration (Wildcard with Credentials)",
                                message=(
                                    "CORSMiddleware is configured with allow_origins=['*'] and allow_credentials=True. "
                                    "This creates a security risk and is disallowed by modern browser security policies."
                                ),
                                evidence=[
                                    Evidence(
                                        fact=f"allow_origins=['*'] combined with allow_credentials=True on line {node.lineno}.",
                                        source=file_path,
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description="Specify explicit trusted domain origins in allow_origins (e.g. ['https://app.example.com']).",
                                        code_snippet="allow_origins=['https://example.com', 'https://app.example.com'], allow_credentials=True",
                                    )
                                ],
                                file=file_path,
                                line=node.lineno,
                                column=getattr(node, "col_offset", None),
                                doc_url=doc_url,
                            )
                        )

                # FastAPI(debug=True)
                if isinstance(node.func, ast.Name) and node.func.id == "FastAPI":
                    for kw in node.keywords:
                        if (
                            kw.arg == "debug"
                            and isinstance(kw.value, ast.Constant)
                            and kw.value.value is True
                        ):
                            rule_def = get_rule_definition("FAP-004")
                            doc_url = (
                                rule_def.doc_url
                                if rule_def
                                else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-004"
                            )
                            diagnostics.append(
                                Diagnostic(
                                    id="FAP-004",
                                    severity=Severity.WARNING,
                                    category="framework",
                                    title="FastAPI debug mode explicitly enabled",
                                    message="FastAPI application instantiated with debug=True, which may expose sensitive traceback details.",
                                    evidence=[
                                        Evidence(
                                            fact=f"FastAPI(debug=True) configured on line {node.lineno}.",
                                            source=file_path,
                                        )
                                    ],
                                    suggestions=[
                                        Suggestion(
                                            description="Disable debug=True or configure it dynamically via environment variables.",
                                        )
                                    ],
                                    file=file_path,
                                    line=node.lineno,
                                    column=getattr(node, "col_offset", None),
                                    doc_url=doc_url,
                                )
                            )

                # OAuth2PasswordBearer(tokenUrl="http://...")
                if isinstance(node.func, ast.Name) and node.func.id == "OAuth2PasswordBearer":
                    for kw in node.keywords:
                        if (
                            kw.arg == "tokenUrl"
                            and isinstance(kw.value, ast.Constant)
                            and isinstance(kw.value.value, str)
                        ):
                            if kw.value.value.startswith(
                                "http://"
                            ) and not kw.value.value.startswith("http://localhost"):
                                rule_def = get_rule_definition("FAP-004")
                                doc_url = (
                                    rule_def.doc_url
                                    if rule_def
                                    else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-004"
                                )
                                diagnostics.append(
                                    Diagnostic(
                                        id="FAP-004",
                                        severity=Severity.ERROR,
                                        category="framework",
                                        title="Insecure HTTP tokenUrl in OAuth2 scheme",
                                        message=f"OAuth2PasswordBearer tokenUrl uses insecure plaintext HTTP: '{kw.value.value}'.",
                                        evidence=[
                                            Evidence(
                                                fact=f"tokenUrl='{kw.value.value}' on line {node.lineno}.",
                                                source=file_path,
                                            )
                                        ],
                                        suggestions=[
                                            Suggestion(
                                                description="Use an HTTPS URL or relative path (e.g. '/auth/token') for tokenUrl.",
                                            )
                                        ],
                                        file=file_path,
                                        line=node.lineno,
                                        column=getattr(node, "col_offset", None),
                                        doc_url=doc_url,
                                    )
                                )

        return diagnostics

    def _check_client_timeouts(self, tree: ast.AST, file_path: str) -> list[Diagnostic]:
        """Check for FAP-005: Missing HTTP client timeout configuration."""
        diagnostics: list[Diagnostic] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_tuple = self._extract_call_tuple(node)
            if not call_tuple:
                continue

            is_http_client = False
            client_name = ""
            if call_tuple in (("httpx", "AsyncClient"), ("httpx", "Client")):
                is_http_client = True
                client_name = ".".join(call_tuple)
            elif call_tuple in (("aiohttp", "ClientSession"),):
                is_http_client = True
                client_name = "aiohttp.ClientSession"

            if is_http_client:
                has_timeout = False
                timeout_none = False

                for kw in node.keywords:
                    if kw.arg == "timeout":
                        has_timeout = True
                        if isinstance(kw.value, ast.Constant) and kw.value.value is None:
                            timeout_none = True

                if not has_timeout or timeout_none:
                    rule_def = get_rule_definition("FAP-005")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-005"
                    )

                    diagnostics.append(
                        Diagnostic(
                            id="FAP-005",
                            severity=Severity.WARNING,
                            category="framework",
                            title="Missing HTTP client timeout configuration",
                            message=(
                                f"'{client_name}' is initialized without an explicit timeout. "
                                f"Unbounded HTTP requests can lead to thread or connection pool starvation."
                            ),
                            evidence=[
                                Evidence(
                                    fact=f"'{client_name}' instantiated on line {node.lineno} without timeout configuration.",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description=f"Configure an explicit timeout on '{client_name}' (e.g. timeout=10.0).",
                                    code_snippet=f"{client_name}(timeout=10.0)",
                                )
                            ],
                            file=file_path,
                            line=node.lineno,
                            column=getattr(node, "col_offset", None),
                            doc_url=doc_url,
                        )
                    )

        return diagnostics

    def _check_yield_dependencies(self, tree: ast.AST, file_path: str) -> list[Diagnostic]:
        """Check for FAP-007: Unsafe yield generator dependency without try...finally."""
        diagnostics: list[Diagnostic] = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            has_yield = any(isinstance(n, (ast.Yield, ast.YieldFrom)) for n in ast.walk(node))
            if not has_yield:
                continue

            yield_in_try_finally = False
            for stmt in node.body:
                if isinstance(stmt, ast.Try) and stmt.finalbody:
                    if any(isinstance(n, (ast.Yield, ast.YieldFrom)) for n in ast.walk(stmt)):
                        yield_in_try_finally = True

            if not yield_in_try_finally and len(node.body) > 1:
                rule_def = get_rule_definition("FAP-007")
                doc_url = (
                    rule_def.doc_url
                    if rule_def
                    else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-007"
                )
                diagnostics.append(
                    Diagnostic(
                        id="FAP-007",
                        severity=Severity.WARNING,
                        category="framework",
                        title="Unsafe yield dependency without try/finally block",
                        message=(
                            f"Generator dependency '{node.name}' contains a yield statement without a try...finally block. "
                            f"If an exception occurs during request execution, teardown/cleanup logic after yield will not execute."
                        ),
                        evidence=[
                            Evidence(
                                fact=f"Function '{node.name}' on line {node.lineno} yields resource without try...finally cleanup.",
                                source=file_path,
                            )
                        ],
                        suggestions=[
                            Suggestion(
                                description="Wrap the yield and teardown cleanup inside a try...finally block.",
                                code_snippet=f"def {node.name}():\n    resource = create_resource()\n    try:\n        yield resource\n    finally:\n        resource.close()",
                            )
                        ],
                        file=file_path,
                        line=node.lineno,
                        column=getattr(node, "col_offset", None),
                        doc_url=doc_url,
                    )
                )

        return diagnostics

    def _check_lifecycle_events(self, tree: ast.AST, file_path: str) -> list[Diagnostic]:
        """Check for FAP-008: Deprecated @app.on_event lifecycle hooks."""
        diagnostics: list[Diagnostic] = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            for dec in node.decorator_list:
                if isinstance(dec, ast.Call):
                    if isinstance(dec.func, ast.Attribute) and dec.func.attr == "on_event":
                        rule_def = get_rule_definition("FAP-008")
                        doc_url = (
                            rule_def.doc_url
                            if rule_def
                            else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-008"
                        )
                        event_name = "startup/shutdown"
                        if (
                            dec.args
                            and isinstance(dec.args[0], ast.Constant)
                            and isinstance(dec.args[0].value, str)
                        ):
                            event_name = dec.args[0].value

                        diagnostics.append(
                            Diagnostic(
                                id="FAP-008",
                                severity=Severity.WARNING,
                                category="framework",
                                title=f"Deprecated @app.on_event('{event_name}') lifecycle hook",
                                message=(
                                    f"Using @app.on_event('{event_name}') is deprecated in modern FastAPI/Starlette. "
                                    f"Use the async context manager lifespan handler instead."
                                ),
                                evidence=[
                                    Evidence(
                                        fact=f"@app.on_event('{event_name}') used on line {node.lineno}.",
                                        source=file_path,
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description="Migrate lifecycle logic to '@asynccontextmanager async def lifespan(app: FastAPI): ...'.",
                                        code_snippet="@asynccontextmanager\nasync def lifespan(app: FastAPI):\n    # Startup logic here\n    yield\n    # Shutdown logic here\n\napp = FastAPI(lifespan=lifespan)",
                                    )
                                ],
                                file=file_path,
                                line=node.lineno,
                                column=getattr(node, "col_offset", None),
                                doc_url=doc_url,
                            )
                        )

        return diagnostics

    def _check_exception_handlers(self, tree: ast.AST, file_path: str) -> list[Diagnostic]:
        """Check for FAP-012: Invalid exception handler signature."""
        diagnostics: list[Diagnostic] = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            for dec in node.decorator_list:
                is_exc_handler = False
                if isinstance(dec, ast.Call):
                    if isinstance(dec.func, ast.Attribute) and dec.func.attr == "exception_handler":
                        is_exc_handler = True
                    elif isinstance(dec.func, ast.Name) and dec.func.id == "exception_handler":
                        is_exc_handler = True

                if is_exc_handler:
                    num_args = len(node.args.args)
                    if num_args != 2:
                        rule_def = get_rule_definition("FAP-012")
                        doc_url = (
                            rule_def.doc_url
                            if rule_def
                            else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-012"
                        )
                        diagnostics.append(
                            Diagnostic(
                                id="FAP-012",
                                severity=Severity.ERROR,
                                category="framework",
                                title="Invalid exception handler signature",
                                message=(
                                    f"Exception handler '{node.name}' has {num_args} argument(s). "
                                    f"FastAPI requires exactly 2 arguments: (request: Request, exc: Exception)."
                                ),
                                evidence=[
                                    Evidence(
                                        fact=f"Function '{node.name}' declared with {num_args} parameter(s) on line {node.lineno}.",
                                        source=file_path,
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description="Update signature to '(request: Request, exc: Exception)'.",
                                        code_snippet=f"def {node.name}(request: Request, exc: Exception):",
                                    )
                                ],
                                file=file_path,
                                line=node.lineno,
                                column=getattr(node, "col_offset", None),
                                doc_url=doc_url,
                            )
                        )

        return diagnostics

    def _check_pydantic_models(self, tree: ast.AST, file_path: str) -> list[Diagnostic]:
        """Check for FAP-016 (Sensitive field exposure), FAP-023 (Pydantic v1 Config class), and FAP-026 (Deprecated validators)."""
        diagnostics: list[Diagnostic] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue

            # FAP-026: Check deprecated Pydantic v1 @validator or @root_validator
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for dec in item.decorator_list:
                        dec_name = ""
                        if isinstance(dec, ast.Call):
                            if isinstance(dec.func, ast.Name):
                                dec_name = dec.func.id
                            elif isinstance(dec.func, ast.Attribute):
                                dec_name = dec.func.attr
                        elif isinstance(dec, ast.Name):
                            dec_name = dec.id
                        elif isinstance(dec, ast.Attribute):
                            dec_name = dec.attr
                        if dec_name in ("validator", "root_validator"):
                            rule_def = get_rule_definition("FAP-026")
                            doc_url = (
                                rule_def.doc_url
                                if rule_def
                                else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-026"
                            )
                            diagnostics.append(
                                Diagnostic(
                                    id="FAP-026",
                                    severity=Severity.WARNING,
                                    category="framework",
                                    title="Deprecated Pydantic v1 @validator or @root_validator",
                                    message=f"Model '{node.name}' uses deprecated '@{dec_name}' on method '{item.name}'.",
                                    evidence=[
                                        Evidence(
                                            fact=f"@{dec_name} decorator on line {item.lineno}.",
                                            source=file_path,
                                        )
                                    ],
                                    suggestions=[
                                        Suggestion(
                                            description="Migrate to '@field_validator' or '@model_validator' from pydantic.",
                                            code_snippet=f"@field_validator('{item.name}')\n@classmethod\ndef validate_{item.name}(cls, v): ...",
                                        )
                                    ],
                                    file=file_path,
                                    line=item.lineno,
                                    column=getattr(item, "col_offset", None),
                                    doc_url=doc_url,
                                )
                            )

            # FAP-023: Check inner class Config
            for item in node.body:
                if isinstance(item, ast.ClassDef) and item.name == "Config":
                    rule_def = get_rule_definition("FAP-023")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-023"
                    )
                    diagnostics.append(
                        Diagnostic(
                            id="FAP-023",
                            severity=Severity.WARNING,
                            category="framework",
                            title="Deprecated Pydantic v1 Config class",
                            message=f"Class '{node.name}' uses inner 'class Config:' which is deprecated in Pydantic v2 / modern FastAPI.",
                            evidence=[
                                Evidence(
                                    fact=f"class Config found inside {node.name} on line {item.lineno}.",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description="Migrate to 'model_config = ConfigDict(...)' from pydantic.",
                                    code_snippet="model_config = ConfigDict(from_attributes=True)",
                                )
                            ],
                            file=file_path,
                            line=item.lineno,
                            column=getattr(item, "col_offset", None),
                            doc_url=doc_url,
                        )
                    )

            # FAP-016: Sensitive field exposure without Field(exclude=True)
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                    field_name = item.target.id.lower()
                    if field_name in SENSITIVE_FIELD_NAMES:
                        is_excluded = False
                        if item.value and isinstance(item.value, ast.Call):
                            for kw in item.value.keywords:
                                if (
                                    kw.arg == "exclude"
                                    and isinstance(kw.value, ast.Constant)
                                    and kw.value.value is True
                                ):
                                    is_excluded = True

                        if not is_excluded:
                            rule_def = get_rule_definition("FAP-016")
                            doc_url = (
                                rule_def.doc_url
                                if rule_def
                                else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-016"
                            )
                            diagnostics.append(
                                Diagnostic(
                                    id="FAP-016",
                                    severity=Severity.ERROR,
                                    category="framework",
                                    title="Sensitive credential field exposed in model",
                                    message=f"Field '{item.target.id}' in model '{node.name}' is not marked with 'Field(exclude=True)'.",
                                    evidence=[
                                        Evidence(
                                            fact=f"Sensitive field '{item.target.id}' declared on line {item.lineno}.",
                                            source=file_path,
                                        )
                                    ],
                                    suggestions=[
                                        Suggestion(
                                            description=f"Mark '{item.target.id}' as excluded: '{item.target.id}: str = Field(exclude=True)' or remove from output model.",
                                            code_snippet=f"{item.target.id}: str = Field(exclude=True)",
                                        )
                                    ],
                                    file=file_path,
                                    line=item.lineno,
                                    column=getattr(item, "col_offset", None),
                                    doc_url=doc_url,
                                )
                            )

            # FAP-033: Missing from_attributes=True in ORM response schema
            if node.name.endswith(("Response", "Out", "Schema", "Read", "DTO")):
                has_from_attributes = False
                for item in node.body:
                    if isinstance(item, (ast.Assign, ast.AnnAssign)):
                        target_name = ""
                        if (
                            isinstance(item, ast.Assign)
                            and item.targets
                            and isinstance(item.targets[0], ast.Name)
                        ):
                            target_name = item.targets[0].id
                        elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                            target_name = item.target.id

                        if target_name == "model_config" and isinstance(item.value, ast.Call):
                            for kw in item.value.keywords:
                                if (
                                    kw.arg == "from_attributes"
                                    and isinstance(kw.value, ast.Constant)
                                    and kw.value.value is True
                                ):
                                    has_from_attributes = True

                    elif isinstance(item, ast.ClassDef) and item.name == "Config":
                        for c_item in item.body:
                            if isinstance(c_item, ast.Assign):
                                for tgt in c_item.targets:
                                    if isinstance(tgt, ast.Name) and tgt.id in (
                                        "from_attributes",
                                        "orm_mode",
                                    ):
                                        if (
                                            isinstance(c_item.value, ast.Constant)
                                            and c_item.value.value is True
                                        ):
                                            has_from_attributes = True

                if not has_from_attributes:
                    rule_def = get_rule_definition("FAP-033")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-033"
                    )
                    diagnostics.append(
                        Diagnostic(
                            id="FAP-033",
                            severity=Severity.WARNING,
                            category="framework",
                            title="Missing from_attributes=True in ORM response schema",
                            message=f"Schema '{node.name}' does not configure 'model_config = ConfigDict(from_attributes=True)' for ORM serialization.",
                            evidence=[
                                Evidence(
                                    fact=f"Model '{node.name}' missing from_attributes=True on line {node.lineno}.",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description="Add 'model_config = ConfigDict(from_attributes=True)' to allow serializing ORM models.",
                                    code_snippet="model_config = ConfigDict(from_attributes=True)",
                                )
                            ],
                            file=file_path,
                            line=node.lineno,
                            column=getattr(node, "col_offset", None),
                            doc_url=doc_url,
                        )
                    )

        return diagnostics

    def _check_router_includes(self, tree: ast.AST, file_path: str) -> list[Diagnostic]:
        """Check for FAP-021: Router included without tags or prefix."""
        diagnostics: list[Diagnostic] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "include_router":
                    has_tags = any(kw.arg == "tags" for kw in node.keywords)
                    has_prefix = any(kw.arg == "prefix" for kw in node.keywords)

                    if not has_tags and not has_prefix:
                        rule_def = get_rule_definition("FAP-021")
                        doc_url = (
                            rule_def.doc_url
                            if rule_def
                            else "https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-021"
                        )
                        diagnostics.append(
                            Diagnostic(
                                id="FAP-021",
                                severity=Severity.WARNING,
                                category="framework",
                                title="Router included without tags or prefix",
                                message="include_router() called without 'tags' or 'prefix', creating flat and unorganized OpenAPI docs.",
                                evidence=[
                                    Evidence(
                                        fact=f"include_router() on line {node.lineno} missing prefix and tags.",
                                        source=file_path,
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description="Specify 'prefix' and 'tags' (e.g. app.include_router(router, prefix='/items', tags=['Items'])).",
                                        code_snippet="app.include_router(router, prefix='/items', tags=['Items'])",
                                    )
                                ],
                                file=file_path,
                                line=node.lineno,
                                column=getattr(node, "col_offset", None),
                                doc_url=doc_url,
                            )
                        )

        return diagnostics
