"""SQLAlchemy and SQL Database Framework Analyzer implementing SQL-001 through SQL-030."""

from __future__ import annotations

import ast
import re

from qv.core.context import ProjectContext
from qv.core.models import Diagnostic, Evidence, Severity, Suggestion
from qv.frameworks.base import FrameworkPlugin
from qv.rules.registry import get_rule_definition

SQL_PACKAGES = frozenset(
    {
        "sqlalchemy",
        "sqlmodel",
        "alembic",
        "databases",
        "psycopg",
        "psycopg2",
        "asyncpg",
        "aiosqlite",
        "tortoise-orm",
        "peewee",
    }
)

DB_URL_REGEX = re.compile(
    r"(?:postgresql|mysql|sqlite|oracle|mssql|cockroachdb)(?:\+[a-z0-9_]+)?://([^:]+):([^@]+)@([^/:]+)(?::\d+)?/([a-zA-Z0-9_.-]+)",
    re.IGNORECASE,
)


class SqlAlchemyAnalyzer(FrameworkPlugin):
    """Comprehensive diagnostic suite for SQLAlchemy, SQLModel, and SQL database interactions."""

    id = "sqlalchemy"
    name = "SQLAlchemy & SQL Database Analyzer"
    description = (
        "Detects N+1 query patterns, session lifecycle leaks, async blocking DB calls, "
        "SQL injection vulnerabilities, connection pool risks, schema integrity flaws, and modern 2.0 syntax."
    )

    def detect(self, context: ProjectContext) -> bool:
        """Detect if SQLAlchemy or SQL-related libraries are present in the project."""
        for dep in context.dependencies:
            if dep.name.lower() in SQL_PACKAGES:
                return True

        for pkg in context.installed_packages:
            if pkg.lower() in SQL_PACKAGES:
                return True

        for imp in context.imports:
            mod_root = imp.module_name.split(".")[0].lower()
            if mod_root in SQL_PACKAGES or mod_root == "sqlite3":
                return True

        return False

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        """Analyze project source files for SQL and SQLAlchemy diagnostics."""
        if not self.detect(context):
            return []

        diagnostics: list[Diagnostic] = []
        has_sqlalchemy_models = False

        for sf in context.source_files:
            try:
                tree = ast.parse(sf.content, filename=str(sf.path))
            except SyntaxError:
                continue

            file_rel = str(sf.relative_path).replace("\\", "/")

            # File-level checks
            diagnostics.extend(self._check_loops_and_queries(tree, file_rel))
            diagnostics.extend(self._check_sessions_and_lifecycle(tree, file_rel))
            diagnostics.extend(self._check_async_safety(tree, file_rel))
            diagnostics.extend(self._check_sql_injection(tree, file_rel))
            diagnostics.extend(self._check_engine_and_connections(tree, file_rel))
            diagnostics.extend(self._check_modern_syntax_and_orm(tree, file_rel))
            diagnostics.extend(self._check_models_and_schema(tree, file_rel))

            if self._has_model_definitions(tree):
                has_sqlalchemy_models = True

        # Project-level check: SQL-016 (Missing Alembic migration config)
        if has_sqlalchemy_models:
            diagnostics.extend(self._check_alembic_setup(context))

        return diagnostics

    def _extract_call_tuple(self, node: ast.Call) -> tuple[str, ...] | None:
        """Extract dotted chain from a call func (e.g. session.execute -> ('session', 'execute'))."""
        parts: list[str] = []
        curr: ast.expr = node.func
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
            return tuple(reversed(parts))
        return None

    def _has_model_definitions(self, tree: ast.AST) -> bool:
        """Check if AST contains SQLAlchemy or SQLModel Table / ORM Class definitions."""
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for base in node.bases:
                    if isinstance(base, ast.Name) and base.id in (
                        "Base",
                        "DeclarativeBase",
                        "SQLModel",
                        "Model",
                    ):
                        return True
                    elif isinstance(base, ast.Attribute) and base.attr in (
                        "Base",
                        "DeclarativeBase",
                        "SQLModel",
                        "Model",
                    ):
                        return True
        return False

    def _check_loops_and_queries(self, tree: ast.AST, file_path: str) -> list[Diagnostic]:
        """Check for SQL-001 (N+1 queries in loops) and SQL-013 (Flush/commit in loops)."""
        diagnostics: list[Diagnostic] = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.For, ast.While, ast.AsyncFor)):
                continue

            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue

                call_tup = self._extract_call_tuple(child)
                if not call_tup:
                    continue

                method_name = call_tup[-1]
                caller_name = call_tup[-2] if len(call_tup) >= 2 else ""

                # SQL-001: N+1 queries in loop
                is_db_query = False
                if method_name in ("execute", "query", "scalars", "scalar") and caller_name in (
                    "session",
                    "db",
                    "conn",
                    "cursor",
                    "cur",
                    "async_session",
                ):
                    is_db_query = True
                elif method_name == "get" and caller_name in ("session", "db", "async_session"):
                    # Check that first arg is not a string literal (which is dict.get('key'))
                    if child.args and not (
                        isinstance(child.args[0], ast.Constant)
                        and isinstance(child.args[0].value, str)
                    ):
                        is_db_query = True

                if is_db_query:
                    rule_def = get_rule_definition("SQL-001")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-001"
                    )
                    diagnostics.append(
                        Diagnostic(
                            id="SQL-001",
                            severity=Severity.WARNING,
                            category="framework",
                            title="Potential N+1 database query in loop",
                            message=f"Database query '{'.'.join(call_tup)}()' executed inside a loop on line {child.lineno}, causing N+1 performance degradation.",
                            evidence=[
                                Evidence(
                                    fact=f"Query executed inside {type(node).__name__} loop on line {child.lineno}.",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description="Batch load objects before the loop using 'where(Model.id.in_(ids))' or eager joinedload/selectinload.",
                                    code_snippet="# Batch query before loop\nstmt = select(Model).where(Model.id.in_(ids))\nresults = session.scalars(stmt).all()",
                                )
                            ],
                            file=file_path,
                            line=child.lineno,
                            column=getattr(child, "col_offset", None),
                            doc_url=doc_url,
                        )
                    )

                # SQL-013: Session flush/commit in loop
                if method_name in ("flush", "commit") and caller_name in (
                    "session",
                    "db",
                    "conn",
                    "async_session",
                ):
                    rule_def = get_rule_definition("SQL-013")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-013"
                    )
                    diagnostics.append(
                        Diagnostic(
                            id="SQL-013",
                            severity=Severity.WARNING,
                            category="framework",
                            title="Session flush or commit called inside loop",
                            message=f"Calling '{'.'.join(call_tup)}()' inside a loop on line {child.lineno} causes severe database roundtrip latency.",
                            evidence=[
                                Evidence(
                                    fact=f"{method_name}() called inside loop on line {child.lineno}.",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description=f"Accumulate changes and call '{caller_name}.{method_name}()' once outside the loop or use bulk insert statements.",
                                    code_snippet="# Option A: Single commit after loop\nfor item in items:\n    session.add(item)\nsession.commit()",
                                )
                            ],
                            file=file_path,
                            line=child.lineno,
                            column=getattr(child, "col_offset", None),
                            doc_url=doc_url,
                        )
                    )

        return diagnostics

    def _check_sessions_and_lifecycle(self, tree: ast.AST, file_path: str) -> list[Diagnostic]:
        """Check for SQL-002, SQL-007, SQL-009, SQL-021, SQL-026, SQL-027."""
        diagnostics: list[Diagnostic] = []

        # SQL-009: expire_on_commit in AsyncSession / async_sessionmaker
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_tup = self._extract_call_tuple(node)
                if call_tup and call_tup[-1] in ("AsyncSession", "async_sessionmaker"):
                    for kw in node.keywords:
                        if (
                            kw.arg == "expire_on_commit"
                            and isinstance(kw.value, ast.Constant)
                            and kw.value.value is True
                        ):
                            rule_def = get_rule_definition("SQL-009")
                            doc_url = (
                                rule_def.doc_url
                                if rule_def
                                else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-009"
                            )
                            diagnostics.append(
                                Diagnostic(
                                    id="SQL-009",
                                    severity=Severity.WARNING,
                                    category="framework",
                                    title="expire_on_commit=True in AsyncSession",
                                    message=f"'{call_tup[-1]}' configured with 'expire_on_commit=True' on line {node.lineno}, causing MissingGreenlet errors in async workflows.",
                                    evidence=[
                                        Evidence(
                                            fact=f"expire_on_commit=True on line {node.lineno}.",
                                            source=file_path,
                                        )
                                    ],
                                    suggestions=[
                                        Suggestion(
                                            description="Set 'expire_on_commit=False' for async sessions.",
                                            code_snippet="async_sessionmaker(engine, expire_on_commit=False)",
                                        )
                                    ],
                                    file=file_path,
                                    line=node.lineno,
                                    column=getattr(node, "col_offset", None),
                                    doc_url=doc_url,
                                )
                            )

        # SQL-021: Missing session.rollback() in database try...except blocks
        for try_node in ast.walk(tree):
            if not isinstance(try_node, ast.Try):
                continue

            has_db_ops = False
            for child in ast.walk(try_node):
                if isinstance(child, ast.Call):
                    c_tup = self._extract_call_tuple(child)
                    if (
                        c_tup
                        and len(c_tup) >= 2
                        and c_tup[-2] in ("session", "db", "s", "async_session")
                        and c_tup[-1] in ("add", "delete", "commit", "flush", "execute")
                    ):
                        has_db_ops = True
                        break

            if has_db_ops:
                for handler in try_node.handlers:
                    has_rollback = False
                    for h_child in ast.walk(handler):
                        if isinstance(h_child, ast.Call):
                            h_tup = self._extract_call_tuple(h_child)
                            if h_tup and h_tup[-1] == "rollback":
                                has_rollback = True
                                break

                    if not has_rollback:
                        rule_def = get_rule_definition("SQL-021")
                        doc_url = (
                            rule_def.doc_url
                            if rule_def
                            else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-021"
                        )
                        diagnostics.append(
                            Diagnostic(
                                id="SQL-021",
                                severity=Severity.WARNING,
                                category="framework",
                                title="Missing session.rollback() in database exception handler",
                                message=f"Exception handler on line {handler.lineno} catches database errors without invoking session.rollback().",
                                evidence=[
                                    Evidence(
                                        fact=f"except block on line {handler.lineno} handles database exception without rollback().",
                                        source=file_path,
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description="Call 'session.rollback()' or 'await session.rollback()' in except handlers.",
                                        code_snippet="except Exception:\n    session.rollback()\n    raise",
                                    )
                                ],
                                file=file_path,
                                line=handler.lineno,
                                doc_url=doc_url,
                            )
                        )

        # Check function-level session lifecycles
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            is_async_func = isinstance(func, ast.AsyncFunctionDef)
            session_vars: dict[str, int] = {}
            async_session_vars: dict[str, int] = {}
            cleaned_up_vars: set[str] = set()
            mutated_session: set[str] = set()
            committed_session: set[str] = set()

            # SQL-027 check: concurrent balance/counter mutation without with_for_update()
            has_counter_mutation = False
            has_for_update = False
            mutation_line = func.lineno

            for item in ast.walk(func):
                # Detect balance decrement or numeric update
                if isinstance(item, ast.AugAssign) and isinstance(item.op, (ast.Sub, ast.Add)):
                    if isinstance(item.target, ast.Attribute) and any(
                        kw in item.target.attr.lower()
                        for kw in ("balance", "stock", "quantity", "credits", "counter", "amount")
                    ):
                        has_counter_mutation = True
                        mutation_line = item.lineno

                # Detect with_for_update call
                if isinstance(item, ast.Call):
                    call_tup = self._extract_call_tuple(item)
                    if call_tup and call_tup[-1] == "with_for_update":
                        has_for_update = True

                # Detect session instantiation e.g. session = SessionLocal() or db = Session()
                if isinstance(item, ast.Assign):
                    if isinstance(item.value, ast.Call):
                        call_tup = self._extract_call_tuple(item.value)
                        if call_tup:
                            for target in item.targets:
                                if isinstance(target, ast.Name):
                                    if any(
                                        name in call_tup[-1]
                                        for name in (
                                            "SessionLocal",
                                            "Session",
                                            "scoped_session",
                                            "sessionmaker",
                                        )
                                    ):
                                        session_vars[target.id] = item.lineno
                                    if any(
                                        name in call_tup[-1]
                                        for name in (
                                            "AsyncSession",
                                            "async_sessionmaker",
                                            "AsyncSessionLocal",
                                        )
                                    ):
                                        async_session_vars[target.id] = item.lineno

                # Detect context manager usage e.g. with SessionLocal() as session:
                if isinstance(item, (ast.With, ast.AsyncWith)):
                    for with_item in item.items:
                        if isinstance(with_item.optional_vars, ast.Name):
                            cleaned_up_vars.add(with_item.optional_vars.id)
                        if isinstance(with_item.context_expr, ast.Name):
                            cleaned_up_vars.add(with_item.context_expr.id)

                # Detect explicit session.close() or await session.close()
                if isinstance(item, ast.Call):
                    call_tup = self._extract_call_tuple(item)
                    if call_tup and len(call_tup) >= 2 and call_tup[-1] == "close":
                        cleaned_up_vars.add(call_tup[-2])
                    if (
                        call_tup
                        and len(call_tup) >= 2
                        and call_tup[-1] in ("add", "add_all", "delete")
                    ):
                        mutated_session.add(call_tup[-2])
                    if call_tup and len(call_tup) >= 2 and call_tup[-1] in ("commit", "begin"):
                        committed_session.add(call_tup[-2])

                if isinstance(item, (ast.Yield, ast.YieldFrom)):
                    if isinstance(item.value, ast.Name):
                        cleaned_up_vars.add(item.value.id)

            # SQL-027: Unsafe concurrent numeric balance or counter update
            if has_counter_mutation and not has_for_update:
                rule_def = get_rule_definition("SQL-027")
                doc_url = (
                    rule_def.doc_url
                    if rule_def
                    else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-027"
                )
                diagnostics.append(
                    Diagnostic(
                        id="SQL-027",
                        severity=Severity.WARNING,
                        category="framework",
                        title="Unsafe concurrent numeric balance or counter update without with_for_update()",
                        message=f"Function '{func.name}' mutates numeric balance/counter on line {mutation_line} without row-level locking (with_for_update()).",
                        evidence=[
                            Evidence(
                                fact=f"Counter mutation in {func.name} without select(...).with_for_update().",
                                source=file_path,
                            )
                        ],
                        suggestions=[
                            Suggestion(
                                description="Lock rows with 'with_for_update()' or use atomic SQL expressions.",
                                code_snippet="stmt = select(Account).where(Account.id == acc_id).with_for_update()",
                            )
                        ],
                        file=file_path,
                        line=mutation_line,
                        doc_url=doc_url,
                    )
                )

            # SQL-026: AsyncSession unmanaged in async function
            if is_async_func:
                for as_var, as_line in async_session_vars.items():
                    if as_var not in cleaned_up_vars:
                        rule_def = get_rule_definition("SQL-026")
                        doc_url = (
                            rule_def.doc_url
                            if rule_def
                            else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-026"
                        )
                        diagnostics.append(
                            Diagnostic(
                                id="SQL-026",
                                severity=Severity.WARNING,
                                category="framework",
                                title="AsyncSession instantiated without async context manager or await close()",
                                message=f"AsyncSession variable '{as_var}' created on line {as_line} is not closed or managed via 'async with'.",
                                evidence=[
                                    Evidence(
                                        fact=f"AsyncSession '{as_var}' on line {as_line} missing async with or await close().",
                                        source=file_path,
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description=f"Use 'async with AsyncSessionLocal() as {as_var}:'.",
                                        code_snippet=f"async with AsyncSessionLocal() as {as_var}:\n    ...",
                                    )
                                ],
                                file=file_path,
                                line=as_line,
                                doc_url=doc_url,
                            )
                        )

            # SQL-002: Session leak
            for s_var, s_line in session_vars.items():
                if s_var not in cleaned_up_vars:
                    rule_def = get_rule_definition("SQL-002")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-002"
                    )
                    diagnostics.append(
                        Diagnostic(
                            id="SQL-002",
                            severity=Severity.WARNING,
                            category="framework",
                            title="Session instantiated without context manager or cleanup",
                            message=f"Session variable '{s_var}' created on line {s_line} is not closed or managed by a context manager.",
                            evidence=[
                                Evidence(
                                    fact=f"Session variable '{s_var}' instantiated without with-block or close() on line {s_line}.",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description=f"Use 'with {s_var}:' or wrap in a try...finally block with '{s_var}.close()'.",
                                    code_snippet=f"with SessionLocal() as {s_var}:\n    ...",
                                )
                            ],
                            file=file_path,
                            line=s_line,
                            doc_url=doc_url,
                        )
                    )

            # SQL-007: Uncommitted transaction in mutation function
            uncommitted = mutated_session - committed_session
            for s_var in uncommitted:
                if s_var in session_vars or s_var in ("session", "db", "s"):
                    rule_def = get_rule_definition("SQL-007")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-007"
                    )
                    diagnostics.append(
                        Diagnostic(
                            id="SQL-007",
                            severity=Severity.WARNING,
                            category="framework",
                            title="Uncommitted transaction in mutation function",
                            message=f"Function '{func.name}' mutates database state via '{s_var}' (add/delete) without calling '{s_var}.commit()'.",
                            evidence=[
                                Evidence(
                                    fact=f"Mutations recorded on '{s_var}' inside {func.name} on line {func.lineno} without commit().",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description=f"Call 'await {s_var}.commit()' or use 'with {s_var}.begin():'.",
                                    code_snippet=f"{s_var}.commit()",
                                )
                            ],
                            file=file_path,
                            line=func.lineno,
                            doc_url=doc_url,
                        )
                    )

        return diagnostics

    def _check_async_safety(self, tree: ast.AST, file_path: str) -> list[Diagnostic]:
        """Check for SQL-003: Sync DB operation in async; SQL-028: Thread-local scoped_session in async."""
        diagnostics: list[Diagnostic] = []

        for func in ast.walk(tree):
            if not isinstance(func, ast.AsyncFunctionDef):
                continue

            for child in ast.walk(func):
                if isinstance(child, ast.Call):
                    call_tup = self._extract_call_tuple(child)
                    if not call_tup:
                        continue

                    # SQL-003: create_engine() in async function
                    if call_tup[-1] == "create_engine":
                        rule_def = get_rule_definition("SQL-003")
                        doc_url = (
                            rule_def.doc_url
                            if rule_def
                            else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-003"
                        )
                        diagnostics.append(
                            Diagnostic(
                                id="SQL-003",
                                severity=Severity.ERROR,
                                category="framework",
                                title="Synchronous DB operation in async event loop",
                                message=f"Synchronous 'create_engine()' called on line {child.lineno} inside async function '{func.name}'.",
                                evidence=[
                                    Evidence(
                                        fact=f"Synchronous create_engine() inside async def {func.name}() on line {child.lineno}.",
                                        source=file_path,
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description="Use 'create_async_engine()' from 'sqlalchemy.ext.asyncio'.",
                                        code_snippet="engine = create_async_engine('postgresql+asyncpg://...')",
                                    )
                                ],
                                file=file_path,
                                line=child.lineno,
                                column=getattr(child, "col_offset", None),
                                doc_url=doc_url,
                            )
                        )

                    # SQL-028: scoped_session in async function
                    if call_tup[-1] == "scoped_session":
                        rule_def = get_rule_definition("SQL-028")
                        doc_url = (
                            rule_def.doc_url
                            if rule_def
                            else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-028"
                        )
                        diagnostics.append(
                            Diagnostic(
                                id="SQL-028",
                                severity=Severity.ERROR,
                                category="framework",
                                title="Thread-local scoped_session used in async context",
                                message=f"Thread-local 'scoped_session' called on line {child.lineno} inside async function '{func.name}'.",
                                evidence=[
                                    Evidence(
                                        fact=f"scoped_session inside async def {func.name}() on line {child.lineno}.",
                                        source=file_path,
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description="Use 'async_scoped_session(..., scopefunc=asyncio.current_task)' or FastAPI dependency injection.",
                                        code_snippet="async_scoped_session(async_session_factory, scopefunc=asyncio.current_task)",
                                    )
                                ],
                                file=file_path,
                                line=child.lineno,
                                column=getattr(child, "col_offset", None),
                                doc_url=doc_url,
                            )
                        )

        return diagnostics

    def _check_sql_injection(self, tree: ast.AST, file_path: str) -> list[Diagnostic]:
        """Check for SQL-004: Raw SQL string interpolation (SQL Injection Risk)."""
        diagnostics: list[Diagnostic] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_tup = self._extract_call_tuple(node)
            if not call_tup:
                continue

            call_name = call_tup[-1]
            is_sql_call = call_name in ("text", "execute", "executemany") or (
                len(call_tup) >= 2
                and call_tup[-2] in ("cursor", "cur", "conn", "session", "db")
                and call_name == "execute"
            )

            if is_sql_call and node.args:
                first_arg = node.args[0]
                has_interpolation = False

                # Check f-strings
                if isinstance(first_arg, ast.JoinedStr):
                    has_interpolation = True

                # Check % formatting or .format()
                elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):
                    has_interpolation = True
                elif (
                    isinstance(first_arg, ast.Call)
                    and isinstance(first_arg.func, ast.Attribute)
                    and first_arg.func.attr == "format"
                ):
                    has_interpolation = True

                if has_interpolation:
                    rule_def = get_rule_definition("SQL-004")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-004"
                    )
                    diagnostics.append(
                        Diagnostic(
                            id="SQL-004",
                            severity=Severity.ERROR,
                            category="framework",
                            title="Raw SQL string interpolation (SQL Injection Risk)",
                            message=f"SQL query constructed using string interpolation/formatting on line {node.lineno}, risking SQL injection.",
                            evidence=[
                                Evidence(
                                    fact=f"Dynamic string formatting inside {call_name}() on line {node.lineno}.",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description="Use parameterized queries with bound variables (:param) instead of string formatting.",
                                    code_snippet="stmt = text('SELECT * FROM users WHERE id = :user_id')\nresult = session.execute(stmt, {'user_id': uid})",
                                )
                            ],
                            file=file_path,
                            line=node.lineno,
                            column=getattr(node, "col_offset", None),
                            doc_url=doc_url,
                        )
                    )

        return diagnostics

    def _check_engine_and_connections(self, tree: ast.AST, file_path: str) -> list[Diagnostic]:
        """Check for SQL-008, SQL-010, SQL-015, SQL-018, SQL-019, SQL-024, SQL-030."""
        diagnostics: list[Diagnostic] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_tup = self._extract_call_tuple(node)
            if not call_tup:
                continue

            # SQL-030: Direct DBAPI raw_connection() used without cleanup
            if call_tup[-1] == "raw_connection":
                rule_def = get_rule_definition("SQL-030")
                doc_url = (
                    rule_def.doc_url
                    if rule_def
                    else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-030"
                )
                diagnostics.append(
                    Diagnostic(
                        id="SQL-030",
                        severity=Severity.WARNING,
                        category="framework",
                        title="Direct DBAPI raw_connection() used without cleanup",
                        message=f"Calling 'raw_connection()' on line {node.lineno} bypasses connection pool management.",
                        evidence=[
                            Evidence(
                                fact=f"engine.raw_connection() on line {node.lineno}.",
                                source=file_path,
                            )
                        ],
                        suggestions=[
                            Suggestion(
                                description="Always close raw DBAPI connections in a try...finally block.",
                                code_snippet="raw_conn = engine.raw_connection()\ntry:\n    ...\nfinally:\n    raw_conn.close()",
                            )
                        ],
                        file=file_path,
                        line=node.lineno,
                        column=getattr(node, "col_offset", None),
                        doc_url=doc_url,
                    )
                )

            if call_tup[-1] not in ("create_engine", "create_async_engine"):
                continue

            # SQL-010 & SQL-024: Check connection URL properties
            if (
                node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                url_str = node.args[0].value
                match = DB_URL_REGEX.search(url_str)
                if match:
                    user, password = match.group(1), match.group(2)
                    host = match.group(3)
                    if password and not password.startswith("$") and not password.startswith("{"):
                        rule_def = get_rule_definition("SQL-010")
                        doc_url = (
                            rule_def.doc_url
                            if rule_def
                            else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-010"
                        )
                        diagnostics.append(
                            Diagnostic(
                                id="SQL-010",
                                severity=Severity.ERROR,
                                category="framework",
                                title="Hardcoded database credentials in connection URL",
                                message=f"Hardcoded database password for user '{user}' detected on line {node.lineno}.",
                                evidence=[
                                    Evidence(
                                        fact=f"Plaintext database credentials in connection string on line {node.lineno}.",
                                        source=file_path,
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description="Load database connection URL from environment variables.",
                                        code_snippet="DATABASE_URL = os.getenv('DATABASE_URL')\nengine = create_engine(DATABASE_URL)",
                                    )
                                ],
                                file=file_path,
                                line=node.lineno,
                                column=getattr(node, "col_offset", None),
                                doc_url=doc_url,
                            )
                        )

                    # SQL-024: Insecure unencrypted remote database connection URL
                    if (
                        host not in ("localhost", "127.0.0.1", "0.0.0.0")
                        and "ssl" not in url_str.lower()
                    ):
                        rule_def = get_rule_definition("SQL-024")
                        doc_url = (
                            rule_def.doc_url
                            if rule_def
                            else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-024"
                        )
                        diagnostics.append(
                            Diagnostic(
                                id="SQL-024",
                                severity=Severity.WARNING,
                                category="framework",
                                title="Insecure unencrypted remote database connection URL",
                                message=f"Remote database connection to '{host}' on line {node.lineno} does not configure SSL encryption ('sslmode=require' or 'ssl=true').",
                                evidence=[
                                    Evidence(
                                        fact=f"Remote DB URL without sslmode/ssl parameter on line {node.lineno}.",
                                        source=file_path,
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description="Enable SSL encryption for remote database connections.",
                                        code_snippet="DATABASE_URL = 'postgresql+psycopg2://user:pass@remote-host:5432/db?sslmode=require'",
                                    )
                                ],
                                file=file_path,
                                line=node.lineno,
                                column=getattr(node, "col_offset", None),
                                doc_url=doc_url,
                            )
                        )

            # SQL-018: Excessive connection pool size (> 50)
            for kw in node.keywords:
                if (
                    kw.arg in ("pool_size", "max_overflow")
                    and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, int)
                ):
                    if kw.value.value > 50:
                        rule_def = get_rule_definition("SQL-018")
                        doc_url = (
                            rule_def.doc_url
                            if rule_def
                            else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-018"
                        )
                        diagnostics.append(
                            Diagnostic(
                                id="SQL-018",
                                severity=Severity.WARNING,
                                category="framework",
                                title="Excessive connection pool size in single application instance",
                                message=f"create_engine declared with '{kw.arg}={kw.value.value}' on line {node.lineno}, which risks database connection starvation.",
                                evidence=[
                                    Evidence(
                                        fact=f"{kw.arg}={kw.value.value} (> 50) on line {node.lineno}.",
                                        source=file_path,
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description="Set pool_size between 5 and 20 per app instance and use an external pooler (e.g. pgBouncer).",
                                        code_snippet="engine = create_engine(..., pool_size=20, max_overflow=10)",
                                    )
                                ],
                                file=file_path,
                                line=node.lineno,
                                column=getattr(node, "col_offset", None),
                                doc_url=doc_url,
                            )
                        )

                # SQL-019: NullPool configured in persistent web application
                if (
                    kw.arg == "poolclass"
                    and isinstance(kw.value, ast.Name)
                    and kw.value.id == "NullPool"
                ):
                    rule_def = get_rule_definition("SQL-019")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-019"
                    )
                    diagnostics.append(
                        Diagnostic(
                            id="SQL-019",
                            severity=Severity.WARNING,
                            category="framework",
                            title="NullPool configured in persistent web application",
                            message=f"create_engine configured with 'poolclass=NullPool' on line {node.lineno}, disabling connection reuse and creating high latency overhead.",
                            evidence=[
                                Evidence(
                                    fact=f"poolclass=NullPool on line {node.lineno}.",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description="Use standard connection pooling (QueuePool) for persistent web servers.",
                                    code_snippet="engine = create_engine(DATABASE_URL, pool_size=10)",
                                )
                            ],
                            file=file_path,
                            line=node.lineno,
                            column=getattr(node, "col_offset", None),
                            doc_url=doc_url,
                        )
                    )

            # SQL-008: Check missing pool_pre_ping=True
            has_pre_ping = any(
                kw.arg == "pool_pre_ping"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                for kw in node.keywords
            )
            is_sqlite = False
            if (
                node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                if node.args[0].value.startswith("sqlite"):
                    is_sqlite = True

            if not has_pre_ping and not is_sqlite:
                rule_def = get_rule_definition("SQL-008")
                doc_url = (
                    rule_def.doc_url
                    if rule_def
                    else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-008"
                )
                diagnostics.append(
                    Diagnostic(
                        id="SQL-008",
                        severity=Severity.WARNING,
                        category="framework",
                        title="create_engine missing pool_pre_ping connection health check",
                        message=f"Database engine on line {node.lineno} is missing 'pool_pre_ping=True' to detect stale dropped connections.",
                        evidence=[
                            Evidence(
                                fact=f"{call_tup[-1]}() declared without pool_pre_ping=True on line {node.lineno}.",
                                source=file_path,
                            )
                        ],
                        suggestions=[
                            Suggestion(
                                description="Add 'pool_pre_ping=True' to prevent stale connection drops.",
                                code_snippet=f"{call_tup[-1]}(..., pool_pre_ping=True)",
                            )
                        ],
                        file=file_path,
                        line=node.lineno,
                        column=getattr(node, "col_offset", None),
                        doc_url=doc_url,
                    )
                )

            # SQL-015: SQLite check_same_thread=False
            if is_sqlite:
                has_check_same_thread = False
                for kw in node.keywords:
                    if kw.arg == "connect_args" and isinstance(kw.value, ast.Dict):
                        for k, v in zip(kw.value.keys, kw.value.values, strict=False):
                            if isinstance(k, ast.Constant) and k.value == "check_same_thread":
                                if isinstance(v, ast.Constant) and v.value is False:
                                    has_check_same_thread = True

                if not has_check_same_thread:
                    rule_def = get_rule_definition("SQL-015")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-015"
                    )
                    diagnostics.append(
                        Diagnostic(
                            id="SQL-015",
                            severity=Severity.WARNING,
                            category="framework",
                            title="SQLite engine missing check_same_thread=False in multi-threaded application",
                            message=f"SQLite database engine on line {node.lineno} does not set 'connect_args={{\"check_same_thread\": False}}'.",
                            evidence=[
                                Evidence(
                                    fact=f"SQLite create_engine() without check_same_thread=False on line {node.lineno}.",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description="Pass 'connect_args={\"check_same_thread\": False}' for SQLite in web apps.",
                                    code_snippet="create_engine('sqlite:///app.db', connect_args={'check_same_thread': False})",
                                )
                            ],
                            file=file_path,
                            line=node.lineno,
                            column=getattr(node, "col_offset", None),
                            doc_url=doc_url,
                        )
                    )

        return diagnostics

    def _check_modern_syntax_and_orm(self, tree: ast.AST, file_path: str) -> list[Diagnostic]:
        """Check for SQL-005, SQL-011, SQL-014, SQL-025."""
        diagnostics: list[Diagnostic] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_tup = self._extract_call_tuple(node)

                # SQL-025: Deprecated engine.execute() / engine.scalar()
                if (
                    call_tup
                    and len(call_tup) >= 2
                    and call_tup[-2] in ("engine", "async_engine")
                    and call_tup[-1] in ("execute", "scalar")
                ):
                    rule_def = get_rule_definition("SQL-025")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-025"
                    )
                    diagnostics.append(
                        Diagnostic(
                            id="SQL-025",
                            severity=Severity.ERROR,
                            category="framework",
                            title="Deprecated engine.execute() or engine.scalar() direct call",
                            message=f"Direct '{'.'.join(call_tup)}()' called on line {node.lineno} is removed in SQLAlchemy 2.0.",
                            evidence=[
                                Evidence(
                                    fact=f"engine.{call_tup[-1]}() on line {node.lineno}.",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description="Acquire connection explicitly: 'with engine.connect() as conn: conn.execute(...)'.",
                                    code_snippet="with engine.connect() as conn:\n    result = conn.execute(stmt)",
                                )
                            ],
                            file=file_path,
                            line=node.lineno,
                            column=getattr(node, "col_offset", None),
                            doc_url=doc_url,
                        )
                    )

                # SQL-014: Deprecated declarative_base()
                if call_tup and call_tup[-1] == "declarative_base":
                    rule_def = get_rule_definition("SQL-014")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-014"
                    )
                    diagnostics.append(
                        Diagnostic(
                            id="SQL-014",
                            severity=Severity.WARNING,
                            category="framework",
                            title="Deprecated declarative_base() function",
                            message=f"Legacy 'declarative_base()' used on line {node.lineno}. SQLAlchemy 2.0 recommends subclassing 'DeclarativeBase'.",
                            evidence=[
                                Evidence(
                                    fact=f"declarative_base() on line {node.lineno}.",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description="Subclass 'DeclarativeBase' from 'sqlalchemy.orm'.",
                                    code_snippet="from sqlalchemy.orm import DeclarativeBase\n\nclass Base(DeclarativeBase):\n    pass",
                                )
                            ],
                            file=file_path,
                            line=node.lineno,
                            column=getattr(node, "col_offset", None),
                            doc_url=doc_url,
                        )
                    )

                # SQL-005: Legacy session.query()
                if (
                    call_tup
                    and call_tup[-1] == "query"
                    and len(call_tup) >= 2
                    and call_tup[-2] in ("session", "db", "s")
                ):
                    rule_def = get_rule_definition("SQL-005")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-005"
                    )
                    diagnostics.append(
                        Diagnostic(
                            id="SQL-005",
                            severity=Severity.WARNING,
                            category="framework",
                            title="Legacy SQLAlchemy 1.x session.query() syntax",
                            message=f"Legacy 'session.query()' called on line {node.lineno}. Use SQLAlchemy 2.0 'session.scalars(select(...))'.",
                            evidence=[
                                Evidence(
                                    fact=f"session.query() on line {node.lineno}.", source=file_path
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description="Migrate to 2.0 select() syntax.",
                                    code_snippet="stmt = select(User).where(User.active == True)\nusers = session.scalars(stmt).all()",
                                )
                            ],
                            file=file_path,
                            line=node.lineno,
                            column=getattr(node, "col_offset", None),
                            doc_url=doc_url,
                        )
                    )

                # SQL-011: Unbounded .all()
                if isinstance(node.func, ast.Attribute) and node.func.attr == "all":
                    caller = node.func.value
                    is_unbounded_query = False
                    if isinstance(caller, ast.Call):
                        inner_tup = self._extract_call_tuple(caller)
                        if inner_tup and inner_tup[-1] in ("scalars", "execute", "query", "select"):
                            is_unbounded_query = True
                    elif isinstance(caller, ast.Name) and caller.id in (
                        "query",
                        "stmt",
                        "result",
                        "records",
                        "items",
                        "res",
                    ):
                        is_unbounded_query = True
                    elif isinstance(caller, ast.Attribute) and caller.attr in (
                        "query",
                        "scalars",
                        "execute",
                    ):
                        is_unbounded_query = True

                    if is_unbounded_query:
                        rule_def = get_rule_definition("SQL-011")
                        doc_url = (
                            rule_def.doc_url
                            if rule_def
                            else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-011"
                        )
                        diagnostics.append(
                            Diagnostic(
                                id="SQL-011",
                                severity=Severity.WARNING,
                                category="framework",
                                title="Unbounded SELECT query without limit or pagination",
                                message=f"Calling '.all()' on database query on line {node.lineno} without visible limit() clause risks memory exhaustion.",
                                evidence=[
                                    Evidence(
                                        fact=f"Query .all() on line {node.lineno}.",
                                        source=file_path,
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description="Add '.limit(PAGE_SIZE)' or paginate results.",
                                        code_snippet="stmt = select(Item).limit(100)\nitems = session.scalars(stmt).all()",
                                    )
                                ],
                                file=file_path,
                                line=node.lineno,
                                column=getattr(node, "col_offset", None),
                                doc_url=doc_url,
                            )
                        )

        return diagnostics

    def _check_models_and_schema(self, tree: ast.AST, file_path: str) -> list[Diagnostic]:
        """Check for SQL-012, SQL-017, SQL-020, SQL-022, SQL-023, SQL-029."""
        diagnostics: list[Diagnostic] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue

            # Determine if this class inherits from Base / DeclarativeBase / SQLModel
            is_orm_model = False
            for base in node.bases:
                if isinstance(base, ast.Name) and base.id in (
                    "Base",
                    "DeclarativeBase",
                    "SQLModel",
                    "Model",
                ):
                    is_orm_model = True
                elif isinstance(base, ast.Attribute) and base.attr in (
                    "Base",
                    "DeclarativeBase",
                    "SQLModel",
                    "Model",
                ):
                    is_orm_model = True

            if not is_orm_model:
                continue

            # Check if abstract class / mixin
            is_abstract = False
            has_table_name = False
            has_primary_key = False
            has_columns = False
            has_cascade_delete = False
            has_fk_cascade = False
            cascade_lineno = node.lineno

            for item in node.body:
                # Check __abstract__ = True
                if isinstance(item, ast.Assign):
                    for target in item.targets:
                        if isinstance(target, ast.Name):
                            if (
                                target.id == "__abstract__"
                                and isinstance(item.value, ast.Constant)
                                and item.value.value is True
                            ):
                                is_abstract = True
                            if target.id in ("__tablename__", "__table__"):
                                has_table_name = True

                # Check SQL-017: Mapped[...] = Column(...)
                if isinstance(item, ast.AnnAssign):
                    if item.annotation and isinstance(item.annotation, ast.Subscript):
                        if (
                            isinstance(item.annotation.value, ast.Name)
                            and item.annotation.value.id == "Mapped"
                        ):
                            if item.value and isinstance(item.value, ast.Call):
                                call_tup = self._extract_call_tuple(item.value)
                                if call_tup and call_tup[-1] == "Column":
                                    rule_def = get_rule_definition("SQL-017")
                                    doc_url = (
                                        rule_def.doc_url
                                        if rule_def
                                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-017"
                                    )
                                    diagnostics.append(
                                        Diagnostic(
                                            id="SQL-017",
                                            severity=Severity.WARNING,
                                            category="framework",
                                            title="Mapped[...] attribute missing mapped_column() in 2.0 Declarative Model",
                                            message=f"Attribute on line {item.lineno} uses 'Mapped[...]' with legacy 'Column()'. Use SQLAlchemy 2.0 'mapped_column()'.",
                                            evidence=[
                                                Evidence(
                                                    fact=f"Mapped[...] assigned with Column() on line {item.lineno}.",
                                                    source=file_path,
                                                )
                                            ],
                                            suggestions=[
                                                Suggestion(
                                                    description="Replace 'Column()' with 'mapped_column()'.",
                                                    code_snippet="id: Mapped[int] = mapped_column(primary_key=True)",
                                                )
                                            ],
                                            file=file_path,
                                            line=item.lineno,
                                            doc_url=doc_url,
                                        )
                                    )

                # Inspect Column / mapped_column / relationship calls
                calls_to_inspect: list[tuple[ast.Call, int]] = []
                if isinstance(item, ast.Assign) and isinstance(item.value, ast.Call):
                    calls_to_inspect.append((item.value, item.lineno))
                elif isinstance(item, ast.AnnAssign) and isinstance(item.value, ast.Call):
                    calls_to_inspect.append((item.value, item.lineno))

                for call_node, call_lineno in calls_to_inspect:
                    call_tup = self._extract_call_tuple(call_node)
                    if not call_tup:
                        continue

                    # Check Column / mapped_column definitions
                    if call_tup[-1] in ("Column", "mapped_column", "Field"):
                        has_columns = True

                        # Check primary_key
                        if any(
                            kw.arg == "primary_key"
                            and isinstance(kw.value, ast.Constant)
                            and kw.value.value is True
                            for kw in call_node.keywords
                        ):
                            has_primary_key = True

                        # SQL-022: Large binary or heavy blob column without deferred()
                        for arg in call_node.args:
                            if isinstance(arg, ast.Name) and arg.id in (
                                "LargeBinary",
                                "BLOB",
                                "BYTEA",
                            ):
                                rule_def = get_rule_definition("SQL-022")
                                doc_url = (
                                    rule_def.doc_url
                                    if rule_def
                                    else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-022"
                                )
                                diagnostics.append(
                                    Diagnostic(
                                        id="SQL-022",
                                        severity=Severity.INFO,
                                        category="framework",
                                        title="Large binary or heavy text column without deferred/load_only strategy",
                                        message=f"Column on line {call_lineno} uses '{arg.id}' without deferred() loading.",
                                        evidence=[
                                            Evidence(
                                                fact=f"{arg.id} column declared on line {call_lineno}.",
                                                source=file_path,
                                            )
                                        ],
                                        suggestions=[
                                            Suggestion(
                                                description="Wrap column in 'deferred()' to prevent loading heavy binary data on all queries.",
                                                code_snippet=f"data = deferred(Column({arg.id}))",
                                            )
                                        ],
                                        file=file_path,
                                        line=call_lineno,
                                        doc_url=doc_url,
                                    )
                                )

                        # SQL-023: ForeignKey without index=True
                        has_fk = False
                        for arg in call_node.args:
                            if isinstance(arg, ast.Call):
                                fk_tup = self._extract_call_tuple(arg)
                                if fk_tup and fk_tup[-1] == "ForeignKey":
                                    has_fk = True

                        if has_fk:
                            has_index = any(
                                kw.arg in ("index", "primary_key", "unique")
                                and isinstance(kw.value, ast.Constant)
                                and kw.value.value is True
                                for kw in call_node.keywords
                            )
                            if not has_index:
                                rule_def = get_rule_definition("SQL-023")
                                doc_url = (
                                    rule_def.doc_url
                                    if rule_def
                                    else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-023"
                                )
                                diagnostics.append(
                                    Diagnostic(
                                        id="SQL-023",
                                        severity=Severity.WARNING,
                                        category="framework",
                                        title="ForeignKey column defined without index=True",
                                        message=f"ForeignKey column on line {call_lineno} is defined without 'index=True', causing sequential scans on joins.",
                                        evidence=[
                                            Evidence(
                                                fact=f"ForeignKey without index=True on line {call_lineno}.",
                                                source=file_path,
                                            )
                                        ],
                                        suggestions=[
                                            Suggestion(
                                                description="Add 'index=True' to ForeignKey columns.",
                                                code_snippet="parent_id = Column(Integer, ForeignKey('parents.id'), index=True)",
                                            )
                                        ],
                                        file=file_path,
                                        line=call_lineno,
                                        doc_url=doc_url,
                                    )
                                )

                    # SQL-012: Relationship cascade delete
                    if call_tup[-1] == "relationship":
                        for kw in call_node.keywords:
                            if (
                                kw.arg == "cascade"
                                and isinstance(kw.value, ast.Constant)
                                and isinstance(kw.value.value, str)
                            ):
                                if "delete" in kw.value.value:
                                    has_cascade_delete = True
                                    cascade_lineno = call_lineno

                    if call_tup[-1] in ("ForeignKey", "Column"):
                        for kw in call_node.keywords:
                            if (
                                kw.arg == "ondelete"
                                and isinstance(kw.value, ast.Constant)
                                and isinstance(kw.value.value, str)
                            ):
                                if "CASCADE" in kw.value.value.upper():
                                    has_fk_cascade = True

            # If not abstract class, check table name & primary key
            if not is_abstract and has_columns:
                # SQL-029: Missing __tablename__
                if not has_table_name:
                    rule_def = get_rule_definition("SQL-029")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-029"
                    )
                    diagnostics.append(
                        Diagnostic(
                            id="SQL-029",
                            severity=Severity.ERROR,
                            category="framework",
                            title="Declarative ORM model missing __tablename__ definition",
                            message=f"Declarative model '{node.name}' on line {node.lineno} does not define '__tablename__'.",
                            evidence=[
                                Evidence(
                                    fact=f"ORM class {node.name} without __tablename__ on line {node.lineno}.",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description="Define '__tablename__ = \"...\"' on concrete model.",
                                    code_snippet=f'class {node.name}(Base):\n    __tablename__ = "{node.name.lower()}s"',
                                )
                            ],
                            file=file_path,
                            line=node.lineno,
                            doc_url=doc_url,
                        )
                    )

                # SQL-020: Missing primary key
                if not has_primary_key:
                    rule_def = get_rule_definition("SQL-020")
                    doc_url = (
                        rule_def.doc_url
                        if rule_def
                        else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-020"
                    )
                    diagnostics.append(
                        Diagnostic(
                            id="SQL-020",
                            severity=Severity.ERROR,
                            category="framework",
                            title="Declarative ORM Model missing primary key definition",
                            message=f"Declarative model '{node.name}' on line {node.lineno} does not define a primary key column.",
                            evidence=[
                                Evidence(
                                    fact=f"Model {node.name} without primary_key=True on line {node.lineno}.",
                                    source=file_path,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description="Add 'primary_key=True' to the ID column.",
                                    code_snippet="id: Mapped[int] = mapped_column(primary_key=True)",
                                )
                            ],
                            file=file_path,
                            line=node.lineno,
                            doc_url=doc_url,
                        )
                    )

            # SQL-012: Cascade delete without DB FK ondelete
            if has_cascade_delete and not has_fk_cascade:
                rule_def = get_rule_definition("SQL-012")
                doc_url = (
                    rule_def.doc_url
                    if rule_def
                    else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-012"
                )
                diagnostics.append(
                    Diagnostic(
                        id="SQL-012",
                        severity=Severity.INFO,
                        category="framework",
                        title="Relationship cascade delete without ForeignKey ondelete CASCADE",
                        message=f"Model '{node.name}' defines relationship cascade delete on line {cascade_lineno} without database-level ForeignKey ondelete='CASCADE'.",
                        evidence=[
                            Evidence(
                                fact=f"cascade='all, delete-orphan' without ForeignKey ondelete='CASCADE' in {node.name}.",
                                source=file_path,
                            )
                        ],
                        suggestions=[
                            Suggestion(
                                description="Add 'ondelete=\"CASCADE\"' to ForeignKey and 'passive_deletes=True' to relationship for fast DB-level cascade deletion.",
                                code_snippet="ForeignKey('parent.id', ondelete='CASCADE')",
                            )
                        ],
                        file=file_path,
                        line=cascade_lineno,
                        column=getattr(node, "col_offset", None),
                        doc_url=doc_url,
                    )
                )

        return diagnostics

    def _check_alembic_setup(self, context: ProjectContext) -> list[Diagnostic]:
        """Check for SQL-016: Missing database migration configuration (Alembic)."""
        diagnostics: list[Diagnostic] = []
        has_alembic = False

        for sf in context.source_files:
            rel_str = str(sf.relative_path).replace("\\", "/")
            if "alembic" in rel_str.lower() or "alembic.ini" in rel_str.lower():
                has_alembic = True
                break

        if not has_alembic:
            rule_def = get_rule_definition("SQL-016")
            doc_url = (
                rule_def.doc_url
                if rule_def
                else "https://github.com/inzamol/qv/blob/main/docs/rules.md#sql-016"
            )
            diagnostics.append(
                Diagnostic(
                    id="SQL-016",
                    severity=Severity.INFO,
                    category="framework",
                    title="Missing database migration configuration (Alembic)",
                    message="SQLAlchemy ORM models detected in project, but no Alembic migrations directory or alembic.ini configuration was found.",
                    evidence=[
                        Evidence(
                            fact="SQLAlchemy models defined without alembic.ini in project root.",
                            source="project",
                        )
                    ],
                    suggestions=[
                        Suggestion(
                            description="Initialize database migrations with Alembic.",
                            code_snippet="alembic init alembic",
                        )
                    ],
                    file="alembic.ini",
                    line=1,
                    doc_url=doc_url,
                )
            )

        return diagnostics
