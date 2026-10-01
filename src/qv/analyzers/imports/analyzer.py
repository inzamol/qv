"""Import and Architecture analyzer implementing IMP-001 and IMP-002."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from qv.core.context import ProjectContext
from qv.core.models import Diagnostic, Evidence, Severity, Suggestion
from qv.rules.registry import get_rule_definition

DEPRECATED_STDLIB_REGISTRY: dict[str, dict[str, Any]] = {
    "distutils": {
        "deprecated": (3, 10),
        "removed": (3, 12),
        "replacement": "Use 'setuptools', 'packaging', or 'sysconfig' instead of 'distutils'.",
    },
    "imp": {
        "deprecated": (3, 4),
        "removed": (3, 12),
        "replacement": "Use 'importlib' instead of deprecated 'imp'.",
    },
    "cgi": {
        "deprecated": (3, 11),
        "removed": (3, 13),
        "replacement": "Use 'urllib.parse', 'multipart', or 'email.message' instead of 'cgi'.",
    },
    "pipes": {
        "deprecated": (3, 11),
        "removed": (3, 13),
        "replacement": "Use 'subprocess' instead of 'pipes'.",
    },
    "asyncore": {
        "deprecated": (3, 6),
        "removed": (3, 12),
        "replacement": "Use 'asyncio' instead of 'asyncore'.",
    },
    "asynchat": {
        "deprecated": (3, 6),
        "removed": (3, 12),
        "replacement": "Use 'asyncio' instead of 'asynchat'.",
    },
    "smtpd": {
        "deprecated": (3, 6),
        "removed": (3, 12),
        "replacement": "Use 'aiosmtpd' instead of 'smtpd'.",
    },
    "crypt": {
        "deprecated": (3, 11),
        "removed": (3, 13),
        "replacement": "Use 'hashlib', 'bcrypt', or 'passlib' instead of 'crypt'.",
    },
    "chunk": {
        "deprecated": (3, 11),
        "removed": (3, 13),
        "replacement": "Replace 'chunk' with custom binary stream parsing.",
    },
    "telnetlib": {
        "deprecated": (3, 11),
        "removed": (3, 13),
        "replacement": "Use 'telnetlib3' or third-party async telnet client.",
    },
    "mailcap": {
        "deprecated": (3, 11),
        "removed": (3, 13),
        "replacement": "Use 'mimetypes' instead of 'mailcap'.",
    },
    "nntplib": {
        "deprecated": (3, 11),
        "removed": (3, 13),
        "replacement": "Use a third-party NNTP client library.",
    },
    "audioop": {
        "deprecated": (3, 11),
        "removed": (3, 13),
        "replacement": "Use 'wave', 'scipy.io.wavfile', or 'pydub' instead of 'audioop'.",
    },
}


class ImportAnalyzer:
    """Analyzes import graphs for circular dependencies, unresolved local imports, dead modules, and stdlib deprecations."""

    id = "imports"
    name = "Import & Architecture Analyzer"
    description = (
        "Detects circular imports, unresolved internal modules, dead code, and deprecated stdlibs."
    )

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        diagnostics: list[Diagnostic] = []

        diagnostics.extend(self._check_circular_imports(context))
        diagnostics.extend(self._check_unresolved_local_imports(context))
        diagnostics.extend(self._check_dead_modules(context))
        diagnostics.extend(self._check_deprecated_stdlib(context))

        return diagnostics

    def _check_circular_imports(self, context: ProjectContext) -> list[Diagnostic]:
        """IMP-001: Detect cycles in local import graph."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("IMP-001")
        if not rule or not context.source_files:
            return diagnostics

        # Build module mapping
        module_to_file: dict[str, str] = {}
        file_to_module: dict[str, str] = {}
        for sf in context.source_files:
            module_to_file[sf.module_name] = str(sf.relative_path)
            file_to_module[str(sf.path)] = sf.module_name

        # Build graph
        graph: dict[str, set[str]] = defaultdict(set)
        for imp in context.imports:
            src_mod = file_to_module.get(str(imp.source_file))
            if not src_mod:
                continue

            target_mod = imp.module_name
            # If target module is in project
            if target_mod in module_to_file and target_mod != src_mod:
                graph[src_mod].add(target_mod)

        # Detect cycles using DFS
        visited: set[str] = set()
        recursion_stack: list[str] = []
        detected_cycles: list[list[str]] = []

        def dfs(node: str) -> None:
            visited.add(node)
            recursion_stack.append(node)

            for neighbor in graph.get(node, []):
                if neighbor not in visited:
                    dfs(neighbor)
                elif neighbor in recursion_stack:
                    # Cycle found
                    idx = recursion_stack.index(neighbor)
                    cycle = recursion_stack[idx:] + [neighbor]
                    detected_cycles.append(cycle)

            recursion_stack.pop()

        for mod in list(graph.keys()):
            if mod not in visited:
                dfs(mod)

        # Format diagnostics for cycles
        seen_cycle_sets = set()
        for cycle in detected_cycles:
            cycle_key = tuple(sorted(set(cycle)))
            if cycle_key in seen_cycle_sets:
                continue
            seen_cycle_sets.add(cycle_key)

            cycle_str = " -> ".join(cycle)
            primary_mod = cycle[0]
            rel_file = module_to_file.get(primary_mod, primary_mod)

            diagnostics.append(
                Diagnostic(
                    id=rule.id,
                    severity=rule.default_severity,
                    category=rule.category,
                    title="Circular import detected",
                    message=f"Circular import cycle detected: {cycle_str}",
                    evidence=[
                        Evidence(
                            fact=f"Import chain: {cycle_str}",
                            source=rel_file,
                        )
                    ],
                    suggestions=[
                        Suggestion(
                            description=f"Break the cycle between {cycle[0]} and {cycle[1]} by refactoring shared logic into a separate module or using deferred imports inside functions.",
                        )
                    ],
                    file=rel_file,
                    doc_url=rule.doc_url,
                )
            )

        return diagnostics

    def _check_unresolved_local_imports(self, context: ProjectContext) -> list[Diagnostic]:
        """IMP-002: Detect local imports that cannot be resolved to any project source file."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("IMP-002")
        if not rule or not context.source_files:
            return diagnostics

        known_modules = {sf.module_name for sf in context.source_files}

        for imp in context.imports:
            if not imp.module_name:
                continue

            # If it's a relative import or clearly aiming at a known root
            if imp.is_relative:
                rel_path = (
                    imp.source_file.relative_to(context.project_root)
                    if imp.source_file.is_relative_to(context.project_root)
                    else imp.source_file
                )
                # If relative and target module is empty or not in known modules
                if imp.module_name and imp.module_name not in known_modules:
                    diagnostics.append(
                        Diagnostic(
                            id=rule.id,
                            severity=rule.default_severity,
                            category=rule.category,
                            title=f"Unresolved relative import: {imp.module_name}",
                            message=f"Module '{imp.module_name}' imported at {rel_path}:{imp.line_number} could not be resolved.",
                            evidence=[
                                Evidence(
                                    fact=f"Relative import statement at {rel_path}:{imp.line_number}",
                                    source=str(rel_path),
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description=f"Verify target file exists or correct relative import path in {rel_path}.",
                                )
                            ],
                            file=str(rel_path),
                            line=imp.line_number,
                            doc_url=rule.doc_url,
                        )
                    )

        return diagnostics

    def _check_dead_modules(self, context: ProjectContext) -> list[Diagnostic]:
        """IMP-003: Detect orphan local source modules never imported or referenced."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("IMP-003")
        if not rule or not context.source_files:
            return diagnostics

        imported_module_names: set[str] = set()
        for imp in context.imports:
            if imp.module_name:
                imported_module_names.add(imp.module_name)
                clean_name = (
                    imp.module_name[4:] if imp.module_name.startswith("src.") else imp.module_name
                )
                imported_module_names.add(clean_name)
                parts = imp.module_name.split(".")
                for i in range(1, len(parts) + 1):
                    sub = ".".join(parts[:i])
                    imported_module_names.add(sub)
                    if sub.startswith("src."):
                        imported_module_names.add(sub[4:])
            if imp.imported_symbols:
                for sym in imp.imported_symbols:
                    if imp.module_name:
                        imported_module_names.add(f"{imp.module_name}.{sym}")
                        if imp.module_name.startswith("src."):
                            imported_module_names.add(f"{imp.module_name[4:]}.{sym}")

        entrypoint_names = {
            "__init__",
            "__main__",
            "main",
            "app",
            "cli",
            "conftest",
            "wsgi",
            "asgi",
            "server",
            "setup",
        }

        for sf in context.source_files:
            rel_str = str(sf.relative_path).replace("\\", "/")
            stem = sf.path.stem

            if "test" in rel_str.lower() or stem.startswith("test_") or stem.endswith("_test"):
                continue

            if sf.is_init or stem in entrypoint_names or "__main__" in sf.content:
                continue

            clean_sf_mod = (
                sf.module_name[4:] if sf.module_name.startswith("src.") else sf.module_name
            )
            if (
                sf.module_name not in imported_module_names
                and clean_sf_mod not in imported_module_names
                and stem not in imported_module_names
            ):
                diagnostics.append(
                    Diagnostic(
                        id=rule.id,
                        severity=rule.default_severity,
                        category=rule.category,
                        title=f"Unused / orphan local module: {sf.module_name}",
                        message=f"Module '{sf.module_name}' ({rel_str}) is not imported by any other module in the project.",
                        evidence=[
                            Evidence(
                                fact=f"Source file {rel_str} exists but no import statements target '{sf.module_name}'",
                                source=rel_str,
                            )
                        ],
                        suggestions=[
                            Suggestion(
                                description=f"Review if {rel_str} is obsolete and can be deleted, or export/import it where needed.",
                                is_safe=False,
                            )
                        ],
                        file=rel_str,
                        doc_url=rule.doc_url,
                    )
                )

        return diagnostics

    def _check_deprecated_stdlib(self, context: ProjectContext) -> list[Diagnostic]:
        """IMP-004: Detect deprecated or removed standard library modules (PEP 594)."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("IMP-004")
        if not rule or not context.imports:
            return diagnostics

        py_version = (context.python_runtime.major, context.python_runtime.minor)

        for imp in context.imports:
            top_level = imp.module_name.split(".")[0]
            dep_info = DEPRECATED_STDLIB_REGISTRY.get(top_level)
            if not dep_info:
                continue

            rel_path = (
                imp.source_file.relative_to(context.project_root)
                if imp.source_file.is_relative_to(context.project_root)
                else imp.source_file
            )

            removed_ver = dep_info["removed"]
            is_removed = py_version >= removed_ver
            sev = Severity.ERROR if is_removed else Severity.WARNING
            status_text = (
                f"removed in Python {removed_ver[0]}.{removed_ver[1]}"
                if is_removed
                else f"deprecated in Python {dep_info['deprecated'][0]}.{dep_info['deprecated'][1]} and will be removed in Python {removed_ver[0]}.{removed_ver[1]}"
            )

            diagnostics.append(
                Diagnostic(
                    id=rule.id,
                    severity=sev,
                    category=rule.category,
                    title=f"Deprecated/removed stdlib module: {top_level}",
                    message=f"Standard library module '{top_level}' was {status_text}. Active runtime is {context.python_runtime.version_str}.",
                    evidence=[
                        Evidence(
                            fact=f"Imported '{top_level}' at {rel_path}:{imp.line_number}",
                            source=str(rel_path),
                        )
                    ],
                    suggestions=[
                        Suggestion(
                            description=dep_info["replacement"],
                            is_safe=False,
                        )
                    ],
                    file=str(rel_path),
                    line=imp.line_number,
                    doc_url=rule.doc_url,
                )
            )

        return diagnostics
