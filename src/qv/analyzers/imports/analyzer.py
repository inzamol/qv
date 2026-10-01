"""Import and Architecture analyzer implementing IMP-001 and IMP-002."""

from __future__ import annotations

from collections import defaultdict

from qv.core.context import ProjectContext
from qv.core.models import Diagnostic, Evidence, Suggestion
from qv.rules.registry import get_rule_definition


class ImportAnalyzer:
    """Analyzes import graphs for circular dependencies and unresolved local imports."""

    id = "imports"
    name = "Import & Architecture Analyzer"
    description = "Detects circular imports and unresolved internal modules."

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        diagnostics: list[Diagnostic] = []

        diagnostics.extend(self._check_circular_imports(context))
        diagnostics.extend(self._check_unresolved_local_imports(context))

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
