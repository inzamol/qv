"""Tree visualizer for project dependencies and internal import graphs."""

from __future__ import annotations

from typing import Any

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from rich.tree import Tree

from qv.core.context import ProjectContext


class TreeVisualizer:
    """Constructs Rich Trees and JSON models of dependencies and import architecture."""

    def __init__(self, context: ProjectContext) -> None:
        self.context = context

    def build_dependency_tree(self, max_depth: int = 5) -> Tree:
        """Construct a Rich Tree of direct and transitive project dependencies."""
        root_tree = Tree(
            f"[bold cyan]📦 {self.context.project_name}[/bold cyan] [dim]({len(self.context.dependencies)} direct dependencies)[/dim]"
        )

        if not self.context.dependencies:
            root_tree.add("[dim yellow]No direct dependencies declared.[/dim yellow]")
            return root_tree

        # Group by direct vs dev dependencies
        prod_deps = [d for d in self.context.dependencies if not d.is_dev]
        dev_deps = [d for d in self.context.dependencies if d.is_dev]

        if prod_deps:
            prod_branch = root_tree.add("[bold green]Direct Dependencies[/bold green]")
            for dep in prod_deps:
                self._add_dependency_node(prod_branch, dep.name, dep.specifier, max_depth, 1, set())

        if dev_deps:
            dev_branch = root_tree.add("[bold blue]Dev Dependencies[/bold blue]")
            for dep in dev_deps:
                self._add_dependency_node(dev_branch, dep.name, dep.specifier, max_depth, 1, set())

        return root_tree

    def _add_dependency_node(
        self,
        parent_tree: Tree,
        pkg_name: str,
        specifier: str,
        max_depth: int,
        current_depth: int,
        ancestors: set[str],
    ) -> None:
        """Recursively attach transitive dependency nodes."""
        canon = canonicalize_name(pkg_name)
        installed = self.context.installed_packages.get(canon)

        if canon in ancestors:
            parent_tree.add(f"[bold red]↺ {pkg_name}[/bold red] [dim](recursive dependency)[/dim]")
            return

        if installed:
            ver_label = f"[green]v{installed.version}[/green]"
            spec_label = f"[dim]({specifier})[/dim]" if specifier else ""
            node_label = f"[bold white]{pkg_name}[/bold white] {ver_label} {spec_label}".strip()
            node = parent_tree.add(node_label)

            if current_depth < max_depth and installed.requires:
                new_ancestors = ancestors | {canon}
                for req_str in installed.requires:
                    try:
                        req = Requirement(req_str)
                        # Ignore extra markers if they don't apply
                        if req.marker:
                            continue
                        self._add_dependency_node(
                            node,
                            req.name,
                            str(req.specifier),
                            max_depth,
                            current_depth + 1,
                            new_ancestors,
                        )
                    except Exception:
                        pass
        else:
            spec_label = f" [dim]({specifier})[/dim]" if specifier else ""
            parent_tree.add(
                f"[bold yellow]{pkg_name}[/bold yellow]{spec_label} [red](not installed in env)[/red]"
            )

    def build_import_tree(self, max_depth: int = 5) -> Tree:
        """Construct a Rich Tree of internal module imports and dependency cycles."""
        root_tree = Tree(
            f"[bold cyan]📁 {self.context.project_name}[/bold cyan] [dim]({len(self.context.source_files)} source files)[/dim]"
        )

        if not self.context.source_files:
            root_tree.add("[dim yellow]No Python source files found in project root.[/dim yellow]")
            return root_tree

        # Build lookup tables
        file_to_module: dict[str, str] = {
            str(sf.path): sf.module_name for sf in self.context.source_files
        }
        known_modules: set[str] = {sf.module_name for sf in self.context.source_files}
        known_packages: set[str] = set()
        for mod in known_modules:
            parts = mod.split(".")
            for i in range(1, len(parts)):
                known_packages.add(".".join(parts[:i]))

        # Map each module to its imported modules
        module_imports: dict[str, list[tuple[str, bool, bool]]] = {}
        for sf in self.context.source_files:
            module_imports[sf.module_name] = []

        for imp in self.context.imports:
            src_mod = file_to_module.get(str(imp.source_file))
            if not src_mod:
                continue

            target = (
                imp.resolved_module
                if (imp.is_relative and imp.resolved_module)
                else imp.module_name
            )
            if not target:
                continue

            is_internal = (
                target in known_modules
                or target in known_packages
                or any(m.startswith(f"{target}.") for m in known_modules)
            )
            if not is_internal and not imp.module_name and imp.is_relative:
                for sym in imp.imported_symbols:
                    if f"{target}.{sym}" in known_modules or f"{target}.{sym}" in known_packages:
                        is_internal = True
                        target = f"{target}.{sym}"
                        break

            is_unresolved = imp.is_relative and not is_internal
            module_imports[src_mod].append((target, is_internal, is_unresolved))

        # Root modules (modules not imported by other modules, or entrypoints)
        all_imported_internals = {
            target for imports in module_imports.values() for target, is_int, _ in imports if is_int
        }

        entry_candidates = [
            sf.module_name
            for sf in self.context.source_files
            if sf.module_name not in all_imported_internals
            or sf.module_name in ("main", "app", "cli", "__main__")
        ]

        if not entry_candidates:
            entry_candidates = [sf.module_name for sf in self.context.source_files]

        for mod_name in entry_candidates:
            self._add_import_node(
                root_tree,
                mod_name,
                module_imports,
                max_depth,
                1,
                set(),
            )

        return root_tree

    def _add_import_node(
        self,
        parent_tree: Tree,
        module_name: str,
        module_imports: dict[str, list[tuple[str, bool, bool]]],
        max_depth: int,
        current_depth: int,
        ancestors: set[str],
    ) -> None:
        """Recursively attach import child nodes with cycle detection."""
        if module_name in ancestors:
            parent_tree.add(
                f"[bold red]↺ {module_name}[/bold red] [bold red](circular cycle!)[/bold red]"
            )
            return

        node = parent_tree.add(f"[bold cyan]📄 {module_name}[/bold cyan]")

        if current_depth < max_depth:
            imports = module_imports.get(module_name, [])
            new_ancestors = ancestors | {module_name}

            for target, is_internal, is_unresolved in imports:
                if is_unresolved:
                    node.add(
                        f"[bold red]✗ {target}[/bold red] [red](unresolved local import)[/red]"
                    )
                elif is_internal:
                    self._add_import_node(
                        node,
                        target,
                        module_imports,
                        max_depth,
                        current_depth + 1,
                        new_ancestors,
                    )
                else:
                    node.add(f"[dim]📦 {target}[/dim]")

    def to_dict(self) -> dict[str, Any]:
        """Serialize dependency and import graph data to a structured dictionary."""
        return {
            "project_name": self.context.project_name,
            "project_path": str(self.context.project_root),
            "dependencies": [
                {
                    "name": d.name,
                    "specifier": d.specifier,
                    "is_dev": d.is_dev,
                    "installed_version": self.context.installed_packages.get(
                        canonicalize_name(d.name), None
                    )
                    and self.context.installed_packages[canonicalize_name(d.name)].version,
                }
                for d in self.context.dependencies
            ],
            "source_files_count": len(self.context.source_files),
            "imports_count": len(self.context.imports),
        }
