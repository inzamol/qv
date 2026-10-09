"""Dependency Risk Graph Visualizer.

Correlates declared dependencies, installed distributions, source AST imports,
package classifications (framework, driver, library, tooling), and diagnostic
risk levels into an annotated dependency tree.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from rich.tree import Tree

from qv.analyzers.dependencies.analyzer import KNOWN_IMPORT_TO_PKG, STDLIB_MODULES
from qv.core.context import ProjectContext
from qv.core.models import Diagnostic, Severity


class DependencyRole(str, Enum):
    """Categorization of a dependency's role in the ecosystem."""

    FRAMEWORK = "framework"
    RUNTIME_DRIVER = "runtime_driver"
    DEV_TOOLING = "dev_tooling"
    LIBRARY = "library"


class RiskLevel(str, Enum):
    """Diagnostic risk assessment level for a dependency."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    HEALTHY = "healthy"


# Known classifications
FRAMEWORK_PACKAGES = {
    "fastapi",
    "django",
    "flask",
    "celery",
    "sqlalchemy",
    "tornado",
    "pyramid",
    "litestar",
    "starlette",
    "aiohttp",
    "sanic",
    "falcon",
    "dash",
    "streamlit",
}

RUNTIME_DRIVER_PACKAGES = {
    "amqp",
    "kombu",
    "asyncpg",
    "psycopg2",
    "psycopg2-binary",
    "psycopg",
    "aiomysql",
    "pymysql",
    "redis",
    "uvicorn",
    "gunicorn",
    "hypercorn",
    "daphne",
    "cryptography",
    "python-dotenv",
    "greenlet",
    "gevent",
    "eventlet",
    "boto3",
    "botocore",
    "grpcio",
    "protobuf",
}

DEV_TOOLING_PACKAGES = {
    "pytest",
    "pytest-cov",
    "pytest-asyncio",
    "ruff",
    "mypy",
    "pyright",
    "black",
    "isort",
    "flake8",
    "coverage",
    "tox",
    "nox",
    "pre-commit",
    "setuptools",
    "wheel",
    "build",
    "hatchling",
    "flit",
}


@dataclass
class DependencyNodeInfo:
    """Rich metadata and risk assessment for a single package node."""

    name: str
    canonical_name: str
    version: str | None = None
    specifier: str = ""
    is_direct: bool = False
    is_dev: bool = False
    is_imported: bool = False
    import_locations: list[str] = field(default_factory=list)
    role: DependencyRole = DependencyRole.LIBRARY
    risk_level: RiskLevel = RiskLevel.HEALTHY
    diagnostics: list[Diagnostic] = field(default_factory=list)
    risk_reasons: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    parent_chains: list[str] = field(default_factory=list)


class DependencyRiskGraph:
    """Constructs annotated dependency risk trees and structured models."""

    def __init__(
        self,
        context: ProjectContext,
        diagnostics: list[Diagnostic] | None = None,
    ) -> None:
        self.context = context
        self.diagnostics = diagnostics or []
        self._nodes: dict[str, DependencyNodeInfo] = {}
        self._analyze()

    def _analyze(self) -> None:
        """Analyze project dependencies, imports, and risk scores."""
        # 1. Map imported packages from source AST
        imported_pkgs: dict[str, list[str]] = {}
        for imp in self.context.imports:
            if imp.is_relative or not imp.module_name:
                continue
            top_level = imp.module_name.split(".")[0].lower()
            if top_level in STDLIB_MODULES:
                continue
            pkg_name = KNOWN_IMPORT_TO_PKG.get(top_level, top_level)
            canon = canonicalize_name(pkg_name)
            loc = f"{imp.source_file.name}:{imp.line_number}"
            imported_pkgs.setdefault(canon, []).append(loc)

        # 2. Map diagnostics to affected packages
        pkg_diagnostics: dict[str, list[Diagnostic]] = {}
        for diag in self.diagnostics:
            for pkg in diag.affected_packages:
                canon = canonicalize_name(pkg)
                pkg_diagnostics.setdefault(canon, []).append(diag)

        # 3. Process direct dependencies
        direct_canon: set[str] = set()
        for dep in self.context.dependencies:
            canon = canonicalize_name(dep.name)
            direct_canon.add(canon)
            installed = self.context.installed_packages.get(canon)
            version = installed.version if installed else None
            role = self._classify_role(dep.name, dep.is_dev)

            node = DependencyNodeInfo(
                name=dep.name,
                canonical_name=canon,
                version=version,
                specifier=dep.specifier,
                is_direct=True,
                is_dev=dep.is_dev,
                is_imported=canon in imported_pkgs,
                import_locations=imported_pkgs.get(canon, []),
                role=role,
            )
            self._nodes[canon] = node

        # 4. Process all installed packages (including transitive)
        for canon, dist in self.context.installed_packages.items():
            if canon not in self._nodes:
                role = self._classify_role(dist.name, is_dev=False)
                node = DependencyNodeInfo(
                    name=dist.name,
                    canonical_name=canon,
                    version=dist.version,
                    is_direct=False,
                    is_imported=canon in imported_pkgs,
                    import_locations=imported_pkgs.get(canon, []),
                    role=role,
                )
                self._nodes[canon] = node

        # 5. Connect child dependencies and compute risk levels
        for canon, node in self._nodes.items():
            installed = self.context.installed_packages.get(canon)
            if installed and installed.requires:
                for req_str in installed.requires:
                    try:
                        req = Requirement(req_str)
                        if not req.marker:
                            node.dependencies.append(canonicalize_name(req.name))
                    except Exception:
                        pass

            # Attach diagnostics & compute risk
            node.diagnostics = pkg_diagnostics.get(canon, [])
            node.risk_level, node.risk_reasons = self._assess_risk(node)

    def _classify_role(self, name: str, is_dev: bool) -> DependencyRole:
        """Classify the functional role of a package."""
        canon = canonicalize_name(name)
        if is_dev or canon in DEV_TOOLING_PACKAGES:
            return DependencyRole.DEV_TOOLING
        if canon in FRAMEWORK_PACKAGES:
            return DependencyRole.FRAMEWORK
        if canon in RUNTIME_DRIVER_PACKAGES:
            return DependencyRole.RUNTIME_DRIVER
        return DependencyRole.LIBRARY

    def _assess_risk(self, node: DependencyNodeInfo) -> tuple[RiskLevel, list[str]]:
        """Compute the risk level and reasons for a node."""
        reasons: list[str] = []
        highest_risk = RiskLevel.HEALTHY

        risk_scores = {
            RiskLevel.CRITICAL: 4,
            RiskLevel.HIGH: 3,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 1,
            RiskLevel.HEALTHY: 0,
        }

        def _update_risk(level: RiskLevel, reason: str) -> None:
            nonlocal highest_risk
            reasons.append(reason)
            if risk_scores[level] > risk_scores[highest_risk]:
                highest_risk = level

        # 1. Evaluate all diagnostics attached to this package
        if node.diagnostics:
            for diag in node.diagnostics:
                if diag.id == "DEP-006":
                    _update_risk(RiskLevel.CRITICAL, f"Vulnerability advisory: {diag.title}")
                elif diag.id == "DEP-001":
                    _update_risk(RiskLevel.HIGH, "Dependency version constraint conflict")
                elif diag.id == "DEP-002":
                    _update_risk(
                        RiskLevel.MEDIUM, "Imported in code but missing from pyproject.toml"
                    )
                elif diag.id == "DEP-007":
                    _update_risk(
                        RiskLevel.MEDIUM,
                        "Imported in code and provided transitively, but not declared directly",
                    )
                elif diag.id == "DEP-004":
                    _update_risk(RiskLevel.MEDIUM, "Python runtime compatibility mismatch")
                elif diag.id == "DEP-003":
                    _update_risk(
                        RiskLevel.LOW, "Declared dependency with no direct import in source AST"
                    )
                elif diag.severity == Severity.ERROR:
                    _update_risk(RiskLevel.HIGH, f"Finding {diag.id}: {diag.title}")
                elif diag.severity == Severity.WARNING:
                    _update_risk(RiskLevel.MEDIUM, f"Finding {diag.id}: {diag.title}")

        # 2. Check installation and import heuristics when no specific diagnostic exists
        else:
            if node.version is None:
                _update_risk(
                    RiskLevel.HIGH,
                    "Declared in pyproject.toml but not installed in active environment",
                )
            elif not node.is_direct and node.is_imported:
                _update_risk(
                    RiskLevel.MEDIUM,
                    "Imported directly in source code but only declared transitively",
                )
            elif node.is_direct and not node.is_imported and node.role == DependencyRole.LIBRARY:
                _update_risk(
                    RiskLevel.LOW,
                    "Direct dependency without direct import (review for unused/driver)",
                )

        if node.version is None and node.diagnostics:
            _update_risk(
                RiskLevel.HIGH,
                "Declared in pyproject.toml but not installed in active environment",
            )

        if highest_risk == RiskLevel.HEALTHY:
            return RiskLevel.HEALTHY, ["No diagnostic issues found; dependency is healthy"]

        return highest_risk, reasons

    def build_tree(
        self,
        annotate: bool = True,
        risk_filter: str | None = None,
        max_depth: int = 5,
    ) -> Tree:
        """Construct an annotated Rich Tree representing the Dependency Risk Graph."""
        total_direct = len([n for n in self._nodes.values() if n.is_direct])
        total_installed = len(self.context.installed_packages)

        root_tree = Tree(
            f"[bold cyan]🛡️  Dependency Risk Graph: {self.context.project_name}[/bold cyan] "
            f"[dim]({total_direct} direct, {total_installed} total installed packages)[/dim]"
        )

        direct_nodes = [n for n in self._nodes.values() if n.is_direct]
        if not direct_nodes:
            root_tree.add("[dim yellow]No dependencies discovered in project.[/dim yellow]")
            return root_tree

        # Filter by risk level if requested
        target_risk = None
        if risk_filter:
            filter_norm = risk_filter.lower().strip()
            if filter_norm not in ("all", ""):
                target_risk = filter_norm

        prod_nodes = [n for n in direct_nodes if not n.is_dev]
        dev_nodes = [n for n in direct_nodes if n.is_dev]

        if prod_nodes:
            prod_branch = root_tree.add("[bold green]Production Dependencies[/bold green]")
            for node in prod_nodes:
                if target_risk and node.risk_level.value != target_risk:
                    continue
                self._add_tree_node(
                    prod_branch,
                    node,
                    max_depth=max_depth,
                    current_depth=1,
                    ancestors=set(),
                    annotate=annotate,
                )

        if dev_nodes:
            dev_branch = root_tree.add("[bold blue]Dev & Tooling Dependencies[/bold blue]")
            for node in dev_nodes:
                if target_risk and node.risk_level.value != target_risk:
                    continue
                self._add_tree_node(
                    dev_branch,
                    node,
                    max_depth=max_depth,
                    current_depth=1,
                    ancestors=set(),
                    annotate=annotate,
                )

        return root_tree

    def _add_tree_node(
        self,
        parent: Tree,
        node: DependencyNodeInfo,
        max_depth: int,
        current_depth: int,
        ancestors: set[str],
        annotate: bool,
    ) -> None:
        """Attach a dependency node and its transitive children."""
        canon = node.canonical_name
        if canon in ancestors:
            parent.add(f"[bold red]↺ {node.name}[/bold red] [dim](circular dependency)[/dim]")
            return

        # Format risk badge
        badge_style = {
            RiskLevel.CRITICAL: "[bold red]CRITICAL RISK[/bold red]",
            RiskLevel.HIGH: "[bold red]HIGH RISK[/bold red]",
            RiskLevel.MEDIUM: "[bold yellow]MEDIUM RISK[/bold yellow]",
            RiskLevel.LOW: "[dim yellow]INFORMATIONAL[/dim yellow]",
            RiskLevel.HEALTHY: "[green]HEALTHY[/green]",
        }.get(node.risk_level, "[green]HEALTHY[/green]")

        ver_str = f" [cyan]v{node.version}[/cyan]" if node.version else " [red](uninstalled)[/red]"
        spec_str = f" [dim]({node.specifier})[/dim]" if node.specifier else ""
        label = f"[bold white]{node.name}[/bold white]{ver_str}{spec_str}  {badge_style}"

        child_branch = parent.add(label)

        if annotate:
            # Annotations block
            dep_type_str = "Direct dependency" if node.is_direct else "Transitive dependency"
            import_str = (
                f"[green]Directly imported ({len(node.import_locations)} files)[/green]"
                if node.is_imported
                else "[dim]No direct AST import found[/dim]"
            )
            role_label = {
                DependencyRole.FRAMEWORK: "Framework core",
                DependencyRole.RUNTIME_DRIVER: "Runtime driver / message broker / database adapter",
                DependencyRole.DEV_TOOLING: "Dev / Testing / Linter tooling",
                DependencyRole.LIBRARY: "Application library",
            }.get(node.role, "Library")

            child_branch.add(f"[dim]Type:[/dim] {dep_type_str}")
            child_branch.add(f"[dim]Import:[/dim] {import_str}")
            child_branch.add(f"[dim]Role:[/dim] [cyan]{role_label}[/cyan]")
            if node.risk_reasons:
                reason_str = "; ".join(node.risk_reasons)
                child_branch.add(f"[dim]Assessment:[/dim] [yellow]{reason_str}[/yellow]")

        if current_depth < max_depth:
            new_ancestors = ancestors | {canon}
            for dep_canon in node.dependencies:
                dep_node = self._nodes.get(dep_canon)
                if dep_node:
                    self._add_tree_node(
                        child_branch,
                        dep_node,
                        max_depth=max_depth,
                        current_depth=current_depth + 1,
                        ancestors=new_ancestors,
                        annotate=annotate,
                    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize dependency risk graph to dictionary."""
        return {
            "project_name": self.context.project_name,
            "project_root": str(self.context.project_root),
            "total_dependencies": len(self._nodes),
            "direct_count": len([n for n in self._nodes.values() if n.is_direct]),
            "installed_count": len(self.context.installed_packages),
            "nodes": [
                {
                    "name": n.name,
                    "canonical_name": n.canonical_name,
                    "version": n.version,
                    "specifier": n.specifier,
                    "is_direct": n.is_direct,
                    "is_dev": n.is_dev,
                    "is_imported": n.is_imported,
                    "import_locations": n.import_locations,
                    "role": n.role.value,
                    "risk_level": n.risk_level.value,
                    "risk_reasons": n.risk_reasons,
                    "dependencies": n.dependencies,
                }
                for n in self._nodes.values()
            ],
        }
