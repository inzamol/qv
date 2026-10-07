"""Architecture Map and Component Graph Visualizer.

Discovers architectural layers and components, builds module/layer dependency graphs,
detects circular component dependencies and layer violations, and renders rich terminal
flowcharts, Mermaid diagrams, Graphviz DOT, and structured JSON.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from qv.core.context import ProjectContext
from qv.core.models import Diagnostic, Severity


class LayerRole(str, Enum):
    """Standardized architectural role for a component/layer."""

    PRESENTATION = "Presentation / API"
    APPLICATION = "Application / Services"
    DOMAIN = "Domain / Business"
    DATA_ACCESS = "Data Access / Repository"
    PERSISTENCE = "Database / Persistence"
    INFRASTRUCTURE = "Infrastructure / Core"
    UTILITY = "Utility / Common"
    CUSTOM = "Custom Component"


# Standard classification mapping keywords to layer roles and default ordering level (1 = top)
ROLE_CLASSIFICATION: dict[str, tuple[LayerRole, int, str]] = {
    # Presentation / Top level (Level 1)
    "api": (LayerRole.PRESENTATION, 1, "API"),
    "routes": (LayerRole.PRESENTATION, 1, "Routes"),
    "routers": (LayerRole.PRESENTATION, 1, "Routers"),
    "controllers": (LayerRole.PRESENTATION, 1, "Controllers"),
    "endpoints": (LayerRole.PRESENTATION, 1, "Endpoints"),
    "views": (LayerRole.PRESENTATION, 1, "Views"),
    "cli": (LayerRole.PRESENTATION, 1, "CLI"),
    "interfaces": (LayerRole.PRESENTATION, 1, "Interfaces"),
    "web": (LayerRole.PRESENTATION, 1, "Web"),
    "handlers": (LayerRole.PRESENTATION, 1, "Handlers"),
    "presentation": (LayerRole.PRESENTATION, 1, "Presentation"),
    "ui": (LayerRole.PRESENTATION, 1, "UI"),
    # Application / Services (Level 2)
    "services": (LayerRole.APPLICATION, 2, "Services"),
    "service": (LayerRole.APPLICATION, 2, "Services"),
    "use_cases": (LayerRole.APPLICATION, 2, "Use Cases"),
    "usecases": (LayerRole.APPLICATION, 2, "Use Cases"),
    "workflows": (LayerRole.APPLICATION, 2, "Workflows"),
    "application": (LayerRole.APPLICATION, 2, "Application"),
    "business": (LayerRole.APPLICATION, 2, "Business Logic"),
    "interactors": (LayerRole.APPLICATION, 2, "Interactors"),
    "logic": (LayerRole.APPLICATION, 2, "Logic"),
    # Domain / Business Entities (Level 3)
    "domain": (LayerRole.DOMAIN, 3, "Domain"),
    "entities": (LayerRole.DOMAIN, 3, "Entities"),
    "domain_models": (LayerRole.DOMAIN, 3, "Domain Models"),
    # Data Access / Repositories (Level 4)
    "repositories": (LayerRole.DATA_ACCESS, 4, "Repository"),
    "repository": (LayerRole.DATA_ACCESS, 4, "Repository"),
    "repo": (LayerRole.DATA_ACCESS, 4, "Repository"),
    "repos": (LayerRole.DATA_ACCESS, 4, "Repository"),
    "dao": (LayerRole.DATA_ACCESS, 4, "DAO"),
    "crud": (LayerRole.DATA_ACCESS, 4, "CRUD"),
    "adapters": (LayerRole.DATA_ACCESS, 4, "Adapters"),
    "gateways": (LayerRole.DATA_ACCESS, 4, "Gateways"),
    "storage": (LayerRole.DATA_ACCESS, 4, "Storage"),
    # Persistence / Database (Level 5)
    "models": (LayerRole.PERSISTENCE, 5, "Models"),
    "database": (LayerRole.PERSISTENCE, 5, "Database"),
    "db": (LayerRole.PERSISTENCE, 5, "Database"),
    "schemas": (LayerRole.PERSISTENCE, 5, "Schemas"),
    "orm": (LayerRole.PERSISTENCE, 5, "ORM"),
    "persistence": (LayerRole.PERSISTENCE, 5, "Persistence"),
    # Utilities / Infrastructure / Common (Level 99 - cross cutting)
    "utils": (LayerRole.UTILITY, 99, "Utils"),
    "util": (LayerRole.UTILITY, 99, "Utils"),
    "helpers": (LayerRole.UTILITY, 99, "Helpers"),
    "common": (LayerRole.UTILITY, 99, "Common"),
    "shared": (LayerRole.UTILITY, 99, "Shared"),
    "lib": (LayerRole.UTILITY, 99, "Lib"),
    "config": (LayerRole.INFRASTRUCTURE, 99, "Config"),
    "constants": (LayerRole.UTILITY, 99, "Constants"),
    "exceptions": (LayerRole.UTILITY, 99, "Exceptions"),
    "infra": (LayerRole.INFRASTRUCTURE, 99, "Infrastructure"),
    "infrastructure": (LayerRole.INFRASTRUCTURE, 99, "Infrastructure"),
    "core": (LayerRole.INFRASTRUCTURE, 99, "Core"),
}


@dataclass
class ImportReference:
    """Individual source-level import statement between modules."""

    source_file: str
    source_module: str
    target_module: str
    line_number: int
    symbols: list[str] = field(default_factory=list)


@dataclass
class ArchitectureComponent:
    """High-level architectural component or layer grouping source files."""

    slug: str
    name: str
    role: LayerRole
    level: int
    source_files: list[str] = field(default_factory=list)
    module_names: list[str] = field(default_factory=list)
    lines_of_code: int = 0

    @property
    def file_count(self) -> int:
        return len(self.source_files)


@dataclass
class ArchitectureEdge:
    """Directed dependency connection between two components."""

    source: str
    target: str
    import_count: int = 0
    imports: list[ImportReference] = field(default_factory=list)
    is_cycle: bool = False
    is_violation: bool = False
    violation_reason: str | None = None


@dataclass
class ArchitectureViolation:
    """An architectural violation or circular dependency finding."""

    violation_type: str  # "layer_violation" | "circular_dependency"
    title: str
    source_layer: str
    target_layer: str
    description: str
    evidence: list[str] = field(default_factory=list)
    rule_id: str = "ARC-001"
    severity: Severity = Severity.WARNING


class ArchitectureGraph:
    """Constructs the architectural layer model, detects anomalies, and manages graph state."""

    def __init__(
        self,
        context: ProjectContext,
        diagnostics: list[Diagnostic] | None = None,
    ) -> None:
        self.context = context
        self.diagnostics = diagnostics or []
        self.components: dict[str, ArchitectureComponent] = {}
        self.edges: dict[tuple[str, str], ArchitectureEdge] = {}
        self.cycles: list[list[str]] = []
        self.violations: list[ArchitectureViolation] = []
        self._file_to_component: dict[str, str] = {}
        self._module_to_component: dict[str, str] = {}
        self._analyze()

    def _analyze(self) -> None:
        """Execute layer classification, edge discovery, cycle detection, and violation analysis."""
        self._classify_components()
        self._build_dependency_edges()
        self._detect_component_cycles()
        self._detect_layer_violations()

    def _classify_components(self) -> None:
        """Map every source file to an architectural layer or subpackage component."""
        if not self.context.source_files:
            return

        pkg_name = self.context.project_name.lower().replace("-", "_")

        # 1. Map each source file to candidate component
        for sf in self.context.source_files:
            rel_path = str(sf.relative_path).replace("\\", "/")
            parts = [p.lower() for p in sf.relative_path.parts]

            # Skip test files from architectural layer analysis
            if any(p in ("tests", "test", "testing", ".pytest_cache") for p in parts):
                continue
            if sf.path.stem.startswith("test_") or sf.path.stem.endswith("_test"):
                continue

            # Strip 'src' or root package directory if present
            clean_parts = [p for p in parts if p not in ("src", "lib", ".")]

            # Determine primary subpackage/layer directory
            if len(clean_parts) >= 3 and (
                clean_parts[0] == pkg_name
                or clean_parts[0] == "qv"
                or len(self.context.source_files) > 10
            ):
                primary_folder = clean_parts[1]
            elif len(clean_parts) >= 2:
                primary_folder = clean_parts[0]
            else:
                primary_folder = sf.path.stem.lower()

            detected_slug: str = primary_folder
            detected_name: str | None = None
            detected_role = LayerRole.CUSTOM
            detected_level = 50

            # Check if primary folder matches known architectural role
            if primary_folder in ROLE_CLASSIFICATION:
                role, level, name = ROLE_CLASSIFICATION[primary_folder]
                detected_name = name
                detected_role = role
                detected_level = level

            # Register component
            if detected_slug not in self.components:
                self.components[detected_slug] = ArchitectureComponent(
                    slug=detected_slug,
                    name=detected_name or detected_slug.replace("_", " ").title(),
                    role=detected_role,
                    level=detected_level,
                )

            comp = self.components[detected_slug]
            comp.source_files.append(rel_path)
            comp.module_names.append(sf.module_name)
            comp.lines_of_code += len(sf.content.splitlines())

            self._file_to_component[str(sf.path)] = detected_slug
            self._file_to_component[rel_path] = detected_slug
            self._module_to_component[sf.module_name] = detected_slug
            # Also handle unprefixed / prefixed module paths
            if sf.module_name.startswith("src."):
                self._module_to_component[sf.module_name[4:]] = detected_slug
            if "." in sf.module_name:
                top_pkg = sf.module_name.split(".")[0]
                if top_pkg in ("src", pkg_name, "qv"):
                    sub_mod = ".".join(sf.module_name.split(".")[1:])
                    self._module_to_component[sub_mod] = detected_slug

    def _resolve_module_to_component(self, mod_name: str) -> str | None:
        """Find the architectural component for a module name."""
        if mod_name in self._module_to_component:
            return self._module_to_component[mod_name]

        # Check prefix match
        for m, comp in self._module_to_component.items():
            if mod_name == m or mod_name.startswith(f"{m}."):
                return comp

        # Check path parts
        parts = mod_name.lower().split(".")
        for part in parts:
            if part in self.components:
                return part

        return None

    def _build_dependency_edges(self) -> None:
        """Map AST imports into directed component edges."""
        for imp in self.context.imports:
            src_comp = self._file_to_component.get(str(imp.source_file))
            if not src_comp:
                continue

            target_cand = (
                imp.resolved_module
                if (imp.is_relative and imp.resolved_module)
                else imp.module_name
            )
            if not target_cand:
                continue

            target_comp = self._resolve_module_to_component(target_cand)
            if not target_comp or target_comp == src_comp:
                continue

            rel_file = (
                str(imp.source_file.relative_to(self.context.project_root)).replace("\\", "/")
                if imp.source_file.is_relative_to(self.context.project_root)
                else str(imp.source_file).replace("\\", "/")
            )

            edge_key = (src_comp, target_comp)
            if edge_key not in self.edges:
                self.edges[edge_key] = ArchitectureEdge(source=src_comp, target=target_comp)

            edge = self.edges[edge_key]
            edge.import_count += 1
            edge.imports.append(
                ImportReference(
                    source_file=rel_file,
                    source_module=imp.source_file.stem,
                    target_module=target_cand,
                    line_number=imp.line_number,
                    symbols=list(imp.imported_symbols),
                )
            )

    def _detect_component_cycles(self) -> None:
        """Detect circular dependencies between architectural components."""
        adj: dict[str, set[str]] = defaultdict(set)
        for src, tgt in self.edges.keys():
            adj[src].add(tgt)

        visited: set[str] = set()
        stack: list[str] = []
        raw_cycles: list[list[str]] = []

        def dfs(node: str) -> None:
            visited.add(node)
            stack.append(node)
            for neighbor in adj.get(node, []):
                if neighbor not in visited:
                    dfs(neighbor)
                elif neighbor in stack:
                    idx = stack.index(neighbor)
                    raw_cycles.append(stack[idx:] + [neighbor])
            stack.pop()

        for node in list(self.components.keys()):
            if node not in visited:
                dfs(node)

        # Canonicalize cycles
        seen = set()
        for cycle in raw_cycles:
            cycle_key = tuple(sorted(set(cycle)))
            if cycle_key in seen:
                continue
            seen.add(cycle_key)
            self.cycles.append(cycle)

            # Mark edges as cycle
            for i in range(len(cycle) - 1):
                k = (cycle[i], cycle[i + 1])
                if k in self.edges:
                    self.edges[k].is_cycle = True

            cycle_str = " → ".join(cycle)
            src_name = self.components.get(
                cycle[0],
                ArchitectureComponent(
                    slug=cycle[0], name=cycle[0], role=LayerRole.CUSTOM, level=50
                ),
            ).name
            tgt_name = self.components.get(
                cycle[1],
                ArchitectureComponent(
                    slug=cycle[1], name=cycle[1], role=LayerRole.CUSTOM, level=50
                ),
            ).name

            evidence_items: list[str] = []
            for i in range(len(cycle) - 1):
                k = (cycle[i], cycle[i + 1])
                if k in self.edges:
                    sample = self.edges[k].imports[0]
                    sym_info = f":{', '.join(sample.symbols)}" if sample.symbols else ""
                    evidence_items.append(
                        f"{sample.source_file}:{sample.line_number} imports {sample.target_module}{sym_info}"
                    )

            self.violations.append(
                ArchitectureViolation(
                    violation_type="circular_dependency",
                    title="Circular component dependency",
                    source_layer=src_name,
                    target_layer=tgt_name,
                    description=f"Circular dependency cycle detected between architectural components: {cycle_str}",
                    evidence=evidence_items,
                    rule_id="ARC-002",
                    severity=Severity.ERROR,
                )
            )

    def _detect_layer_violations(self) -> None:
        """Detect architectural layer skipping, upward dependencies, and forbidden boundaries."""
        # Check standard layer ordering rules:
        # Presentation (1) -> Application/Services (2) -> Repository/Data Access (4) -> Database/Models (5)
        # 1. Downward layer skipping: e.g. Level 1 (API) directly importing Level 5 (Database) when Level 2 (Services) or Level 4 (Repository) exists.
        has_services = any(c.role == LayerRole.APPLICATION for c in self.components.values())
        has_repo = any(c.role == LayerRole.DATA_ACCESS for c in self.components.values())

        for (src_slug, tgt_slug), edge in self.edges.items():
            src_comp = self.components.get(src_slug)
            tgt_comp = self.components.get(tgt_slug)
            if not src_comp or not tgt_comp:
                continue

            # Case 1: Downward skipping violation (API -> Database directly)
            if (
                src_comp.role == LayerRole.PRESENTATION
                and tgt_comp.role == LayerRole.PERSISTENCE
                and (has_services or has_repo)
            ):
                intermediate = (
                    "Services & Repository"
                    if (has_services and has_repo)
                    else "Services"
                    if has_services
                    else "Repository"
                )
                reason = (
                    f"{src_comp.name} → {tgt_comp.name} directly (bypasses {intermediate} layer)"
                )
                edge.is_violation = True
                edge.violation_reason = reason

                evidence = [
                    f"{imp.source_file}:{imp.line_number} imports {imp.target_module}"
                    + (f" ({', '.join(imp.symbols)})" if imp.symbols else "")
                    for imp in edge.imports[:3]
                ]

                self.violations.append(
                    ArchitectureViolation(
                        violation_type="layer_violation",
                        title="Architecture layer violation",
                        source_layer=src_comp.name,
                        target_layer=tgt_comp.name,
                        description=f"{src_comp.name} directly imports {tgt_comp.name}, bypassing intermediate {intermediate} layers.",
                        evidence=evidence,
                        rule_id="ARC-001",
                        severity=Severity.WARNING,
                    )
                )

            # Case 2: Upward dependency (Lower layer depends on higher layer)
            elif tgt_comp.role == LayerRole.PRESENTATION and src_comp.role in (
                LayerRole.APPLICATION,
                LayerRole.DATA_ACCESS,
                LayerRole.PERSISTENCE,
                LayerRole.UTILITY,
            ):
                reason = f"{src_comp.name} → {tgt_comp.name} (lower layer depends on higher {tgt_comp.name} layer)"
                edge.is_violation = True
                edge.violation_reason = reason

                evidence = [
                    f"{imp.source_file}:{imp.line_number} imports {imp.target_module}"
                    + (f" ({', '.join(imp.symbols)})" if imp.symbols else "")
                    for imp in edge.imports[:3]
                ]

                self.violations.append(
                    ArchitectureViolation(
                        violation_type="layer_violation",
                        title="Inverted layer dependency",
                        source_layer=src_comp.name,
                        target_layer=tgt_comp.name,
                        description=f"{src_comp.name} depends directly on upper layer {tgt_comp.name}, violating inversion of control.",
                        evidence=evidence,
                        rule_id="ARC-001",
                        severity=Severity.WARNING,
                    )
                )

            # Case 3: Persistence/Database importing Application/Services directly
            elif src_comp.role == LayerRole.PERSISTENCE and tgt_comp.role == LayerRole.APPLICATION:
                reason = f"{src_comp.name} → {tgt_comp.name} (database layer depends on business services)"
                edge.is_violation = True
                edge.violation_reason = reason

                evidence = [
                    f"{imp.source_file}:{imp.line_number} imports {imp.target_module}"
                    for imp in edge.imports[:3]
                ]

                self.violations.append(
                    ArchitectureViolation(
                        violation_type="layer_violation",
                        title="Inverted database dependency",
                        source_layer=src_comp.name,
                        target_layer=tgt_comp.name,
                        description=f"{src_comp.name} depends on {tgt_comp.name}, causing tight coupling and cyclic risk.",
                        evidence=evidence,
                        rule_id="ARC-001",
                        severity=Severity.WARNING,
                    )
                )

    def to_dict(self) -> dict[str, Any]:
        """Serialize complete architecture model to structured dictionary."""
        return {
            "project_name": self.context.project_name,
            "project_path": str(self.context.project_root),
            "components": [
                {
                    "slug": c.slug,
                    "name": c.name,
                    "role": c.role.value,
                    "level": c.level,
                    "file_count": c.file_count,
                    "lines_of_code": c.lines_of_code,
                    "files": c.source_files,
                }
                for c in self.components.values()
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "import_count": e.import_count,
                    "is_cycle": e.is_cycle,
                    "is_violation": e.is_violation,
                    "violation_reason": e.violation_reason,
                    "imports": [
                        {
                            "source_file": imp.source_file,
                            "target_module": imp.target_module,
                            "line_number": imp.line_number,
                            "symbols": imp.symbols,
                        }
                        for imp in e.imports
                    ],
                }
                for e in self.edges.values()
            ],
            "cycles": self.cycles,
            "violations": [
                {
                    "violation_type": v.violation_type,
                    "title": v.title,
                    "rule_id": v.rule_id,
                    "severity": v.severity.value,
                    "source_layer": v.source_layer,
                    "target_layer": v.target_layer,
                    "description": v.description,
                    "evidence": v.evidence,
                }
                for v in self.violations
            ],
            "summary": {
                "total_components": len(self.components),
                "total_edges": len(self.edges),
                "total_source_files": len(self.context.source_files),
                "circular_dependencies_count": len(self.cycles),
                "layer_violations_count": len(
                    [v for v in self.violations if v.violation_type == "layer_violation"]
                ),
                "is_healthy": len(self.violations) == 0,
            },
        }

    def to_mermaid(self) -> str:
        """Generate GitHub-compatible Mermaid flowchart of project architecture."""
        lines = ["flowchart TD", '    subgraph ArchitectureMap["Project Architecture Map"]']

        for c in self.components.values():
            node_id = c.slug.replace("-", "_")
            label = f"{c.name} ({c.file_count} files)"
            lines.append(f'        {node_id}["{label}"]')

        lines.append("")

        for (src, tgt), edge in self.edges.items():
            src_id = src.replace("-", "_")
            tgt_id = tgt.replace("-", "_")
            cnt_str = f"|{edge.import_count} imports|" if edge.import_count > 1 else ""

            if edge.is_cycle:
                lines.append(f"        {src_id} -.->|⚠ CYCLE| {tgt_id}")
            elif edge.is_violation:
                lines.append(f"        {src_id} -.->|⚠ VIOLATION| {tgt_id}")
            else:
                lines.append(f"        {src_id} -->{cnt_str} {tgt_id}")

        lines.append("    end")
        return "\n".join(lines)

    def to_dot(self) -> str:
        """Generate Graphviz DOT specification."""
        lines = [
            "digraph ArchitectureMap {",
            "    rankdir=TB;",
            '    node [shape=box, style="rounded,filled", fillcolor="#f8fafc", color="#64748b", fontname="Helvetica"];',
            '    edge [color="#64748b", fontname="Helvetica", fontsize=10];',
        ]

        for c in self.components.values():
            node_id = c.slug.replace("-", "_")
            label = f"{c.name}\\n({c.file_count} files)"
            lines.append(f'    {node_id} [label="{label}"];')

        for (src, tgt), edge in self.edges.items():
            src_id = src.replace("-", "_")
            tgt_id = tgt.replace("-", "_")
            if edge.is_cycle:
                lines.append(
                    f'    {src_id} -> {tgt_id} [color="#ef4444", style=dashed, label="CYCLE", fontcolor="#ef4444"];'
                )
            elif edge.is_violation:
                lines.append(
                    f'    {src_id} -> {tgt_id} [color="#f59e0b", style=dashed, label="VIOLATION", fontcolor="#f59e0b"];'
                )
            else:
                lines.append(f'    {src_id} -> {tgt_id} [label="{edge.import_count}"];')

        lines.append("}")
        return "\n".join(lines)


class ArchitectureVisualizer:
    """Rich visualizer for rendering interactive terminal architecture maps."""

    def __init__(self, graph: ArchitectureGraph, console: Console | None = None) -> None:
        self.graph = graph
        self.console = console or Console()

    def render_ascii_flow(self) -> str:
        """Render beautiful ASCII/Unicode architecture graph flow."""
        components = sorted(
            self.graph.components.values(),
            key=lambda c: (c.level, c.name),
        )

        if not components:
            return "  [dim](No source components found in project)[/dim]\n"

        # Check if project fits classic 4/5-tier layered stack
        api_comp = next((c for c in components if c.role == LayerRole.PRESENTATION), None)
        srv_comp = next((c for c in components if c.role == LayerRole.APPLICATION), None)
        repo_comp = next((c for c in components if c.role == LayerRole.DATA_ACCESS), None)
        db_comp = next((c for c in components if c.role == LayerRole.PERSISTENCE), None)
        util_comp = next(
            (c for c in components if c.role in (LayerRole.UTILITY, LayerRole.INFRASTRUCTURE)), None
        )

        # If standard 3+ tier architecture matched, render the classic visual hierarchy
        if (api_comp or srv_comp) and (repo_comp or db_comp or util_comp):
            return self._render_standard_stack(
                api_comp, srv_comp, repo_comp, db_comp, util_comp, components
            )

        # Otherwise render dynamic hierarchical component layout
        return self._render_generic_flow(components)

    def _render_standard_stack(
        self,
        api: ArchitectureComponent | None,
        srv: ArchitectureComponent | None,
        repo: ArchitectureComponent | None,
        db: ArchitectureComponent | None,
        util: ArchitectureComponent | None,
        all_comps: list[ArchitectureComponent],
    ) -> str:
        """Render canonical clean/layered architecture topology."""
        lines: list[str] = []

        # Top: API / Presentation
        if api:
            label = f"{api.name} ({api.file_count})"
            lines.append("          ┌───────────────────────┐")
            lines.append(f"          │  {label:^19}  │")
            lines.append("          └───────────┬───────────┘")
            lines.append("                      │")
            lines.append("                      ▼")

        # Middle: Services
        if srv:
            label = f"{srv.name} ({srv.file_count})"
            lines.append("          ┌───────────────────────┐")
            lines.append(f"          │  {label:^19}  │")
            if repo and util:
                lines.append("          └─────┬───────────┬─────┘")
                lines.append("                │           │      ")
                lines.append("                ▼           ▼      ")
            elif repo or util:
                lines.append("          └───────────┬───────────┘")
                lines.append("                      │")
                lines.append("                      ▼")
            else:
                lines.append("          └───────────────────────┘")

        # Split level: Repository & Utils side-by-side
        if repo and util:
            r_lbl = f"{repo.name} ({repo.file_count})"
            u_lbl = f"{util.name} ({util.file_count})"
            lines.append("     ┌─────────────┐     ┌─────────────┐")
            lines.append(f"     │ {r_lbl:^11} │     │ {u_lbl:^11} │")
            if db:
                lines.append("     └──────┬──────┘     └─────────────┘")
                lines.append("            │")
                lines.append("            ▼")
            else:
                lines.append("     └─────────────┘     └─────────────┘")
        elif repo:
            r_lbl = f"{repo.name} ({repo.file_count})"
            lines.append("          ┌───────────────────────┐")
            lines.append(f"          │  {r_lbl:^19}  │")
            if db:
                lines.append("          └───────────┬───────────┘")
                lines.append("                      │")
                lines.append("                      ▼")
            else:
                lines.append("          └───────────────────────┘")
        elif util:
            u_lbl = f"{util.name} ({util.file_count})"
            lines.append("          ┌───────────────────────┐")
            lines.append(f"          │  {u_lbl:^19}  │")
            if db:
                lines.append("          └───────────┬───────────┘")
                lines.append("                      │")
                lines.append("                      ▼")
            else:
                lines.append("          └───────────────────────┘")

        # Bottom: Database
        if db:
            d_lbl = f"{db.name} ({db.file_count})"
            lines.append("          ┌───────────────────────┐")
            lines.append(f"          │  {d_lbl:^19}  │")
            lines.append("          └───────────────────────┘")

        # Other leftover custom components
        handled = {c.slug for c in (api, srv, repo, db, util) if c}
        leftover = [c for c in all_comps if c.slug not in handled]
        if leftover:
            lines.append("")
            lines.append("      [dim]Additional Subsystems:[/dim]")
            for c in leftover:
                lines.append(
                    f"      • [cyan]{c.name}[/cyan] ({c.file_count} files, {c.lines_of_code} LOC)"
                )

        return "\n".join(lines)

    def _render_generic_flow(self, components: list[ArchitectureComponent]) -> str:
        """Render arbitrary component dependency topology."""
        lines: list[str] = []

        for i, c in enumerate(components):
            c_edges_out = [e for (s, t), e in self.graph.edges.items() if s == c.slug]
            label = f"{c.name} ({c.file_count} files)"
            status_icon = "✓"
            if any(e.is_cycle for e in c_edges_out):
                status_icon = "⚠ CYCLE"
            elif any(e.is_violation for e in c_edges_out):
                status_icon = "⚠ VIOLATION"

            lines.append("  ┌───────────────────────────────┐")
            lines.append(f"  │  {label:<21} [dim]{status_icon:>6}[/dim] │")
            lines.append("  └───────────────┬───────────────┘")

            if c_edges_out:
                for edge in c_edges_out:
                    target_comp = self.graph.components.get(edge.target)
                    tgt_name = target_comp.name if target_comp else edge.target
                    if edge.is_cycle:
                        lines.append(
                            f"                  ├──► [bold red]↺ {tgt_name}[/bold red] [red](cycle: {edge.import_count} imports)[/red]"
                        )
                    elif edge.is_violation:
                        lines.append(
                            f"                  ├──► [bold yellow]⚠ {tgt_name}[/bold yellow] [yellow](violation: {edge.import_count} imports)[/yellow]"
                        )
                    else:
                        lines.append(
                            f"                  ├──► [cyan]{tgt_name}[/cyan] [dim]({edge.import_count} imports)[/dim]"
                        )
            if i < len(components) - 1:
                lines.append("                  │")

        return "\n".join(lines)

    def build_summary_table(self) -> Table:
        """Build Rich summary table of architectural components and couplings."""
        table = Table(
            title="Architectural Layers & Components",
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            show_lines=False,
        )
        table.add_column("Layer / Component", style="bold white", no_wrap=True)
        table.add_column("Role", style="cyan")
        table.add_column("Files", justify="right", style="white")
        table.add_column("LOC", justify="right", style="dim")
        table.add_column("Depends On", style="yellow")
        table.add_column("Depended By", style="blue")
        table.add_column("Health", justify="center")

        for c in sorted(self.graph.components.values(), key=lambda x: (x.level, x.name)):
            deps_out = [
                self.graph.components[t].name
                for (s, t) in self.graph.edges.keys()
                if s == c.slug and t in self.graph.components
            ]
            deps_in = [
                self.graph.components[s].name
                for (s, t) in self.graph.edges.keys()
                if t == c.slug and s in self.graph.components
            ]

            has_cycle = any(
                e.is_cycle for (s, t), e in self.graph.edges.items() if s == c.slug or t == c.slug
            )
            has_violation = any(
                e.is_violation
                for (s, t), e in self.graph.edges.items()
                if s == c.slug or t == c.slug
            )

            if has_cycle:
                health = "[bold red]✗ Cycle[/bold red]"
            elif has_violation:
                health = "[bold yellow]⚠ Violation[/bold yellow]"
            else:
                health = "[bold green]✓ Clean[/bold green]"

            table.add_row(
                c.name,
                c.role.value,
                str(c.file_count),
                str(c.lines_of_code),
                ", ".join(deps_out) if deps_out else "[dim]—[/dim]",
                ", ".join(deps_in) if deps_in else "[dim]—[/dim]",
                health,
            )

        return table

    def print_graph(self) -> None:
        """Print the complete architecture visualizer to Rich console."""
        self.console.print("\n[bold cyan]qv Architecture Graph & Layer Map[/bold cyan]\n")

        # 1. Flow Diagram
        ascii_art = self.render_ascii_flow()
        flow_panel = Panel(
            ascii_art,
            title="[bold green]Dependency Flow & Layer Hierarchy[/bold green]",
            border_style="cyan",
            padding=(1, 2),
        )
        self.console.print(flow_panel)
        self.console.print()

        # 2. Prominent Findings Callout (Circular Dependencies and Layer Violations)
        if self.graph.violations:
            findings_text = Text()
            for v in self.graph.violations:
                if v.violation_type == "circular_dependency":
                    findings_text.append("⚠ Circular dependency\n", style="bold red")
                    findings_text.append(
                        f"  {v.description.replace('Circular dependency cycle detected between architectural components: ', '')}\n",
                        style="red",
                    )
                    for ev in v.evidence:
                        findings_text.append(f"  • {ev}\n", style="dim red")
                    findings_text.append("\n")
                else:
                    findings_text.append("⚠ Layer violation\n", style="bold yellow")
                    findings_text.append(f"  {v.description}\n", style="yellow")
                    for ev in v.evidence:
                        findings_text.append(f"  • {ev}\n", style="dim yellow")
                    findings_text.append("\n")

            violations_panel = Panel(
                findings_text,
                title="[bold red]Architecture Anomalies & Violations[/bold red]",
                border_style="red" if self.graph.cycles else "yellow",
                padding=(1, 2),
            )
            self.console.print(violations_panel)
            self.console.print()
        else:
            self.console.print(
                "[bold green]✓ No architectural layer violations or circular component dependencies detected.[/bold green]\n"
            )

        # 3. Layer Breakdown Table
        self.console.print(self.build_summary_table())
        self.console.print()
