"""Unit and integration tests for ArchitectureGraph and ArchitectureVisualizer."""

from pathlib import Path

from qv.core.context import (
    CIConfig,
    DockerConfig,
    ImportRecord,
    ProjectContext,
    PythonRuntime,
    SourceFile,
)
from qv.core.models import Severity
from qv.visualizers.architecture import (
    ArchitectureGraph,
    ArchitectureVisualizer,
    LayerRole,
)


def _build_layered_project(tmp_path: Path) -> ProjectContext:
    """Helper to build a 5-tier layered project context with a violation and a cycle."""
    runtime = PythonRuntime("3.12.0", 3, 12, 0)

    api_file = tmp_path / "api" / "users.py"
    srv_file = tmp_path / "services" / "user_service.py"
    repo_file = tmp_path / "repositories" / "user_repo.py"
    db_file = tmp_path / "database" / "models.py"
    util_file = tmp_path / "utils" / "crypto.py"

    api_file.parent.mkdir(parents=True, exist_ok=True)
    srv_file.parent.mkdir(parents=True, exist_ok=True)
    repo_file.parent.mkdir(parents=True, exist_ok=True)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    util_file.parent.mkdir(parents=True, exist_ok=True)

    return ProjectContext(
        project_root=tmp_path,
        project_name="layered-architecture-demo",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(),
        lock_files=(),
        dependencies=(),
        installed_packages={},
        source_files=(
            SourceFile(
                path=api_file,
                relative_path=Path("api/users.py"),
                content="from services.user_service import UserService\nfrom database.models import User",
                module_name="api.users",
            ),
            SourceFile(
                path=srv_file,
                relative_path=Path("services/user_service.py"),
                content="from repositories.user_repo import UserRepository\nfrom utils.crypto import hash_pw",
                module_name="services.user_service",
            ),
            SourceFile(
                path=repo_file,
                relative_path=Path("repositories/user_repo.py"),
                content="from database.models import User",
                module_name="repositories.user_repo",
            ),
            SourceFile(
                path=db_file,
                relative_path=Path("database/models.py"),
                content="class User: pass",
                module_name="database.models",
            ),
            SourceFile(
                path=util_file,
                relative_path=Path("utils/crypto.py"),
                content="from services.user_service import UserService",
                module_name="utils.crypto",
            ),
        ),
        imports=(
            # API -> Services (valid)
            ImportRecord(
                module_name="services.user_service",
                source_file=api_file,
                line_number=1,
                is_relative=False,
                imported_symbols=("UserService",),
            ),
            # API -> Database (violation: downward skip)
            ImportRecord(
                module_name="database.models",
                source_file=api_file,
                line_number=2,
                is_relative=False,
                imported_symbols=("User",),
            ),
            # Services -> Repositories (valid)
            ImportRecord(
                module_name="repositories.user_repo",
                source_file=srv_file,
                line_number=1,
                is_relative=False,
                imported_symbols=("UserRepository",),
            ),
            # Services -> Utils (valid)
            ImportRecord(
                module_name="utils.crypto",
                source_file=srv_file,
                line_number=2,
                is_relative=False,
                imported_symbols=("hash_pw",),
            ),
            # Repositories -> Database (valid)
            ImportRecord(
                module_name="database.models",
                source_file=repo_file,
                line_number=1,
                is_relative=False,
                imported_symbols=("User",),
            ),
            # Utils -> Services (cycle: services -> utils -> services)
            ImportRecord(
                module_name="services.user_service",
                source_file=util_file,
                line_number=1,
                is_relative=False,
                imported_symbols=("UserService",),
            ),
        ),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )


def test_architecture_graph_layer_classification(tmp_path: Path):
    context = _build_layered_project(tmp_path)
    graph = ArchitectureGraph(context=context)

    assert "api" in graph.components
    assert "services" in graph.components
    assert "repositories" in graph.components
    assert "database" in graph.components
    assert "utils" in graph.components

    assert graph.components["api"].role == LayerRole.PRESENTATION
    assert graph.components["services"].role == LayerRole.APPLICATION
    assert graph.components["repositories"].role == LayerRole.DATA_ACCESS
    assert graph.components["database"].role == LayerRole.PERSISTENCE
    assert graph.components["utils"].role == LayerRole.UTILITY


def test_architecture_graph_cycle_and_violation_detection(tmp_path: Path):
    context = _build_layered_project(tmp_path)
    graph = ArchitectureGraph(context=context)

    # Check cycles
    assert len(graph.cycles) >= 1
    cycle_nodes = set(graph.cycles[0])
    assert "services" in cycle_nodes
    assert "utils" in cycle_nodes

    # Check violations
    layer_violations = [v for v in graph.violations if v.violation_type == "layer_violation"]
    assert len(layer_violations) >= 1
    assert layer_violations[0].source_layer == "API"
    assert layer_violations[0].target_layer == "Database"
    assert "bypassing" in layer_violations[0].description


def test_architecture_visualizer_ascii_rendering(tmp_path: Path):
    context = _build_layered_project(tmp_path)
    graph = ArchitectureGraph(context=context)
    visualizer = ArchitectureVisualizer(graph=graph)

    ascii_flow = visualizer.render_ascii_flow()
    assert "API" in ascii_flow
    assert "Services" in ascii_flow
    assert "Repository" in ascii_flow
    assert "Database" in ascii_flow
    assert "Utils" in ascii_flow
    assert "┌" in ascii_flow and "▼" in ascii_flow


def test_architecture_graph_mermaid_export(tmp_path: Path):
    context = _build_layered_project(tmp_path)
    graph = ArchitectureGraph(context=context)

    mermaid_str = graph.to_mermaid()
    assert "flowchart TD" in mermaid_str
    assert "subgraph ArchitectureMap" in mermaid_str
    assert "api" in mermaid_str
    assert "services" in mermaid_str
    assert "⚠ VIOLATION" in mermaid_str
    assert "⚠ CYCLE" in mermaid_str


def test_architecture_graph_dot_export(tmp_path: Path):
    context = _build_layered_project(tmp_path)
    graph = ArchitectureGraph(context=context)

    dot_str = graph.to_dot()
    assert "digraph ArchitectureMap" in dot_str
    assert "api -> services" in dot_str.lower() or "api" in dot_str
    assert "CYCLE" in dot_str
    assert "VIOLATION" in dot_str


def test_architecture_graph_json_serialization(tmp_path: Path):
    context = _build_layered_project(tmp_path)
    graph = ArchitectureGraph(context=context)

    data = graph.to_dict()
    assert data["project_name"] == "layered-architecture-demo"
    assert len(data["components"]) == 5
    assert len(data["edges"]) >= 5
    assert len(data["cycles"]) >= 1
    assert len(data["violations"]) >= 1
    assert data["summary"]["is_healthy"] is False
    assert data["summary"]["circular_dependencies_count"] >= 1
    assert data["summary"]["layer_violations_count"] >= 1


def test_architecture_graph_to_diagnostics(tmp_path: Path):
    context = _build_layered_project(tmp_path)
    graph = ArchitectureGraph(context=context)
    diagnostics = graph.to_diagnostics()

    rule_ids = {d.id for d in diagnostics}
    assert "ARC-001" in rule_ids
    assert "ARC-002" in rule_ids

    arc_001 = next(d for d in diagnostics if d.id == "ARC-001")
    assert arc_001.category == "architecture"
    assert arc_001.severity == Severity.WARNING
    assert arc_001.file is not None
    assert "api/users.py" in str(arc_001.file)
    assert arc_001.line == 2

    arc_002 = next(d for d in diagnostics if d.id == "ARC-002")
    assert arc_002.category == "architecture"
    assert arc_002.severity == Severity.ERROR


def test_flat_layout_many_files_classification(tmp_path: Path):
    runtime = PythonRuntime("3.12.0", 3, 12, 0)
    source_files = []
    # Create 12 files in flat layout with nested subdirectories (> 10 files)
    for i in range(6):
        p1 = tmp_path / "api" / f"v{i}" / f"user_{i}.py"
        p1.parent.mkdir(parents=True, exist_ok=True)
        source_files.append(
            SourceFile(
                path=p1,
                relative_path=p1.relative_to(tmp_path),
                content="def f(): pass",
                module_name=f"api.v{i}.user_{i}",
            )
        )
        p2 = tmp_path / "services" / f"sub_{i}" / f"svc_{i}.py"
        p2.parent.mkdir(parents=True, exist_ok=True)
        source_files.append(
            SourceFile(
                path=p2,
                relative_path=p2.relative_to(tmp_path),
                content="def f(): pass",
                module_name=f"services.sub_{i}.svc_{i}",
            )
        )

    context = ProjectContext(
        project_root=tmp_path,
        project_name="flat-demo",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(),
        lock_files=(),
        dependencies=(),
        installed_packages={},
        source_files=tuple(source_files),
        imports=(),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    graph = ArchitectureGraph(context=context)
    # Must identify "api" and "services" as primary components, not "v0" or "sub_0"
    assert "api" in graph.components
    assert "services" in graph.components
    assert graph.components["api"].role == LayerRole.PRESENTATION
    assert graph.components["services"].role == LayerRole.APPLICATION


def test_resolve_module_third_party_not_matched_to_internal_component(tmp_path: Path):
    runtime = PythonRuntime("3.12.0", 3, 12, 0)
    api_file = tmp_path / "api" / "routes.py"
    core_file = tmp_path / "core" / "engine.py"
    api_file.parent.mkdir(parents=True, exist_ok=True)
    core_file.parent.mkdir(parents=True, exist_ok=True)

    context = ProjectContext(
        project_root=tmp_path,
        project_name="tp-demo",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(),
        lock_files=(),
        dependencies=(),
        installed_packages={},
        source_files=(
            SourceFile(
                path=api_file,
                relative_path=api_file.relative_to(tmp_path),
                content="import requests.api\nfrom click.core import BaseCommand",
                module_name="api.routes",
            ),
            SourceFile(
                path=core_file,
                relative_path=core_file.relative_to(tmp_path),
                content="from sqlalchemy.orm import Session",
                module_name="core.engine",
            ),
        ),
        imports=(
            ImportRecord(
                module_name="requests.api",
                source_file=core_file,
                line_number=1,
                is_relative=False,
                imported_symbols=(),
            ),
            ImportRecord(
                module_name="click.core",
                source_file=api_file,
                line_number=2,
                is_relative=False,
                imported_symbols=("BaseCommand",),
            ),
        ),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    graph = ArchitectureGraph(context=context)
    # Third-party dotted segments must not be resolved to internal components
    assert graph._resolve_module_to_component("requests.api") is None
    assert graph._resolve_module_to_component("click.core") is None
    assert graph._resolve_module_to_component("sqlalchemy.orm") is None
    # No false edges should have been created
    assert len(graph.edges) == 0
