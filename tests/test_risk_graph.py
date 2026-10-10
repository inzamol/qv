import json
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner
from rich.console import Console
from rich.tree import Tree

from qv.cli.main import cli
from qv.core.context import (
    CIConfig,
    DependencyDeclaration,
    DockerConfig,
    ImportRecord,
    InstalledDistribution,
    ProjectContext,
    PythonRuntime,
    SourceFile,
)
from qv.core.models import Diagnostic, Severity
from qv.visualizers.risk_graph import DependencyRiskGraph, DependencyRole, RiskLevel


def _make_context(
    tmp_path: Path,
    dependencies: tuple[DependencyDeclaration, ...] = (),
    installed_packages: dict[str, InstalledDistribution] | None = None,
    source_files: tuple[SourceFile, ...] = (),
    imports: tuple[ImportRecord, ...] = (),
) -> ProjectContext:
    return ProjectContext(
        project_root=tmp_path,
        project_name="test-project",
        python_runtime=PythonRuntime(
            version_str="3.12.0",
            major=3,
            minor=12,
            micro=0,
            is_virtualenv=True,
        ),
        package_manager="pip",
        manifest_files=(tmp_path / "pyproject.toml",),
        lock_files=(),
        dependencies=dependencies,
        installed_packages=installed_packages or {},
        source_files=source_files,
        imports=imports,
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )


def test_dependency_risk_graph_basic(tmp_path: Path):
    """Test basic dependency risk graph creation and role classification."""
    context = _make_context(
        tmp_path=tmp_path,
        dependencies=(
            DependencyDeclaration(
                name="celery",
                specifier=">=5.3.0",
                source_file=tmp_path / "pyproject.toml",
            ),
            DependencyDeclaration(
                name="pytest",
                specifier=">=8.0.0",
                source_file=tmp_path / "pyproject.toml",
                is_dev=True,
            ),
        ),
        installed_packages={
            "celery": InstalledDistribution(
                name="celery",
                version="5.3.6",
                requires=("kombu>=5.3.0",),
            ),
            "kombu": InstalledDistribution(
                name="kombu",
                version="5.3.5",
                requires=("amqp>=5.2.0",),
            ),
            "amqp": InstalledDistribution(
                name="amqp",
                version="5.2.0",
            ),
            "pytest": InstalledDistribution(
                name="pytest",
                version="8.3.0",
            ),
        },
        source_files=(
            SourceFile(
                path=tmp_path / "app.py",
                relative_path=Path("app.py"),
                content="import celery\n",
                module_name="app",
            ),
        ),
        imports=(
            ImportRecord(
                module_name="celery",
                source_file=tmp_path / "app.py",
                line_number=1,
                is_relative=False,
            ),
        ),
    )

    graph = DependencyRiskGraph(context=context)
    tree = graph.build_tree(annotate=True)
    assert tree is not None

    data = graph.to_dict()
    assert data["project_name"] == "test-project"
    assert data["direct_count"] == 2
    assert data["installed_count"] == 4

    nodes_by_name = {n["name"]: n for n in data["nodes"]}
    assert nodes_by_name["celery"]["role"] == DependencyRole.FRAMEWORK.value
    assert nodes_by_name["celery"]["is_direct"] is True
    assert nodes_by_name["celery"]["is_imported"] is True
    assert nodes_by_name["pytest"]["role"] == DependencyRole.DEV_TOOLING.value
    assert nodes_by_name["amqp"]["role"] == DependencyRole.RUNTIME_DRIVER.value


def test_dependency_risk_graph_diagnostics(tmp_path: Path):
    """Test diagnostic correlation with risk levels."""
    context = _make_context(
        tmp_path=tmp_path,
        dependencies=(
            DependencyDeclaration(
                name="requests",
                specifier="==2.11.2",
                source_file=tmp_path / "pyproject.toml",
            ),
        ),
        installed_packages={
            "requests": InstalledDistribution(
                name="requests",
                version="2.11.2",
            ),
        },
    )

    diag = Diagnostic(
        id="DEP-006",
        severity=Severity.ERROR,
        category="security",
        title="Critical CVE in requests",
        message="Vulnerable version detected",
        affected_packages=["requests"],
    )

    graph = DependencyRiskGraph(context=context, diagnostics=[diag])
    data = graph.to_dict()
    req_node = [n for n in data["nodes"] if n["name"] == "requests"][0]
    assert req_node["risk_level"] == RiskLevel.CRITICAL.value
    assert any("Vulnerability" in r for r in req_node["risk_reasons"])


def test_dependency_cli_graph_flag(tmp_path: Path):
    """Test qv dependency --graph and qv tree --risk CLI commands."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "cli-test"
version = "0.1.0"
dependencies = [
    "requests>=2.31.0"
]
""",
        encoding="utf-8",
    )

    runner = CliRunner()
    res = runner.invoke(cli, ["dependency", str(tmp_path), "--graph"])
    assert res.exit_code == 0
    assert "Dependency Risk & Usage Graph" in res.output

    # Test JSON output
    res_json = runner.invoke(cli, ["dependency", str(tmp_path), "--graph", "--json"])
    assert res_json.exit_code == 0
    assert '"project_name": "cli-test"' in res_json.output

    # Test qv tree --risk
    res_tree = runner.invoke(cli, ["tree", str(tmp_path), "--risk"])
    assert res_tree.exit_code == 0
    assert "Dependency Risk & Usage Graph" in res_tree.output


@pytest.fixture
def imported_context(tmp_path: Path) -> ProjectContext:
    """One installed, directly imported library with no baseline risk."""
    return _make_context(
        tmp_path,
        dependencies=(DependencyDeclaration("requests", ">=2", tmp_path / "pyproject.toml"),),
        installed_packages={"requests": InstalledDistribution("requests", "2.31.0")},
        imports=(ImportRecord("requests.sessions", tmp_path / "app.py", 3, False),),
    )


def _diagnostic(rule: str, severity: Severity, *packages: str) -> Diagnostic:
    return Diagnostic(
        id=rule,
        severity=severity,
        category="dependencies",
        title=f"Finding {rule}",
        message="Dependency requires attention",
        affected_packages=list(packages),
    )


def _render(tree: Tree) -> str:
    console = Console(width=240, color_system=None)
    with console.capture() as capture:
        console.print(tree)
    return capture.get()


@pytest.mark.parametrize(
    ("name", "is_dev", "expected"),
    [
        ("FastAPI", False, DependencyRole.FRAMEWORK),
        ("PSYCOPG2_binary", False, DependencyRole.RUNTIME_DRIVER),
        ("pytest.cov", False, DependencyRole.DEV_TOOLING),
        ("requests", False, DependencyRole.LIBRARY),
        ("requests", True, DependencyRole.DEV_TOOLING),
        ("FastAPI", True, DependencyRole.DEV_TOOLING),
    ],
)
def test_role_classification(
    tmp_path: Path, name: str, is_dev: bool, expected: DependencyRole
) -> None:
    context = _make_context(
        tmp_path,
        dependencies=(DependencyDeclaration(name, "", tmp_path / "pyproject.toml", is_dev=is_dev),),
    )
    node = DependencyRiskGraph(context).to_dict()["nodes"][0]
    assert node["role"] == expected.value
    assert node["is_dev"] is is_dev


def test_import_aliases_and_canonical_names_share_one_node(tmp_path: Path) -> None:
    context = _make_context(
        tmp_path,
        dependencies=(
            DependencyDeclaration("Python_DateUtil", ">=2", tmp_path / "pyproject.toml"),
        ),
        installed_packages={"python-dateutil": InstalledDistribution("python-dateutil", "2.9.0")},
        imports=(
            ImportRecord("dateutil.parser", tmp_path / "app.py", 2, False),
            ImportRecord("dateutil.relativedelta", tmp_path / "worker.py", 7, False),
        ),
    )
    diagnostic = _diagnostic("DEP-001", Severity.ERROR, "PYTHON.DATEUTIL")
    data = DependencyRiskGraph(context, [diagnostic]).to_dict()
    assert data["total_dependencies"] == data["direct_count"] == data["installed_count"] == 1
    node = data["nodes"][0]
    assert node["name"] == "Python_DateUtil"
    assert node["canonical_name"] == "python-dateutil"
    assert node["version"] == "2.9.0"
    assert node["specifier"] == ">=2"
    assert node["is_imported"] is True
    assert node["import_locations"] == ["app.py:2", "worker.py:7"]
    assert node["risk_level"] == "high"


@pytest.mark.parametrize(
    ("module", "relative"), [("requests", True), ("", False), ("os.path", False)]
)
def test_relative_empty_and_stdlib_imports_are_ignored(
    tmp_path: Path, module: str, relative: bool
) -> None:
    package = module.split(".")[0] or "requests"
    context = _make_context(
        tmp_path,
        dependencies=(DependencyDeclaration(package, "", tmp_path / "pyproject.toml"),),
        imports=(ImportRecord(module, tmp_path / "app.py", 1, relative),),
    )
    node = DependencyRiskGraph(context).to_dict()["nodes"][0]
    assert node["is_imported"] is False
    assert node["import_locations"] == []


@pytest.mark.parametrize(
    ("rule", "severity", "risk", "reason"),
    [
        ("DEP-006", Severity.ERROR, RiskLevel.CRITICAL, "Vulnerability advisory"),
        ("DEP-001", Severity.ERROR, RiskLevel.HIGH, "version constraint conflict"),
        ("DEP-002", Severity.ERROR, RiskLevel.MEDIUM, "missing from pyproject.toml"),
        ("DEP-007", Severity.WARNING, RiskLevel.MEDIUM, "provided transitively"),
        ("DEP-004", Severity.WARNING, RiskLevel.MEDIUM, "runtime compatibility mismatch"),
        ("DEP-003", Severity.WARNING, RiskLevel.LOW, "no direct import"),
        ("CUSTOM-001", Severity.ERROR, RiskLevel.HIGH, "Finding CUSTOM-001"),
        ("CUSTOM-001", Severity.WARNING, RiskLevel.MEDIUM, "Finding CUSTOM-001"),
        ("CUSTOM-001", Severity.INFO, RiskLevel.HEALTHY, "healthy"),
    ],
)
def test_diagnostic_risk_and_explanation(
    imported_context: ProjectContext, rule: str, severity: Severity, risk: RiskLevel, reason: str
) -> None:
    graph = DependencyRiskGraph(imported_context, [_diagnostic(rule, severity, "requests")])
    node = graph.to_dict()["nodes"][0]
    assert node["risk_level"] == risk.value
    assert any(reason in explanation for explanation in node["risk_reasons"])


def test_diagnostics_only_affect_named_packages(imported_context: ProjectContext) -> None:
    context = replace(
        imported_context,
        installed_packages={
            **imported_context.installed_packages,
            "urllib3": InstalledDistribution("urllib3", "2.0"),
            "certifi": InstalledDistribution("certifi", "2024.2.2"),
        },
    )
    graph = DependencyRiskGraph(
        context,
        [
            _diagnostic("DEP-006", Severity.ERROR, "REQUESTS", "urllib3", "absent-package"),
            _diagnostic("DEP-001", Severity.ERROR),
        ],
    )
    nodes = {node["name"]: node for node in graph.to_dict()["nodes"]}
    assert set(nodes) == {"requests", "urllib3", "certifi"}
    assert nodes["requests"]["risk_level"] == nodes["urllib3"]["risk_level"] == "critical"
    assert nodes["certifi"]["risk_level"] == "healthy"


@pytest.mark.parametrize(
    ("direct", "imported", "installed", "risk", "reason"),
    [
        (True, True, True, "healthy", "healthy"),
        (True, False, True, "low", "without direct import"),
        (True, True, False, "high", "not installed"),
        (False, True, True, "medium", "only declared transitively"),
        (False, False, True, "healthy", "healthy"),
    ],
)
def test_usage_and_installation_risk(
    imported_context: ProjectContext,
    direct: bool,
    imported: bool,
    installed: bool,
    risk: str,
    reason: str,
) -> None:
    context = replace(
        imported_context,
        dependencies=imported_context.dependencies if direct else (),
        imports=imported_context.imports if imported else (),
        installed_packages=imported_context.installed_packages if installed else {},
    )
    node = DependencyRiskGraph(context).to_dict()["nodes"][0]
    assert node["is_direct"] is direct
    assert node["is_imported"] is imported
    assert node["risk_level"] == risk
    assert any(reason in explanation for explanation in node["risk_reasons"])


@pytest.mark.parametrize("name", ["fastapi", "uvicorn", "pytest"])
def test_frameworks_drivers_and_tooling_need_no_direct_import(tmp_path: Path, name: str) -> None:
    context = _make_context(
        tmp_path,
        dependencies=(DependencyDeclaration(name, "", tmp_path / "pyproject.toml"),),
        installed_packages={name: InstalledDistribution(name, "1.0")},
    )
    assert DependencyRiskGraph(context).to_dict()["nodes"][0]["risk_level"] == "healthy"


def test_requires_parsing_skips_malformed_and_optional_requirements(
    imported_context: ProjectContext,
) -> None:
    context = replace(
        imported_context,
        installed_packages={
            "requests": InstalledDistribution(
                "requests",
                "2.31.0",
                requires=(
                    "not a valid requirement!",
                    "Optional-Pkg; extra == 'dev'",
                    "Other-Pkg; python_version < '2'",
                    "Child_Pkg[http]>=1.0",
                    "missing-child>=1",
                ),
            ),
            "child-pkg": InstalledDistribution("Child_Pkg", "1.0"),
        },
    )
    graph = DependencyRiskGraph(context)
    nodes = {node["canonical_name"]: node for node in graph.to_dict()["nodes"]}
    assert nodes["requests"]["dependencies"] == ["child-pkg", "missing-child"]
    assert nodes["child-pkg"]["is_direct"] is False
    rendered = _render(graph.build_tree(annotate=False))
    assert "Child_Pkg" in rendered
    assert "missing-child" not in rendered
    assert "Optional-Pkg" not in rendered


@pytest.fixture
def branching_context(tmp_path: Path) -> ProjectContext:
    """Two branches share a child which links back to their root."""
    return _make_context(
        tmp_path,
        dependencies=(
            DependencyDeclaration("app-root", ">=1", tmp_path / "pyproject.toml"),
            DependencyDeclaration("dev-helper", "", tmp_path / "pyproject.toml", is_dev=True),
        ),
        installed_packages={
            "app-root": InstalledDistribution("app-root", "1.0", requires=("left", "right")),
            "left": InstalledDistribution("left", "1.0", requires=("shared",)),
            "right": InstalledDistribution("right", "1.0", requires=("shared",)),
            "shared": InstalledDistribution("shared", "1.0", requires=("app-root",)),
        },
    )


@pytest.mark.parametrize(
    ("depth", "visible", "hidden"),
    [(1, "app-root", "left"), (2, "left", "shared"), (3, "shared", "circular dependency")],
)
def test_tree_depth_limits_dependency_levels(
    branching_context: ProjectContext, depth: int, visible: str, hidden: str
) -> None:
    rendered = _render(
        DependencyRiskGraph(branching_context).build_tree(max_depth=depth, annotate=False)
    )
    assert visible in rendered
    assert hidden not in rendered


def test_cycles_terminate_and_shared_children_expand_on_each_path(
    branching_context: ProjectContext,
) -> None:
    graph = DependencyRiskGraph(branching_context)
    rendered = _render(graph.build_tree(max_depth=20, annotate=False))
    assert rendered.count("shared") == 2
    assert rendered.count("circular dependency") == 2
    # Traversal state must not leak between calls.
    assert _render(graph.build_tree(max_depth=20, annotate=False)) == rendered


@pytest.mark.parametrize("annotate", [True, False])
def test_tree_groups_and_annotation_toggle(
    branching_context: ProjectContext, annotate: bool
) -> None:
    rendered = _render(DependencyRiskGraph(branching_context).build_tree(annotate=annotate))
    for text in (
        "Production Dependencies",
        "Dev & Tooling Dependencies",
        "v1.0",
        "(>=1)",
        "(uninstalled)",
    ):
        assert text in rendered
    for text in ("Type:", "Import:", "Role:", "Assessment:", "Transitive dependency"):
        assert (text in rendered) is annotate


@pytest.mark.parametrize(
    ("risk_filter", "names"),
    [
        (None, {"app-root", "dev-helper"}),
        ("all", {"app-root", "dev-helper"}),
        ("  LOW  ", {"app-root"}),
        ("high", {"dev-helper"}),
        ("critical", set()),
    ],
)
def test_tree_filters_direct_nodes(
    branching_context: ProjectContext, risk_filter: str | None, names: set[str]
) -> None:
    tree = DependencyRiskGraph(branching_context).build_tree(
        risk_filter=risk_filter, annotate=False, max_depth=1
    )
    labels = [str(child.label) for group in tree.children for child in group.children]
    assert len(labels) == len(names)
    for name in names:
        assert any(name in label for label in labels)


def test_empty_graph_serialization_and_tree(tmp_path: Path) -> None:
    graph = DependencyRiskGraph(_make_context(tmp_path))
    assert graph.to_dict() == {
        "project_name": "test-project",
        "project_root": str(tmp_path),
        "total_dependencies": 0,
        "direct_count": 0,
        "installed_count": 0,
        "nodes": [],
    }
    assert "No dependencies discovered" in _render(graph.build_tree())


def test_serialization_is_json_compatible_and_preserves_node_metadata(
    imported_context: ProjectContext,
) -> None:
    data = DependencyRiskGraph(imported_context).to_dict()
    assert json.loads(json.dumps(data)) == data
    assert data["project_root"] == str(imported_context.project_root)
    assert data["nodes"] == [
        {
            "name": "requests",
            "canonical_name": "requests",
            "version": "2.31.0",
            "specifier": ">=2",
            "is_direct": True,
            "is_dev": False,
            "is_imported": True,
            "import_locations": ["app.py:3"],
            "role": "library",
            "risk_level": "healthy",
            "risk_reasons": ["No diagnostic issues found; dependency is healthy"],
            "dependencies": [],
        }
    ]


@pytest.mark.parametrize("advisory_first", [True, False])
def test_vulnerability_risk_is_independent_of_diagnostic_order(
    imported_context: ProjectContext, advisory_first: bool
) -> None:
    diagnostics = [
        _diagnostic("DEP-006", Severity.ERROR, "requests"),
        _diagnostic("DEP-001", Severity.ERROR, "requests"),
    ]
    if not advisory_first:
        diagnostics.reverse()
    node = DependencyRiskGraph(imported_context, diagnostics).to_dict()["nodes"][0]
    assert node["risk_level"] == "critical"
    assert any("Vulnerability advisory" in reason for reason in node["risk_reasons"])


def test_unused_import_heuristic_does_not_hide_warning(imported_context: ProjectContext) -> None:
    context = replace(imported_context, imports=())
    diagnostic = _diagnostic("CUSTOM-001", Severity.WARNING, "requests")
    node = DependencyRiskGraph(context, [diagnostic]).to_dict()["nodes"][0]
    assert node["risk_level"] == "medium"
