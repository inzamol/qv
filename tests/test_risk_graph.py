from pathlib import Path

from click.testing import CliRunner

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
