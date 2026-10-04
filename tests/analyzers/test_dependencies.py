"""Unit tests for dependency analyzer rules."""

from pathlib import Path

from qv.analyzers.dependencies.analyzer import DependencyAnalyzer
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
from qv.core.models import Severity


def test_dep_001_conflict_detected(tmp_path: Path):
    runtime = PythonRuntime("3.12.0", 3, 12, 0)
    # celery requires kombu<5.4, but installed kombu is 5.5.2
    context = ProjectContext(
        project_root=tmp_path,
        project_name="conflict-app",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(),
        lock_files=(),
        dependencies=(),
        installed_packages={
            "celery": InstalledDistribution(
                name="celery",
                version="5.4.0",
                requires=("kombu<5.4.0,>=5.3.0",),
            ),
            "kombu": InstalledDistribution(
                name="kombu",
                version="5.5.2",
                requires=(),
            ),
        },
        source_files=(),
        imports=(),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    analyzer = DependencyAnalyzer()
    diagnostics = analyzer.analyze(context)

    conflict_diags = [d for d in diagnostics if d.id == "DEP-001"]
    assert len(conflict_diags) == 1
    assert conflict_diags[0].severity == Severity.ERROR
    assert "celery requires kombu<5.4.0,>=5.3.0" in conflict_diags[0].message


def test_dep_002_missing_dependency(tmp_path: Path):
    runtime = PythonRuntime("3.12.0", 3, 12, 0)
    src_file = tmp_path / "app.py"
    src_file.write_text("import requests\n", encoding="utf-8")

    context = ProjectContext(
        project_root=tmp_path,
        project_name="missing-dep-app",
        python_runtime=runtime,
        package_manager="pip",
        manifest_files=(),
        lock_files=(),
        dependencies=(),  # requests is NOT declared
        installed_packages={},
        source_files=(
            SourceFile(
                path=src_file,
                relative_path=Path("app.py"),
                content="import requests\n",
                module_name="app",
            ),
        ),
        imports=(
            ImportRecord(
                module_name="requests",
                source_file=src_file,
                line_number=1,
                is_relative=False,
            ),
        ),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    analyzer = DependencyAnalyzer()
    diagnostics = analyzer.analyze(context)

    missing_diags = [d for d in diagnostics if d.id == "DEP-002"]
    assert len(missing_diags) == 1
    assert "requests" in missing_diags[0].affected_packages


def test_dep_003_unused_dependency(tmp_path: Path):
    runtime = PythonRuntime("3.12.0", 3, 12, 0)
    manifest = tmp_path / "pyproject.toml"

    context = ProjectContext(
        project_root=tmp_path,
        project_name="unused-dep-app",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(manifest,),
        lock_files=(),
        dependencies=(
            DependencyDeclaration(
                name="httpx",
                specifier=">=0.25.0",
                source_file=manifest,
            ),
        ),
        installed_packages={},
        source_files=(
            SourceFile(
                path=tmp_path / "main.py",
                relative_path=Path("main.py"),
                content="import json\n",
                module_name="main",
            ),
        ),
        imports=(
            ImportRecord(
                module_name="json",
                source_file=tmp_path / "main.py",
                line_number=1,
                is_relative=False,
            ),
        ),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    analyzer = DependencyAnalyzer()
    diagnostics = analyzer.analyze(context)

    unused_diags = [d for d in diagnostics if d.id == "DEP-003"]
    assert len(unused_diags) == 1
    assert "httpx" in unused_diags[0].affected_packages
    assert unused_diags[0].title == "No direct import detected: httpx"
    assert "no direct import was detected" in unused_diags[0].message
    assert any(e.source == "AST Import Analysis" for e in unused_diags[0].evidence)


def test_dep_002_known_package_mappings_and_build_tools(tmp_path: Path):
    runtime = PythonRuntime("3.12.0", 3, 12, 0)
    setup_file = tmp_path / "setup.py"
    app_file = tmp_path / "app.py"

    manifest = tmp_path / "requirements" / "default.txt"
    manifest.parent.mkdir(parents=True)
    manifest.write_text("prometheus-client>=0.14.0\ncelery>=5.0\n", encoding="utf-8")

    context = ProjectContext(
        project_root=tmp_path,
        project_name="my-app",
        python_runtime=runtime,
        package_manager="pip",
        manifest_files=(setup_file, manifest),
        lock_files=(),
        dependencies=(
            DependencyDeclaration(
                name="prometheus-client",
                specifier=">=0.14.0",
                source_file=manifest,
            ),
            DependencyDeclaration(
                name="celery",
                specifier=">=5.0",
                source_file=manifest,
            ),
        ),
        installed_packages={},
        source_files=(
            SourceFile(
                path=setup_file,
                relative_path=Path("setup.py"),
                content="import setuptools\n",
                module_name="setup",
            ),
            SourceFile(
                path=app_file,
                relative_path=Path("app.py"),
                content="import prometheus_client\nimport celery\n",
                module_name="app",
            ),
        ),
        imports=(
            ImportRecord(
                module_name="setuptools",
                source_file=setup_file,
                line_number=1,
                is_relative=False,
            ),
            ImportRecord(
                module_name="prometheus_client",
                source_file=app_file,
                line_number=1,
                is_relative=False,
            ),
            ImportRecord(
                module_name="celery",
                source_file=app_file,
                line_number=2,
                is_relative=False,
            ),
        ),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    analyzer = DependencyAnalyzer()
    diagnostics = analyzer.analyze(context)

    missing_diags = [d for d in diagnostics if d.id == "DEP-002"]
    assert len(missing_diags) == 0


def test_project_discovery_requirements_folder(tmp_path: Path):
    from qv.core.project import ProjectDiscovery

    req_dir = tmp_path / "requirements"
    req_dir.mkdir()
    (req_dir / "default.txt").write_text("tornado>=6.0\ncelery>=5.2\n", encoding="utf-8")
    (req_dir / "test.txt").write_text("pytest>=7.0\npytz\n", encoding="utf-8")

    pkg_dir = tmp_path / "flower"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text("", encoding="utf-8")
    (pkg_dir / "app.py").write_text("from . import events\nimport tornado.web\n", encoding="utf-8")
    (pkg_dir / "events.py").write_text("import celery\n", encoding="utf-8")

    discovery = ProjectDiscovery(tmp_path)
    context = discovery.discover_context()

    dep_names = {d.name.lower() for d in context.dependencies}
    assert "tornado" in dep_names
    assert "celery" in dep_names
    assert "pytest" in dep_names
    assert "pytz" in dep_names

    # Check relative import resolution
    app_imports = [imp for imp in context.imports if imp.source_file.name == "app.py"]
    rel_imp = next(imp for imp in app_imports if imp.is_relative)
    assert rel_imp.resolved_module == "flower"
