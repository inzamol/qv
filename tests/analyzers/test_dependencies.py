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


def test_dep_004_python_compatibility_mismatch(tmp_path: Path):
    """Test that DEP-004 is reported when an installed package's Requires-Python is incompatible with the active runtime."""
    runtime = PythonRuntime("3.8.0", 3, 8, 0)
    # package requires Python >=3.10, but active runtime is 3.8.0
    context = ProjectContext(
        project_root=tmp_path,
        project_name="incompatible-app",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(),
        lock_files=(),
        dependencies=(),
        installed_packages={
            "modern-pkg": InstalledDistribution(
                name="modern-pkg",
                version="2.0.0",
                requires=(),
                requires_python=">=3.10",
            ),
            "compat-pkg": InstalledDistribution(
                name="compat-pkg",
                version="1.0.0",
                requires=(),
                requires_python=">=3.7",
            ),
        },
        source_files=(),
        imports=(),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    analyzer = DependencyAnalyzer()
    diagnostics = analyzer.analyze(context)

    compat_diags = [d for d in diagnostics if d.id == "DEP-004"]
    assert len(compat_diags) == 1
    assert compat_diags[0].severity == Severity.WARNING
    assert "modern-pkg" in compat_diags[0].title
    assert ">=3.10" in compat_diags[0].message


def test_dep_007_undeclared_transitive_dependency(tmp_path: Path):
    """Test that importing a package provided transitively by a declared dependency emits DEP-007 (not DEP-002)."""
    runtime = PythonRuntime("3.12.0", 3, 12, 0)
    manifest = tmp_path / "pyproject.toml"
    tasks_file = tmp_path / "tasks.py"

    context = ProjectContext(
        project_root=tmp_path,
        project_name="celery-app",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(manifest,),
        lock_files=(),
        dependencies=(
            DependencyDeclaration(
                name="celery",
                specifier=">=5.3.0",
                source_file=manifest,
            ),
        ),
        installed_packages={
            "celery": InstalledDistribution(
                name="celery",
                version="5.3.6",
                requires=("kombu<6.0,>=5.3.4",),
            ),
            "kombu": InstalledDistribution(
                name="kombu",
                version="5.3.5",
                requires=(),
            ),
        },
        source_files=(
            SourceFile(
                path=tasks_file,
                relative_path=Path("tasks.py"),
                content="import kombu\n",
                module_name="tasks",
            ),
        ),
        imports=(
            ImportRecord(
                module_name="kombu",
                source_file=tasks_file,
                line_number=1,
                is_relative=False,
            ),
        ),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    analyzer = DependencyAnalyzer()
    diagnostics = analyzer.analyze(context)

    # Must emit DEP-007 with WARNING severity
    dep_007 = [d for d in diagnostics if d.id == "DEP-007"]
    assert len(dep_007) == 1
    assert dep_007[0].severity == Severity.WARNING
    assert dep_007[0].title == "Undeclared transitive dependency: kombu"
    assert "celery" in dep_007[0].message
    assert any(e.source and "celery metadata" in e.source for e in dep_007[0].evidence)

    # Must NOT emit DEP-002 for kombu
    dep_002 = [d for d in diagnostics if d.id == "DEP-002"]
    assert len(dep_002) == 0


def test_dep_002_and_dep_007_independent_suppression(tmp_path: Path):
    """Test that DEP-002 and DEP-007 can be configured/suppressed independently."""
    from qv.core.config import QvConfig
    from qv.core.engine import AnalysisEngine

    runtime = PythonRuntime("3.12.0", 3, 12, 0)
    manifest = tmp_path / "pyproject.toml"
    app_file = tmp_path / "app.py"

    context = ProjectContext(
        project_root=tmp_path,
        project_name="mixed-deps-app",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(manifest,),
        lock_files=(),
        dependencies=(
            DependencyDeclaration(
                name="celery",
                specifier=">=5.3.0",
                source_file=manifest,
            ),
        ),
        installed_packages={
            "celery": InstalledDistribution(
                name="celery",
                version="5.3.6",
                requires=("kombu<6.0,>=5.3.4",),
            ),
            "kombu": InstalledDistribution(
                name="kombu",
                version="5.3.5",
                requires=(),
            ),
        },
        source_files=(
            SourceFile(
                path=app_file,
                relative_path=Path("app.py"),
                content="import kombu\nimport requests\n",
                module_name="app",
            ),
        ),
        imports=(
            ImportRecord(
                module_name="kombu",
                source_file=app_file,
                line_number=1,
                is_relative=False,
            ),
            ImportRecord(
                module_name="requests",
                source_file=app_file,
                line_number=2,
                is_relative=False,
            ),
        ),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    # Suppress only DEP-007: DEP-002 must still be emitted
    config_ignore_007 = QvConfig(ignored_rules={"DEP-007"})
    res_007_ignored = AnalysisEngine(config=config_ignore_007).run(context)
    rule_ids_1 = [d.id for d in res_007_ignored.diagnostics]
    assert "DEP-002" in rule_ids_1
    assert "DEP-007" not in rule_ids_1

    # Suppress only DEP-002: DEP-007 must still be emitted
    config_ignore_002 = QvConfig(ignored_rules={"DEP-002"})
    res_002_ignored = AnalysisEngine(config=config_ignore_002).run(context)
    rule_ids_2 = [d.id for d in res_002_ignored.diagnostics]
    assert "DEP-007" in rule_ids_2
    assert "DEP-002" not in rule_ids_2


def test_dep_007_transitive_graph_traversal(tmp_path: Path):
    """Test that importing package C (where declared A requires B, and installed B requires C)
    emits DEP-007 (warning), not DEP-002 (error), by traversing the installed requirement graph.
    """
    from qv.core.config import QvConfig
    from qv.core.engine import AnalysisEngine

    runtime = PythonRuntime("3.12.0", 3, 12, 0)
    manifest = tmp_path / "pyproject.toml"
    service_file = tmp_path / "service.py"

    context = ProjectContext(
        project_root=tmp_path,
        project_name="nested-deps-app",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(manifest,),
        lock_files=(),
        dependencies=(
            DependencyDeclaration(
                name="pkg-a",
                specifier=">=1.0.0",
                source_file=manifest,
            ),
        ),
        installed_packages={
            "pkg-a": InstalledDistribution(
                name="pkg-a",
                version="1.0.0",
                requires=("pkg-b>=2.0.0",),
            ),
            "pkg-b": InstalledDistribution(
                name="pkg-b",
                version="2.0.0",
                requires=("pkg-c>=3.0.0",),
            ),
            "pkg-c": InstalledDistribution(
                name="pkg-c",
                version="3.0.0",
                requires=(),
            ),
        },
        source_files=(
            SourceFile(
                path=service_file,
                relative_path=Path("service.py"),
                content="import pkg_c\n",
                module_name="service",
            ),
        ),
        imports=(
            ImportRecord(
                module_name="pkg_c",
                source_file=service_file,
                line_number=1,
                is_relative=False,
            ),
        ),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    analyzer = DependencyAnalyzer()
    diagnostics = analyzer.analyze(context)

    # Must emit DEP-007 (warning), NOT DEP-002 (error)
    dep_007 = [d for d in diagnostics if d.id == "DEP-007"]
    assert len(dep_007) == 1
    assert dep_007[0].severity == Severity.WARNING
    assert "pkg_c" in dep_007[0].title
    assert "pkg-a" in dep_007[0].message
    assert any(e.source and "pkg-a metadata" in e.source for e in dep_007[0].evidence)

    dep_002 = [d for d in diagnostics if d.id == "DEP-002"]
    assert len(dep_002) == 0

    # Verify that suppressing DEP-007 suppresses the finding, and suppressing DEP-002 preserves it
    cfg_ignore_007 = QvConfig(ignored_rules={"DEP-007"})
    res_ignore_007 = AnalysisEngine(config=cfg_ignore_007).run(context)
    assert not any(d.id in ("DEP-002", "DEP-007") for d in res_ignore_007.diagnostics)

    cfg_ignore_002 = QvConfig(ignored_rules={"DEP-002"})
    res_ignore_002 = AnalysisEngine(config=cfg_ignore_002).run(context)
    assert any(d.id == "DEP-007" for d in res_ignore_002.diagnostics)
    assert not any(d.id == "DEP-002" for d in res_ignore_002.diagnostics)


def test_dep_002_when_transitive_marker_does_not_apply(tmp_path: Path):
    """Test that if a declared package lists foo; python_version < '3.10' and runtime is Python 3.12,
    importing foo emits DEP-002 (error), not DEP-007, and is not hidden by DEP-007 suppression.
    """
    from qv.core.config import QvConfig
    from qv.core.engine import AnalysisEngine

    runtime = PythonRuntime("3.12.0", 3, 12, 0)
    manifest = tmp_path / "pyproject.toml"
    app_file = tmp_path / "app.py"

    context = ProjectContext(
        project_root=tmp_path,
        project_name="incompatible-marker-app",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(manifest,),
        lock_files=(),
        dependencies=(
            DependencyDeclaration(
                name="pkg-a",
                specifier=">=1.0.0",
                source_file=manifest,
            ),
        ),
        installed_packages={
            "pkg-a": InstalledDistribution(
                name="pkg-a",
                version="1.0.0",
                requires=('foo<2.0; python_version < "3.10"',),
            ),
        },
        source_files=(
            SourceFile(
                path=app_file,
                relative_path=Path("app.py"),
                content="import foo\n",
                module_name="app",
            ),
        ),
        imports=(
            ImportRecord(
                module_name="foo",
                source_file=app_file,
                line_number=1,
                is_relative=False,
            ),
        ),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    analyzer = DependencyAnalyzer()
    diagnostics = analyzer.analyze(context)

    # Must emit DEP-002 (error) because foo is NOT supplied by pkg-a in Python 3.12
    dep_002 = [d for d in diagnostics if d.id == "DEP-002"]
    assert len(dep_002) == 1
    assert dep_002[0].severity == Severity.ERROR
    assert "foo" in dep_002[0].title

    # Must NOT emit DEP-007
    dep_007 = [d for d in diagnostics if d.id == "DEP-007"]
    assert len(dep_007) == 0

    # Disabling only DEP-007 must NOT hide this missing dependency error
    cfg_ignore_007 = QvConfig(ignored_rules={"DEP-007"})
    res_ignore_007 = AnalysisEngine(config=cfg_ignore_007).run(context)
    rule_ids = [d.id for d in res_ignore_007.diagnostics]
    assert "DEP-002" in rule_ids
    assert "DEP-007" not in rule_ids


def test_dep_002_when_transitive_package_not_installed(tmp_path: Path):
    """Test that if a requirement marker applies but the package is not installed in the environment,
    importing it emits DEP-002 (error) instead of falsely reporting DEP-007.
    """
    runtime = PythonRuntime("3.12.0", 3, 12, 0)
    manifest = tmp_path / "pyproject.toml"
    app_file = tmp_path / "app.py"

    context = ProjectContext(
        project_root=tmp_path,
        project_name="uninstalled-transitive-app",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(manifest,),
        lock_files=(),
        dependencies=(
            DependencyDeclaration(
                name="pkg-a",
                specifier=">=1.0.0",
                source_file=manifest,
            ),
        ),
        installed_packages={
            "pkg-a": InstalledDistribution(
                name="pkg-a",
                version="1.0.0",
                requires=("missing_pkg>=1.0",),
            ),
            # missing_pkg is NOT installed
        },
        source_files=(
            SourceFile(
                path=app_file,
                relative_path=Path("app.py"),
                content="import missing_pkg\n",
                module_name="app",
            ),
        ),
        imports=(
            ImportRecord(
                module_name="missing_pkg",
                source_file=app_file,
                line_number=1,
                is_relative=False,
            ),
        ),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    analyzer = DependencyAnalyzer()
    diagnostics = analyzer.analyze(context)

    # Must emit DEP-002 (error) because missing_pkg is not installed
    dep_002 = [d for d in diagnostics if d.id == "DEP-002"]
    assert len(dep_002) == 1
    assert dep_002[0].severity == Severity.ERROR

    dep_007 = [d for d in diagnostics if d.id == "DEP-007"]
    assert len(dep_007) == 0


def test_dep_007_with_selected_extras(tmp_path: Path):
    """Test that requirement markers evaluating extras only provide transitive dependencies
    when those extras are selected in the declaration.
    """
    runtime = PythonRuntime("3.12.0", 3, 12, 0)
    manifest = tmp_path / "pyproject.toml"
    app_file = tmp_path / "app.py"

    installed = {
        "pkg-a": InstalledDistribution(
            name="pkg-a",
            version="1.0.0",
            requires=('extra_pkg>=1.0; extra == "socks"',),
        ),
        "extra-pkg": InstalledDistribution(
            name="extra-pkg",
            version="1.0.0",
            requires=(),
        ),
    }

    # Case 1: Extra "socks" NOT selected -> emits DEP-002
    context_no_extra = ProjectContext(
        project_root=tmp_path,
        project_name="no-extra-app",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(manifest,),
        lock_files=(),
        dependencies=(
            DependencyDeclaration(
                name="pkg-a",
                specifier=">=1.0.0",
                source_file=manifest,
                extras=(),
            ),
        ),
        installed_packages=installed,
        source_files=(
            SourceFile(
                path=app_file,
                relative_path=Path("app.py"),
                content="import extra_pkg\n",
                module_name="app",
            ),
        ),
        imports=(
            ImportRecord(
                module_name="extra_pkg",
                source_file=app_file,
                line_number=1,
                is_relative=False,
            ),
        ),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    analyzer = DependencyAnalyzer()
    diags_no_extra = analyzer.analyze(context_no_extra)
    assert any(d.id == "DEP-002" for d in diags_no_extra)
    assert not any(d.id == "DEP-007" for d in diags_no_extra)

    # Case 2: Extra "socks" IS selected -> emits DEP-007
    context_with_extra = ProjectContext(
        project_root=tmp_path,
        project_name="with-extra-app",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(manifest,),
        lock_files=(),
        dependencies=(
            DependencyDeclaration(
                name="pkg-a",
                specifier=">=1.0.0",
                source_file=manifest,
                extras=("socks",),
            ),
        ),
        installed_packages=installed,
        source_files=(
            SourceFile(
                path=app_file,
                relative_path=Path("app.py"),
                content="import extra_pkg\n",
                module_name="app",
            ),
        ),
        imports=(
            ImportRecord(
                module_name="extra_pkg",
                source_file=app_file,
                line_number=1,
                is_relative=False,
            ),
        ),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    diags_with_extra = analyzer.analyze(context_with_extra)
    assert any(d.id == "DEP-007" for d in diags_with_extra)
    assert not any(d.id == "DEP-002" for d in diags_with_extra)
