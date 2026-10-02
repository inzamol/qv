"""Unit tests for import and architecture analyzer."""

from pathlib import Path

from qv.analyzers.imports.analyzer import ImportAnalyzer
from qv.core.context import (
    CIConfig,
    DockerConfig,
    ImportRecord,
    ProjectContext,
    PythonRuntime,
    SourceFile,
)
from qv.core.models import Severity


def test_imp_001_circular_import_detection(tmp_path: Path):
    runtime = PythonRuntime("3.12.0", 3, 12, 0)
    file_a = tmp_path / "module_a.py"
    file_b = tmp_path / "module_b.py"

    context = ProjectContext(
        project_root=tmp_path,
        project_name="cycle-app",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(),
        lock_files=(),
        dependencies=(),
        installed_packages={},
        source_files=(
            SourceFile(
                path=file_a,
                relative_path=Path("module_a.py"),
                content="import module_b",
                module_name="module_a",
            ),
            SourceFile(
                path=file_b,
                relative_path=Path("module_b.py"),
                content="import module_a",
                module_name="module_b",
            ),
        ),
        imports=(
            ImportRecord(
                module_name="module_b",
                source_file=file_a,
                line_number=1,
                is_relative=False,
            ),
            ImportRecord(
                module_name="module_a",
                source_file=file_b,
                line_number=1,
                is_relative=False,
            ),
        ),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    analyzer = ImportAnalyzer()
    diagnostics = analyzer.analyze(context)

    cycle_diags = [d for d in diagnostics if d.id == "IMP-001"]
    assert len(cycle_diags) >= 1
    assert cycle_diags[0].severity == Severity.ERROR
    assert "Circular import cycle detected" in cycle_diags[0].message


def test_imp_003_dead_module_detection(tmp_path: Path):
    runtime = PythonRuntime("3.12.0", 3, 12, 0)
    main_file = tmp_path / "main.py"
    used_file = tmp_path / "helper.py"
    dead_file = tmp_path / "orphan.py"

    context = ProjectContext(
        project_root=tmp_path,
        project_name="dead-code-app",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(),
        lock_files=(),
        dependencies=(),
        installed_packages={},
        source_files=(
            SourceFile(
                path=main_file,
                relative_path=Path("main.py"),
                content="import helper",
                module_name="main",
            ),
            SourceFile(
                path=used_file,
                relative_path=Path("helper.py"),
                content="def util(): pass",
                module_name="helper",
            ),
            SourceFile(
                path=dead_file,
                relative_path=Path("orphan.py"),
                content="def obsolete(): pass",
                module_name="orphan",
            ),
        ),
        imports=(
            ImportRecord(
                module_name="helper",
                source_file=main_file,
                line_number=1,
                is_relative=False,
            ),
        ),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    analyzer = ImportAnalyzer()
    diagnostics = analyzer.analyze(context)

    dead_diags = [d for d in diagnostics if d.id == "IMP-003"]
    assert len(dead_diags) == 1
    assert "orphan" in dead_diags[0].message
    assert dead_diags[0].severity == Severity.WARNING


def test_imp_004_deprecated_stdlib_detection(tmp_path: Path):
    runtime = PythonRuntime("3.12.0", 3, 12, 0)
    app_file = tmp_path / "app.py"

    context = ProjectContext(
        project_root=tmp_path,
        project_name="legacy-app",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(),
        lock_files=(),
        dependencies=(),
        installed_packages={},
        source_files=(
            SourceFile(
                path=app_file,
                relative_path=Path("app.py"),
                content="import distutils\nimport pipes",
                module_name="app",
            ),
        ),
        imports=(
            ImportRecord(
                module_name="distutils",
                source_file=app_file,
                line_number=1,
                is_relative=False,
            ),
            ImportRecord(
                module_name="pipes",
                source_file=app_file,
                line_number=2,
                is_relative=False,
            ),
        ),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    analyzer = ImportAnalyzer()
    diagnostics = analyzer.analyze(context)

    stdlib_diags = [d for d in diagnostics if d.id == "IMP-004"]
    assert len(stdlib_diags) == 2
    # distutils was removed in 3.12 so severity is ERROR on 3.12
    distutils_diag = next(d for d in stdlib_diags if "distutils" in d.title)
    assert distutils_diag.severity == Severity.ERROR
    assert "setuptools" in distutils_diag.suggestions[0].description


def test_imp_002_relative_imports_resolved(tmp_path: Path):
    runtime = PythonRuntime("3.12.0", 3, 12, 0)
    app_file = tmp_path / "myapp" / "app.py"
    events_file = tmp_path / "myapp" / "events.py"

    context = ProjectContext(
        project_root=tmp_path,
        project_name="myapp",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(),
        lock_files=(),
        dependencies=(),
        installed_packages={},
        source_files=(
            SourceFile(
                path=app_file,
                relative_path=Path("myapp/app.py"),
                content="from . import events\nfrom .events import handle_event",
                module_name="myapp.app",
            ),
            SourceFile(
                path=events_file,
                relative_path=Path("myapp/events.py"),
                content="def handle_event(): pass",
                module_name="myapp.events",
            ),
        ),
        imports=(
            ImportRecord(
                module_name="",
                source_file=app_file,
                line_number=1,
                is_relative=True,
                imported_symbols=("events",),
                level=1,
                resolved_module="myapp",
            ),
            ImportRecord(
                module_name="events",
                source_file=app_file,
                line_number=2,
                is_relative=True,
                imported_symbols=("handle_event",),
                level=1,
                resolved_module="myapp.events",
            ),
        ),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    analyzer = ImportAnalyzer()
    diagnostics = analyzer.analyze(context)

    unresolved_diags = [d for d in diagnostics if d.id == "IMP-002"]
    assert len(unresolved_diags) == 0

    dead_diags = [d for d in diagnostics if d.id == "IMP-003"]
    # myapp.events is imported by myapp.app via relative import so it is not dead
    assert not any("myapp.events" in d.title for d in dead_diags)
