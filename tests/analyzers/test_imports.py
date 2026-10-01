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
