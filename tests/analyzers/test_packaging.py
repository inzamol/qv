"""Unit tests for packaging analyzer."""

from pathlib import Path

from qv.analyzers.packaging.analyzer import PackagingAnalyzer
from qv.core.context import (
    CIConfig,
    DockerConfig,
    ProjectContext,
    PythonRuntime,
)


def test_pkg_001_missing_project_table(tmp_path: Path):
    runtime = PythonRuntime("3.12.0", 3, 12, 0)
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[build-system]\nrequires = ['setuptools']\n", encoding="utf-8")

    context = ProjectContext(
        project_root=tmp_path,
        project_name="bad-pkg",
        python_runtime=runtime,
        package_manager="pip",
        manifest_files=(pyproject,),
        lock_files=(),
        dependencies=(),
        installed_packages={},
        source_files=(),
        imports=(),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    analyzer = PackagingAnalyzer()
    diagnostics = analyzer.analyze(context)

    pkg_diags = [d for d in diagnostics if d.id == "PKG-001"]
    assert len(pkg_diags) == 1
    assert "Missing [project] metadata" in pkg_diags[0].title


def test_pkg_002_invalid_toml(tmp_path: Path):
    runtime = PythonRuntime("3.12.0", 3, 12, 0)
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project\nname = 'broken'", encoding="utf-8")

    context = ProjectContext(
        project_root=tmp_path,
        project_name="broken-toml",
        python_runtime=runtime,
        package_manager="pip",
        manifest_files=(pyproject,),
        lock_files=(),
        dependencies=(),
        installed_packages={},
        source_files=(),
        imports=(),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    analyzer = PackagingAnalyzer()
    diagnostics = analyzer.analyze(context)

    pkg_diags = [d for d in diagnostics if d.id == "PKG-002"]
    assert len(pkg_diags) == 1
    assert "Failed to parse pyproject.toml" in pkg_diags[0].message
