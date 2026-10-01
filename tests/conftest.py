"""Pytest configuration and test fixtures."""

import sys
from pathlib import Path

import pytest

from qv.core.context import (
    CIConfig,
    DependencyDeclaration,
    DockerConfig,
    InstalledDistribution,
    ProjectContext,
    PythonRuntime,
    SourceFile,
)


@pytest.fixture
def dummy_context(tmp_path: Path) -> ProjectContext:
    """Fixture providing a clean minimal ProjectContext."""
    runtime = PythonRuntime(
        version_str="3.12.0",
        major=3,
        minor=12,
        micro=0,
        executable=sys.executable,
        is_virtualenv=True,
        virtualenv_path=tmp_path / ".venv",
    )
    return ProjectContext(
        project_root=tmp_path,
        project_name="sample-project",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(tmp_path / "pyproject.toml",),
        lock_files=(tmp_path / "uv.lock",),
        dependencies=(
            DependencyDeclaration(
                name="click",
                specifier=">=8.0.0",
                source_file=tmp_path / "pyproject.toml",
            ),
        ),
        installed_packages={
            "click": InstalledDistribution(
                name="click",
                version="8.1.7",
                requires=(),
            ),
        },
        source_files=(
            SourceFile(
                path=tmp_path / "main.py",
                relative_path=Path("main.py"),
                content="import click\n\n@click.command()\ndef main():\n    pass\n",
                module_name="main",
            ),
        ),
        imports=(),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
        config={},
    )
