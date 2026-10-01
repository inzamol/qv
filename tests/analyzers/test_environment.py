"""Unit tests for environment analyzer rules."""

from pathlib import Path

from qv.analyzers.environment.drift import EnvironmentAnalyzer
from qv.core.context import (
    CIConfig,
    DockerConfig,
    ProjectContext,
    PythonRuntime,
)


def test_env_001_python_drift(tmp_path: Path):
    runtime = PythonRuntime("3.11.2", 3, 11, 2)
    context = ProjectContext(
        project_root=tmp_path,
        project_name="drift-app",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(),
        lock_files=(),
        dependencies=(),
        installed_packages={},
        source_files=(),
        imports=(),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
        config={"target_python": "3.12"},
    )

    analyzer = EnvironmentAnalyzer()
    diagnostics = analyzer.analyze(context)
    drift = [d for d in diagnostics if d.id == "ENV-001"]
    assert len(drift) == 1
    assert "Active Python 3.11.2 does not match target Python 3.12" in drift[0].message


def test_env_002_docker_drift(tmp_path: Path):
    runtime = PythonRuntime("3.12.6", 3, 12, 6)
    context = ProjectContext(
        project_root=tmp_path,
        project_name="docker-app",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(),
        lock_files=(),
        dependencies=(),
        installed_packages={},
        source_files=(),
        imports=(),
        docker=DockerConfig(
            has_dockerfile=True,
            dockerfile_path=tmp_path / "Dockerfile",
            base_image="python:3.10-slim",
            base_python_version="3.10",
        ),
        ci=CIConfig(has_ci=False),
    )

    analyzer = EnvironmentAnalyzer()
    diagnostics = analyzer.analyze(context)
    docker_drift = [d for d in diagnostics if d.id == "ENV-002"]
    assert len(docker_drift) == 1
    assert (
        "Dockerfile base image uses Python 3.10, while local runtime is 3.12"
        in docker_drift[0].message
    )
