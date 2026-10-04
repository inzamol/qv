"""Immutable project context consumed by analyzers."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from qv.core.models import Diagnostic


@dataclass(frozen=True)
class PythonRuntime:
    """Information about detected/configured Python runtime."""

    version_str: str
    major: int
    minor: int
    micro: int
    executable: str | None = None
    is_virtualenv: bool = False
    virtualenv_path: Path | None = None


@dataclass(frozen=True)
class DependencyDeclaration:
    """A declared project dependency (e.g. from pyproject.toml or requirements.txt)."""

    name: str
    specifier: str
    source_file: Path
    line_number: int | None = None
    is_dev: bool = False
    extras: tuple[str, ...] = ()


@dataclass(frozen=True)
class InstalledDistribution:
    """An installed Python package in the environment."""

    name: str
    version: str
    location: str | None = None
    requires: tuple[str, ...] = ()
    required_by: tuple[str, ...] = ()
    direct_url: str | None = None
    requires_python: str | None = None


@dataclass(frozen=True)
class ImportRecord:
    """An import statement discovered in source code."""

    module_name: str
    source_file: Path
    line_number: int
    is_relative: bool
    imported_symbols: tuple[str, ...] = ()
    level: int = 0
    resolved_module: str | None = None


@dataclass(frozen=True)
class SourceFile:
    """A Python source file in the project."""

    path: Path
    relative_path: Path
    content: str
    is_init: bool = False
    module_name: str = ""


@dataclass(frozen=True)
class DockerConfig:
    """Detected Docker configuration."""

    has_dockerfile: bool
    dockerfile_path: Path | None = None
    base_image: str | None = None
    base_python_version: str | None = None


@dataclass(frozen=True)
class CIConfig:
    """Detected CI configuration."""

    has_ci: bool
    provider: str | None = None  # github_actions, gitlab_ci, etc.
    workflow_files: tuple[Path, ...] = ()
    matrix_python_versions: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProjectContext:
    """Immutable project context passed into each analyzer."""

    project_root: Path
    project_name: str
    python_runtime: PythonRuntime
    package_manager: str  # uv, poetry, pip, pdm, flit, hatch, etc.
    manifest_files: tuple[Path, ...]
    lock_files: tuple[Path, ...]
    dependencies: tuple[DependencyDeclaration, ...]
    installed_packages: dict[str, InstalledDistribution]
    source_files: tuple[SourceFile, ...]
    imports: tuple[ImportRecord, ...]
    docker: DockerConfig
    ci: CIConfig
    discovery_diagnostics: tuple[Diagnostic, ...] = ()
    config: dict[str, Any] = field(default_factory=dict)
