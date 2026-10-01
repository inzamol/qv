"""Tests for lockfile and pinned dependency parsers."""

from __future__ import annotations

import json
from pathlib import Path

from qv.analyzers.security.lockfile_parser import LockfileParser
from qv.core.context import (
    CIConfig,
    DependencyDeclaration,
    DockerConfig,
    InstalledDistribution,
    ProjectContext,
    PythonRuntime,
)


def test_parse_uv_lock(tmp_path: Path):
    uv_lock_content = """
version = 1
revision = 1
requires-python = ">=3.10"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "urllib3" },
]

[[package]]
name = "urllib3"
version = "2.0.7"
source = { registry = "https://pypi.org/simple" }
"""
    lock_file = tmp_path / "uv.lock"
    lock_file.write_text(uv_lock_content, encoding="utf-8")

    direct_names = {"requests"}
    packages = LockfileParser.parse_uv_lock(lock_file, direct_names)

    assert len(packages) == 2
    req_pkg = next(p for p in packages if p.name == "requests")
    assert req_pkg.version == "2.31.0"
    assert req_pkg.is_direct is True

    url_pkg = next(p for p in packages if p.name == "urllib3")
    assert url_pkg.version == "2.0.7"
    assert url_pkg.is_direct is False


def test_parse_poetry_lock(tmp_path: Path):
    poetry_lock_content = """
[[package]]
name = "flask"
version = "2.2.5"
description = "A simple framework for building complex web applications."
optional = false
python-versions = ">=3.7"

[[package]]
name = "werkzeug"
version = "2.2.3"
description = "The comprehensive WSGI web application library."
optional = false
python-versions = ">=3.7"
"""
    lock_file = tmp_path / "poetry.lock"
    lock_file.write_text(poetry_lock_content, encoding="utf-8")

    packages = LockfileParser.parse_poetry_lock(lock_file, direct_names={"flask"})
    assert len(packages) == 2
    flask_pkg = next(p for p in packages if p.name == "flask")
    assert flask_pkg.version == "2.2.5"
    assert flask_pkg.is_direct is True


def test_parse_pipfile_lock(tmp_path: Path):
    pipfile_content = {
        "_meta": {"hash": {"sha256": "abcdef"}},
        "default": {
            "requests": {"version": "==2.28.1"},
            "certifi": {"version": "==2022.12.7"},
        },
        "develop": {
            "pytest": {"version": "==7.2.0"},
        },
    }
    lock_file = tmp_path / "Pipfile.lock"
    lock_file.write_text(json.dumps(pipfile_content), encoding="utf-8")

    packages = LockfileParser.parse_pipfile_lock(lock_file, direct_names={"requests"})
    assert len(packages) == 3
    assert any(p.name == "requests" and p.version == "2.28.1" and p.is_direct for p in packages)
    assert any(
        p.name == "certifi" and p.version == "2022.12.7" and not p.is_direct for p in packages
    )


def test_parse_requirements_txt(tmp_path: Path):
    req_content = """
# Pinned packages
jinja2==2.11.2
requests>=2.25.0
click == 8.1.3
"""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(req_content, encoding="utf-8")

    packages = LockfileParser.parse_requirements_txt(req_file, direct_names={"jinja2", "click"})
    assert len(packages) == 2
    assert any(p.name == "jinja2" and p.version == "2.11.2" for p in packages)
    assert any(p.name == "click" and p.version == "8.1.3" for p in packages)


def test_parse_context_fallback_to_installed(tmp_path: Path):
    runtime = PythonRuntime(version_str="3.11.0", major=3, minor=11, micro=0)
    context = ProjectContext(
        project_root=tmp_path,
        project_name="test_proj",
        python_runtime=runtime,
        package_manager="pip",
        manifest_files=(),
        lock_files=(),
        dependencies=(
            DependencyDeclaration(
                name="requests",
                specifier=">=2.0.0",
                source_file=tmp_path / "pyproject.toml",
            ),
        ),
        installed_packages={
            "requests": InstalledDistribution(name="requests", version="2.31.0"),
            "urllib3": InstalledDistribution(name="urllib3", version="2.0.7"),
        },
        source_files=(),
        imports=(),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    packages = LockfileParser.parse_context(context)
    assert len(packages) == 2
    req_pkg = next(p for p in packages if p.name == "requests")
    assert req_pkg.version == "2.31.0"
    assert req_pkg.is_direct is True
