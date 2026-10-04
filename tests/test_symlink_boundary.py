"""Tests for symlink security boundary during project discovery (Issue #6)."""

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from qv.cli.main import cli
from qv.core.project import ProjectDiscovery


def test_external_symlink_python_file_excluded(tmp_path: Path):
    """Ensure external symlink to a .py file outside project root is not discovered."""
    project_dir = tmp_path / "test-project"
    project_dir.mkdir()
    main_py = project_dir / "main.py"
    main_py.write_text("import os\n", encoding="utf-8")

    external_dir = tmp_path / "external"
    external_dir.mkdir()
    external_py = external_dir / "external.py"
    external_py.write_text("import malicious_external_pkg\n", encoding="utf-8")

    link_py = project_dir / "external.py"
    try:
        os.symlink(external_py, link_py)
    except OSError:
        pytest.skip("Symlink creation not supported in this environment")

    discovery = ProjectDiscovery(root=project_dir)
    context = discovery.discover_context()

    source_file_paths = [sf.path.resolve() for sf in context.source_files]
    assert main_py.resolve() in source_file_paths
    assert external_py.resolve() not in source_file_paths

    imported_modules = {imp.module_name for imp in context.imports}
    assert "os" in imported_modules
    assert "malicious_external_pkg" not in imported_modules


def test_external_symlink_directory_excluded(tmp_path: Path):
    """Ensure external symlink to a directory outside project root is not discovered."""
    project_dir = tmp_path / "test-project"
    project_dir.mkdir()
    main_py = project_dir / "main.py"
    main_py.write_text("import sys\n", encoding="utf-8")

    external_dir = tmp_path / "ext_dir"
    external_dir.mkdir()
    ext_file = external_dir / "helper.py"
    ext_file.write_text("import external_helper\n", encoding="utf-8")

    link_dir = project_dir / "ext_dir"
    try:
        os.symlink(external_dir, link_dir, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation not supported in this environment")

    discovery = ProjectDiscovery(root=project_dir)
    context = discovery.discover_context()

    source_file_paths = [sf.path.resolve() for sf in context.source_files]
    assert main_py.resolve() in source_file_paths
    assert ext_file.resolve() not in source_file_paths


def test_external_symlink_requirements_excluded(tmp_path: Path):
    """Ensure external symlink to requirements.txt is not treated as manifest."""
    project_dir = tmp_path / "test-project"
    project_dir.mkdir()

    external_req = tmp_path / "external_reqs.txt"
    external_req.write_text("external-pkg>=1.0.0\n", encoding="utf-8")

    link_req = project_dir / "requirements.txt"
    try:
        os.symlink(external_req, link_req)
    except OSError:
        pytest.skip("Symlink creation not supported in this environment")

    discovery = ProjectDiscovery(root=project_dir)
    context = discovery.discover_context()

    dep_names = {d.name for d in context.dependencies}
    assert "external-pkg" not in dep_names


def test_internal_symlink_allowed(tmp_path: Path):
    """Ensure internal symlink within project root is allowed."""
    project_dir = tmp_path / "test-project"
    project_dir.mkdir()
    main_py = project_dir / "main.py"
    main_py.write_text("import math\n", encoding="utf-8")

    link_py = project_dir / "alias.py"
    try:
        os.symlink(main_py, link_py)
    except OSError:
        pytest.skip("Symlink creation not supported in this environment")

    discovery = ProjectDiscovery(root=project_dir)
    context = discovery.discover_context()

    assert any(sf.path.name == "alias.py" for sf in context.source_files)


def test_broken_symlink_gracefully_ignored(tmp_path: Path):
    """Ensure dangling/broken symlink is ignored without error."""
    project_dir = tmp_path / "test-project"
    project_dir.mkdir()
    main_py = project_dir / "main.py"
    main_py.write_text("import json\n", encoding="utf-8")

    broken_link = project_dir / "dangling.py"
    try:
        os.symlink(project_dir / "nonexistent.py", broken_link)
    except OSError:
        pytest.skip("Symlink creation not supported in this environment")

    discovery = ProjectDiscovery(root=project_dir)
    context = discovery.discover_context()

    assert len(context.source_files) == 1
    assert context.source_files[0].path.name == "main.py"


def test_cli_scan_with_external_symlink(tmp_path: Path):
    """Integration test: qv scan on project with external symlink."""
    project_dir = tmp_path / "test-project"
    project_dir.mkdir()
    pyproject = project_dir / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "demo"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )
    main_py = project_dir / "main.py"
    main_py.write_text("x = 1\n", encoding="utf-8")

    external_py = tmp_path / "external.py"
    external_py.write_text("import undeclared_missing_package\n", encoding="utf-8")

    link_py = project_dir / "external.py"
    try:
        os.symlink(external_py, link_py)
    except OSError:
        pytest.skip("Symlink creation not supported in this environment")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(project_dir)])
    assert result.exit_code == 0
    # undeclared_missing_package must not cause a DEP-002 diagnostic because external.py is outside boundary
    assert "undeclared_missing_package" not in result.output
