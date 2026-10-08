"""Project initialization for QV health configuration and CI workflows."""

from __future__ import annotations

import re
from pathlib import Path

import tomlkit
from packaging.specifiers import SpecifierSet
from packaging.version import Version
from tomlkit.items import Table

from qv.core.config import ConfigurationError

DEFAULT_MIN_SEVERITY = "warning"
DEFAULT_DEPENDENCIES_IGNORE = ["amqp"]
DEFAULT_RULES: dict[str, str] = {
    "DEP-003": "warning",
    "SQL-014": "error",
}
DEFAULT_PATHS_EXCLUDE = [
    "tests",
    "migrations",
]


def build_qv_toml_table() -> Table:
    """Construct the standardized [tool.qv] table and nested tables."""
    qv = tomlkit.table()
    qv["min_severity"] = DEFAULT_MIN_SEVERITY

    deps = tomlkit.table()
    deps_ignore = tomlkit.array('[\n    "amqp",\n]')
    deps["ignore"] = deps_ignore
    qv["dependencies"] = deps

    rules = tomlkit.table()
    rules["DEP-003"] = "warning"
    rules["SQL-014"] = "error"
    qv["rules"] = rules

    paths = tomlkit.table()
    paths_exclude = tomlkit.array('[\n    "tests",\n    "migrations",\n]')
    paths["exclude"] = paths_exclude
    qv["paths"] = paths

    return qv


def init_pyproject(
    project_root: Path,
    force: bool = False,
    dry_run: bool = False,
) -> tuple[bool, str, str]:
    """Generate or update the [tool.qv] table in pyproject.toml.

    Returns:
        (modified, message, toml_content)
    """
    pyproject_path = project_root / "pyproject.toml"

    if pyproject_path.exists():
        if pyproject_path.is_dir():
            raise ConfigurationError(f"Expected file at '{pyproject_path}', but found directory.")
        try:
            content = pyproject_path.read_text(encoding="utf-8")
            doc = tomlkit.parse(content)
        except Exception as e:
            raise ConfigurationError(f"Failed to parse existing '{pyproject_path}': {e}") from e

        tool_table = doc.get("tool")
        has_qv = isinstance(tool_table, dict) and "qv" in tool_table
        if has_qv and not force:
            return (
                False,
                f"[tool.qv] configuration already exists in {pyproject_path}. Use --force to overwrite.",
                tomlkit.dumps(doc),
            )

        if not isinstance(tool_table, dict):
            doc["tool"] = tomlkit.table()

        doc["tool"]["qv"] = build_qv_toml_table()
        rendered = tomlkit.dumps(doc)
        if not dry_run:
            pyproject_path.write_text(rendered, encoding="utf-8")
        action = "Overwrote" if has_qv and force else "Initialized"
        return (
            True,
            f"{action} [tool.qv] configuration in {pyproject_path}.",
            rendered,
        )

    # pyproject.toml does not exist
    doc = tomlkit.document()
    tool = tomlkit.table()
    tool["qv"] = build_qv_toml_table()
    doc["tool"] = tool
    rendered = tomlkit.dumps(doc)

    if not dry_run:
        project_root.mkdir(parents=True, exist_ok=True)
        pyproject_path.write_text(rendered, encoding="utf-8")

    return (
        True,
        f"Created {pyproject_path} with [tool.qv] configuration.",
        rendered,
    )


def determine_ci_python_version(project_root: Path) -> str:
    """Determine a suitable Python version for CI based on requires-python."""
    default_version = "3.11"
    pyproject_path = project_root / "pyproject.toml"
    if not pyproject_path.exists() or pyproject_path.is_dir():
        return default_version

    try:
        content = pyproject_path.read_text(encoding="utf-8")
        m = re.search(r'requires-python\s*=\s*["\']([^"\']+)["\']', content)
        if m:
            spec = SpecifierSet(m.group(1))
            for candidate in ["3.11", "3.12", "3.10", "3.13", "3.9"]:
                if Version(candidate) in spec:
                    return candidate
    except Exception:
        pass
    return default_version


def generate_github_workflow(project_root: Path) -> str:
    """Generate GitHub Actions workflow content conforming to CIAnalyzer rules CI-001 through CI-006."""
    py_version = determine_ci_python_version(project_root)
    is_uv = (project_root / "uv.lock").exists()

    if is_uv:
        return f"""name: QV Project Health Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

concurrency:
  group: ${{{{ github.workflow }}}}-${{{{ github.ref }}}}
  cancel-in-progress: true

jobs:
  qv-scan:
    name: QV Health Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v5
        with:
          enable-cache: true

      - name: Set up Python
        run: uv python install {py_version}

      - name: Run QV Health Scan
        run: uv run qv scan --ci --github-annotations
"""

    return f"""name: QV Project Health Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

concurrency:
  group: ${{{{ github.workflow }}}}-${{{{ github.ref }}}}
  cancel-in-progress: true

jobs:
  qv-scan:
    name: QV Health Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "{py_version}"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install python-qv

      - name: Run QV Health Scan
        run: qv scan --ci --github-annotations
"""


def init_github_workflow(
    project_root: Path,
    force: bool = False,
    dry_run: bool = False,
) -> tuple[bool, str, str, Path]:
    """Generate .github/workflows/qv.yml workflow.

    Returns:
        (modified, message, workflow_content, workflow_path)
    """
    workflow_dir = project_root / ".github" / "workflows"
    workflow_path = workflow_dir / "qv.yml"
    rendered = generate_github_workflow(project_root)

    if workflow_path.exists():
        if not force:
            return (
                False,
                f"GitHub Actions workflow already exists at {workflow_path}. Use --force to overwrite.",
                workflow_path.read_text(encoding="utf-8") if workflow_path.is_file() else rendered,
                workflow_path,
            )

    if not dry_run:
        workflow_dir.mkdir(parents=True, exist_ok=True)
        workflow_path.write_text(rendered, encoding="utf-8")

    action = "Overwrote" if workflow_path.exists() and force else "Created"
    return (
        True,
        f"{action} GitHub Actions workflow at {workflow_path}.",
        rendered,
        workflow_path,
    )
