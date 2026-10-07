"""CLI tests for 'qv architecture' and 'qv architecture graph' commands."""

import json
from pathlib import Path

from click.testing import CliRunner

from qv.cli.main import cli


def _setup_layered_repo(tmp_path: Path) -> Path:
    """Create a minimal project repository with layered structure and pyproject.toml."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "arch-demo"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )

    api_dir = tmp_path / "api"
    api_dir.mkdir(parents=True, exist_ok=True)
    (api_dir / "__init__.py").write_text("", encoding="utf-8")
    (api_dir / "routes.py").write_text(
        "from services.user_service import get_user\nfrom database.db import connect_db\n",
        encoding="utf-8",
    )

    srv_dir = tmp_path / "services"
    srv_dir.mkdir(parents=True, exist_ok=True)
    (srv_dir / "__init__.py").write_text("", encoding="utf-8")
    (srv_dir / "user_service.py").write_text(
        "from database.db import connect_db\ndef get_user(): pass\n",
        encoding="utf-8",
    )

    db_dir = tmp_path / "database"
    db_dir.mkdir(parents=True, exist_ok=True)
    (db_dir / "__init__.py").write_text("", encoding="utf-8")
    (db_dir / "db.py").write_text("def connect_db(): pass\n", encoding="utf-8")

    return tmp_path


def test_cli_architecture_scan_default(tmp_path: Path):
    repo_path = _setup_layered_repo(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["architecture", str(repo_path)])
    assert result.exit_code == 0
    assert (
        "ARC-001" in result.output
        or "Architecture layer violation" in result.output
        or "Passed" in result.output
    )


def test_cli_architecture_graph_subcommand(tmp_path: Path):
    repo_path = _setup_layered_repo(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["architecture", "graph", str(repo_path)])
    assert result.exit_code == 0
    assert "Architecture Graph" in result.output or "Dependency Flow" in result.output
    assert "API" in result.output
    assert "Services" in result.output
    assert "Database" in result.output


def test_cli_architecture_graph_flag(tmp_path: Path):
    repo_path = _setup_layered_repo(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["architecture", str(repo_path), "--graph"])
    assert result.exit_code == 0
    assert "Architecture Graph" in result.output or "Dependency Flow" in result.output
    assert "API" in result.output


def test_cli_architecture_graph_json_format(tmp_path: Path):
    repo_path = _setup_layered_repo(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["architecture", "graph", str(repo_path), "--json"])
    assert result.exit_code == 0

    data = json.loads(result.output)
    assert data["project_name"] == "arch-demo"
    assert "components" in data
    assert "edges" in data
    assert "violations" in data


def test_cli_architecture_graph_mermaid_format(tmp_path: Path):
    repo_path = _setup_layered_repo(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["architecture", "graph", str(repo_path), "--format", "mermaid"])
    assert result.exit_code == 0
    assert "flowchart TD" in result.output
    assert "ArchitectureMap" in result.output


def test_cli_architecture_graph_dot_format(tmp_path: Path):
    repo_path = _setup_layered_repo(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["architecture", "graph", str(repo_path), "--format", "dot"])
    assert result.exit_code == 0
    assert "digraph ArchitectureMap" in result.output


def test_cli_architecture_graph_ascii_format(tmp_path: Path):
    repo_path = _setup_layered_repo(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["architecture", "graph", str(repo_path), "--format", "ascii"])
    assert result.exit_code == 0
    assert "API" in result.output
    assert "Services" in result.output
    assert "Database" in result.output


def test_cli_architecture_graph_output_file(tmp_path: Path):
    repo_path = _setup_layered_repo(tmp_path)
    out_file = tmp_path / "arch_diagram.md"
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["architecture", "graph", str(repo_path), "--format", "mermaid", "-o", str(out_file)],
    )
    assert result.exit_code == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "flowchart TD" in content


def test_cli_architecture_graph_strict_mode(tmp_path: Path):
    repo_path = _setup_layered_repo(tmp_path)
    runner = CliRunner()

    # In our sample repo, API -> Database directly is a layer violation
    result = runner.invoke(cli, ["architecture", "graph", str(repo_path), "--strict"])
    assert result.exit_code == 1
