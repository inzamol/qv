"""Tests for TreeVisualizer and qv tree CLI command."""

from pathlib import Path

from click.testing import CliRunner
from qv.cli.main import cli
from qv.core.config import QvConfig
from qv.core.project import ProjectDiscovery
from qv.visualizers.tree import TreeVisualizer


def test_tree_visualizer_dependencies():
    root = Path(__file__).parent.parent / "examples" / "missing_dependencies"
    config = QvConfig()
    context = ProjectDiscovery(root=root, config=config).discover_context()

    visualizer = TreeVisualizer(context=context)
    tree = visualizer.build_dependency_tree(max_depth=3)
    assert tree is not None
    assert "missing-deps-example" in str(tree.label)


def test_tree_visualizer_imports_with_cycles():
    root = Path(__file__).parent.parent / "examples" / "circular_imports"
    config = QvConfig()
    context = ProjectDiscovery(root=root, config=config).discover_context()

    visualizer = TreeVisualizer(context=context)
    tree = visualizer.build_import_tree(max_depth=5)
    assert tree is not None
    assert "circular-imports-example" in str(tree.label)


def test_tree_visualizer_to_dict():
    root = Path(__file__).parent.parent / "examples" / "unused_dependencies"
    config = QvConfig()
    context = ProjectDiscovery(root=root, config=config).discover_context()

    visualizer = TreeVisualizer(context=context)
    data = visualizer.to_dict()
    assert data["project_name"] == "unused-deps-example"
    assert len(data["dependencies"]) == 3


def test_cli_tree_command():
    root = Path(__file__).parent.parent / "examples" / "all_in_one_unhealthy"
    runner = CliRunner()
    result = runner.invoke(cli, ["tree", str(root)])
    assert result.exit_code == 0
    assert "Dependency Hierarchy" in result.output
    assert "Internal Module Import Architecture" in result.output


def test_cli_tree_json_output():
    root = Path(__file__).parent.parent / "examples" / "missing_dependencies"
    runner = CliRunner()
    result = runner.invoke(cli, ["tree", str(root), "--json"])
    assert result.exit_code == 0
    assert '"project_name": "missing-deps-example"' in result.output


def test_cli_graph_alias():
    root = Path(__file__).parent.parent / "examples" / "circular_imports"
    runner = CliRunner()
    result = runner.invoke(cli, ["graph", str(root), "--imports"])
    assert result.exit_code == 0
    assert "Internal Module Import Architecture" in result.output
