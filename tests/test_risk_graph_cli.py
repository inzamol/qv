"""Unit tests for the risk graph command paths, isolated from environment discovery."""

import importlib
import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest
from click.testing import CliRunner
from rich.tree import Tree

from qv.analyzers.dependencies.analyzer import DependencyAnalyzer
from qv.cli.main import cli
from qv.core.config import QvConfig
from qv.core.context import ProjectContext
from qv.core.models import Diagnostic, ScanResult, Severity
from qv.core.project import Project
from qv.visualizers.risk_graph import DependencyRiskGraph

# qv.cli exports a function named main, so resolve the module explicitly.
cli_module = importlib.import_module("qv.cli.main")


@pytest.fixture
def project(dummy_context: ProjectContext, monkeypatch: pytest.MonkeyPatch) -> Project:
    project = Project(dummy_context.project_root, QvConfig(), dummy_context)
    monkeypatch.setattr(cli_module, "load_project", Mock(return_value=project))
    return project


@pytest.fixture
def scan_result(project: Project) -> ScanResult:
    return ScanResult.create(
        project_name=project.context.project_name,
        project_path=str(project.root),
        python_version="3.12.0",
        package_manager="uv",
        diagnostics=[
            Diagnostic(
                id="DEP-001",
                severity=Severity.ERROR,
                category="dependencies",
                title="Dependency constraint conflict",
                message="Installed version violates the declared constraint",
                affected_packages=["click"],
            )
        ],
    )


@pytest.fixture
def engine(scan_result: ScanResult, monkeypatch: pytest.MonkeyPatch) -> Mock:
    engine = Mock()
    engine.return_value.run.return_value = scan_result
    monkeypatch.setattr(cli_module, "AnalysisEngine", engine)
    return engine


@pytest.mark.parametrize(
    ("command", "options"),
    [
        ("dependency", ["--graph"]),
        ("dependency", ["--risk", "HIGH"]),
        ("tree", ["--risk"]),
        ("graph", ["-r"]),
    ],
)
def test_graph_json_exports_metadata_despite_blocking_diagnostics(
    command: str, options: list[str], project: Project, engine: Mock
) -> None:
    result = CliRunner().invoke(cli, [command, str(project.root), *options, "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["project_name"] == project.context.project_name
    assert data["direct_count"] == data["installed_count"] == data["total_dependencies"] == 1
    node = data["nodes"][0]
    assert node["name"] == "click"
    assert node["risk_level"] == "high"
    assert node["risk_reasons"] == ["Dependency version constraint conflict"]
    engine.return_value.run.assert_called_once_with(project.context)
    assert engine.call_args.kwargs["config"] is project.config
    analyzers = engine.call_args.kwargs["analyzers"]
    assert len(analyzers) == 1
    assert isinstance(analyzers[0], DependencyAnalyzer)


@pytest.mark.parametrize(
    ("command", "options", "expected"),
    [
        ("dependency", ["--graph"], {"annotate": True, "risk_filter": None, "max_depth": 5}),
        (
            "dependency",
            ["-r", "HIGH", "-L", "2", "--no-annotate"],
            {"annotate": False, "risk_filter": "high", "max_depth": 2},
        ),
        ("tree", ["--risk", "--depth", "3"], {"annotate": True, "max_depth": 3}),
        ("graph", ["-r", "-L", "1"], {"annotate": True, "max_depth": 1}),
    ],
)
def test_graph_options_reach_tree_renderer(
    command: str,
    options: list[str],
    expected: dict[str, object],
    project: Project,
    engine: Mock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    build_tree = Mock(return_value=Tree("rendered graph"))
    monkeypatch.setattr(DependencyRiskGraph, "build_tree", build_tree)
    result = CliRunner().invoke(cli, [command, str(project.root), *options])
    assert result.exit_code == 0, result.output
    assert "Dependency Risk & Usage Graph" in result.output
    assert "rendered graph" in result.output
    build_tree.assert_called_once_with(**expected)


@pytest.mark.parametrize("blocking", [True, False])
def test_dependency_json_without_graph_is_scan_result(
    project: Project, scan_result: ScanResult, engine: Mock, blocking: bool
) -> None:
    if not blocking:
        scan_result = ScanResult.create(
            project_name=project.context.project_name,
            project_path=str(project.root),
            python_version="3.12.0",
            package_manager="uv",
            diagnostics=[],
        )
        engine.return_value.run.return_value = scan_result
    result = CliRunner().invoke(cli, ["dependency", str(project.root), "--json"])
    assert result.exit_code == (1 if blocking else 0), result.output
    assert json.loads(result.output) == scan_result.model_dump(mode="json")


@pytest.mark.parametrize("risk", ["all", "critical", "high", "medium", "low", "healthy"])
def test_risk_option_alone_activates_graph(risk: str, project: Project, engine: Mock) -> None:
    result = CliRunner().invoke(cli, ["dependency", str(project.root), "--risk", risk])
    assert result.exit_code == 0, result.output
    assert "Dependency Risk & Usage Graph" in result.output
    assert ("click" in result.output) is (risk in {"all", "high"})


@pytest.mark.parametrize("options", [["--risk", "unknown"], ["--graph", "--depth", "bad"]])
def test_invalid_graph_option_fails_before_analysis(
    tmp_path: Path, options: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    load_project = Mock()
    monkeypatch.setattr(cli_module, "load_project", load_project)
    result = CliRunner().invoke(cli, ["dependency", str(tmp_path), *options])
    assert result.exit_code == 2
    assert "Invalid value" in result.output
    load_project.assert_not_called()


@pytest.mark.parametrize("command", ["tree", "graph"])
def test_risk_mode_takes_precedence_over_legacy_tree_flags(
    command: str, project: Project, engine: Mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    legacy_visualizer = Mock()
    monkeypatch.setattr(cli_module, "TreeVisualizer", legacy_visualizer)
    result = CliRunner().invoke(
        cli, [command, str(project.root), "--risk", "--imports", "--dependencies", "--json"]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["nodes"][0]["risk_level"] == "high"
    legacy_visualizer.assert_not_called()


def test_compact_graph_preserves_risk_badge_and_omits_metadata(
    project: Project, engine: Mock
) -> None:
    result = CliRunner().invoke(cli, ["dependency", str(project.root), "-g", "--no-annotate"])
    assert result.exit_code == 0, result.output
    assert "click" in result.output
    assert "HIGH RISK" in result.output
    for label in ("Type:", "Import:", "Role:", "Assessment:"):
        assert label not in result.output


def test_graph_json_with_empty_project(project: Project, engine: Mock) -> None:
    project.context = replace(project.context, dependencies=(), installed_packages={})
    result = CliRunner().invoke(cli, ["dependency", str(project.root), "--graph", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["nodes"] == []
    assert data["direct_count"] == data["installed_count"] == data["total_dependencies"] == 0
