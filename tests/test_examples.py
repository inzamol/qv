"""End-to-end integration tests on example test projects."""

from pathlib import Path

from qv.core.config import QvConfig
from qv.core.engine import AnalysisEngine
from qv.core.project import ProjectDiscovery
from qv.remediation.engine import RemediationEngine


def test_missing_dependencies_example():
    root = Path(__file__).parent.parent / "examples" / "missing_dependencies"
    config = QvConfig()
    context = ProjectDiscovery(root=root, config=config).discover_context()
    result = AnalysisEngine(config=config).run(context)

    rule_ids = [d.id for d in result.diagnostics]
    assert "DEP-002" in rule_ids

    # Verify remediation plans to add missing packages
    plan = RemediationEngine(project_root=root).plan_fixes(result)
    added_pkgs = {a.metadata.get("package") for a in plan.actions}
    assert "httpx" in added_pkgs
    assert "pydantic" in added_pkgs


def test_unused_dependencies_example():
    root = Path(__file__).parent.parent / "examples" / "unused_dependencies"
    config = QvConfig()
    context = ProjectDiscovery(root=root, config=config).discover_context()
    result = AnalysisEngine(config=config).run(context)

    rule_ids = [d.id for d in result.diagnostics]
    assert "DEP-003" in rule_ids

    # Verify remediation plans to remove unused packages
    plan = RemediationEngine(project_root=root).plan_fixes(result)
    removed_pkgs = {a.metadata.get("package") for a in plan.actions}
    assert "requests" in removed_pkgs
    assert "pyyaml" in removed_pkgs


def test_circular_imports_example():
    root = Path(__file__).parent.parent / "examples" / "circular_imports"
    config = QvConfig()
    context = ProjectDiscovery(root=root, config=config).discover_context()
    result = AnalysisEngine(config=config).run(context)

    rule_ids = [d.id for d in result.diagnostics]
    assert "IMP-001" in rule_ids


def test_unresolved_imports_example():
    root = Path(__file__).parent.parent / "examples" / "unresolved_imports"
    config = QvConfig()
    context = ProjectDiscovery(root=root, config=config).discover_context()
    result = AnalysisEngine(config=config).run(context)

    rule_ids = [d.id for d in result.diagnostics]
    assert "IMP-002" in rule_ids


def test_missing_metadata_example():
    root = Path(__file__).parent.parent / "examples" / "missing_metadata"
    config = QvConfig()
    context = ProjectDiscovery(root=root, config=config).discover_context()
    result = AnalysisEngine(config=config).run(context)

    rule_ids = [d.id for d in result.diagnostics]
    assert "PKG-001" in rule_ids


def test_environment_drift_example():
    root = Path(__file__).parent.parent / "examples" / "environment_drift"
    config = QvConfig()
    context = ProjectDiscovery(root=root, config=config).discover_context()
    result = AnalysisEngine(config=config).run(context)

    rule_ids = [d.id for d in result.diagnostics]
    assert "ENV-002" in rule_ids
    assert "ENV-003" in rule_ids


def test_all_in_one_unhealthy_example():
    root = Path(__file__).parent.parent / "examples" / "all_in_one_unhealthy"
    config = QvConfig()
    context = ProjectDiscovery(root=root, config=config).discover_context()
    result = AnalysisEngine(config=config).run(context)

    rule_ids = {d.id for d in result.diagnostics}
    assert "DEP-002" in rule_ids
    assert "DEP-003" in rule_ids
    assert "IMP-001" in rule_ids
    assert "ENV-002" in rule_ids


def test_dead_modules_example():
    root = Path(__file__).parent.parent / "examples" / "dead_modules"
    config = QvConfig()
    context = ProjectDiscovery(root=root, config=config).discover_context()
    result = AnalysisEngine(config=config).run(context)

    rule_ids = [d.id for d in result.diagnostics]
    assert "IMP-003" in rule_ids
    orphan_diag = next(d for d in result.diagnostics if d.id == "IMP-003")
    assert "unused_legacy_module" in orphan_diag.message


def test_deprecated_stdlib_example():
    root = Path(__file__).parent.parent / "examples" / "deprecated_stdlib"
    config = QvConfig()
    context = ProjectDiscovery(root=root, config=config).discover_context()
    result = AnalysisEngine(config=config).run(context)

    rule_ids = [d.id for d in result.diagnostics]
    assert "IMP-004" in rule_ids
    assert any("distutils" in d.message for d in result.diagnostics)
    assert any("imp" in d.message for d in result.diagnostics)
