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


def test_vulnerable_dependencies_example():
    root = Path(__file__).parent.parent / "examples" / "vulnerable_dependencies"
    config = QvConfig()
    context = ProjectDiscovery(root=root, config=config).discover_context()

    # Provide mock osv client or run live if online
    from unittest.mock import MagicMock

    from qv.analyzers.security.analyzer import SecurityAnalyzer
    from qv.analyzers.security.osv_client import Vulnerability

    mock_osv = MagicMock()
    mock_osv.query_packages.return_value = {
        ("jinja2", "2.11.2"): [
            Vulnerability(
                id="GHSA-j7hp-h8jx-5ppr",
                package_name="jinja2",
                installed_version="2.11.2",
                summary="Jinja2 HTML injection vulnerability",
                details="Details",
                aliases=("CVE-2024-22195",),
                fixed_versions=("3.1.3",),
                advisory_url="https://github.com/advisories/GHSA-j7hp-h8jx-5ppr",
            )
        ]
    }

    engine = AnalysisEngine(
        config=config,
        analyzers=[SecurityAnalyzer(osv_client=mock_osv)],
    )
    result = engine.run(context)

    rule_ids = [d.id for d in result.diagnostics]
    assert "DEP-006" in rule_ids
    vuln_diag = next(d for d in result.diagnostics if d.id == "DEP-006")
    assert "jinja2" in vuln_diag.affected_packages
    assert "GHSA-j7hp-h8jx-5ppr" in vuln_diag.title
