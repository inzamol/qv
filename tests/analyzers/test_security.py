"""Tests for SecurityAnalyzer (DEP-006) and OsvClient."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from qv.analyzers.security.analyzer import SecurityAnalyzer
from qv.analyzers.security.osv_client import OsvClient, Vulnerability
from qv.core.context import (
    CIConfig,
    DependencyDeclaration,
    DockerConfig,
    InstalledDistribution,
    ProjectContext,
    PythonRuntime,
)
from qv.core.models import Severity


def test_osv_client_query_parsing():
    client = OsvClient()
    mock_response_data = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-j7hp-h8jx-5ppr",
                        "summary": "Jinja2 vulnerable to HTML attribute injection",
                        "details": "In Jinja2 before 3.1.3, xmlattr filter is vulnerable.",
                        "aliases": ["CVE-2024-22195"],
                        "affected": [
                            {
                                "package": {"name": "jinja2", "ecosystem": "PyPI"},
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [
                                            {"introduced": "0"},
                                            {"fixed": "3.1.3"},
                                        ],
                                    }
                                ],
                            }
                        ],
                        "references": [
                            {
                                "type": "ADVISORY",
                                "url": "https://github.com/advisories/GHSA-j7hp-h8jx-5ppr",
                            }
                        ],
                    }
                ]
            }
        ]
    }

    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(mock_response_data).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = client.query_packages([("jinja2", "2.11.2")])

    assert ("jinja2", "2.11.2") in res
    vulns = res[("jinja2", "2.11.2")]
    assert len(vulns) == 1
    v = vulns[0]
    assert v.id == "GHSA-j7hp-h8jx-5ppr"
    assert "CVE-2024-22195" in v.aliases
    assert v.fixed_versions == ("3.1.3",)
    assert v.advisory_url == "https://github.com/advisories/GHSA-j7hp-h8jx-5ppr"


def test_security_analyzer_generates_diagnostics(tmp_path: Path):
    runtime = PythonRuntime(version_str="3.11.0", major=3, minor=11, micro=0)
    context = ProjectContext(
        project_root=tmp_path,
        project_name="vulnerable_app",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(),
        lock_files=(),
        dependencies=(
            DependencyDeclaration(
                name="jinja2",
                specifier="==2.11.2",
                source_file=tmp_path / "pyproject.toml",
            ),
        ),
        installed_packages={
            "jinja2": InstalledDistribution(name="jinja2", version="2.11.2"),
        },
        source_files=(),
        imports=(),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
    )

    mock_osv = MagicMock()
    mock_osv.query_packages.return_value = {
        ("jinja2", "2.11.2"): [
            Vulnerability(
                id="GHSA-j7hp-h8jx-5ppr",
                package_name="jinja2",
                installed_version="2.11.2",
                summary="Jinja2 HTML injection vulnerability",
                details="Detailed description",
                aliases=("CVE-2024-22195",),
                fixed_versions=("3.1.3",),
                advisory_url="https://github.com/advisories/GHSA-j7hp-h8jx-5ppr",
            )
        ]
    }

    analyzer = SecurityAnalyzer(osv_client=mock_osv)
    diagnostics = analyzer.analyze(context)

    assert len(diagnostics) == 1
    d = diagnostics[0]
    assert d.id == "DEP-006"
    assert d.severity == Severity.ERROR
    assert "jinja2" in d.affected_packages
    assert "CVE-2024-22195" in d.evidence[1].fact
    assert any("3.1.3" in s.description for s in d.suggestions)


def test_security_analyzer_skips_when_offline(tmp_path: Path):
    runtime = PythonRuntime(version_str="3.11.0", major=3, minor=11, micro=0)
    context = ProjectContext(
        project_root=tmp_path,
        project_name="vulnerable_app",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(),
        lock_files=(),
        dependencies=(),
        installed_packages={
            "jinja2": InstalledDistribution(name="jinja2", version="2.11.2"),
        },
        source_files=(),
        imports=(),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
        config={"offline": True},
    )

    mock_osv = MagicMock()
    analyzer = SecurityAnalyzer(osv_client=mock_osv)
    diagnostics = analyzer.analyze(context)

    assert len(diagnostics) == 0
    mock_osv.query_packages.assert_not_called()
