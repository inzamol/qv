"""Packaging analyzer implementing PKG-001 and PKG-002."""

from __future__ import annotations

import sys

from qv.core.context import ProjectContext
from qv.core.models import Diagnostic, Evidence, Suggestion
from qv.rules.registry import get_rule_definition

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


class PackagingAnalyzer:
    """Analyzes pyproject.toml and packaging metadata for validity and completeness."""

    id = "packaging"
    name = "Packaging Analyzer"
    description = (
        "Checks pyproject.toml and project metadata for PEP 621 compliance and completeness."
    )

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        diagnostics: list[Diagnostic] = []
        pyproject_path = context.project_root / "pyproject.toml"

        if not pyproject_path.exists():
            return diagnostics

        try:
            with open(pyproject_path, "rb") as f:
                data = tomllib.load(f)
        except Exception as e:
            rule_pkg002 = get_rule_definition("PKG-002")
            if rule_pkg002:
                diagnostics.append(
                    Diagnostic(
                        id=rule_pkg002.id,
                        severity=rule_pkg002.default_severity,
                        category=rule_pkg002.category,
                        title=rule_pkg002.title,
                        message=f"Failed to parse pyproject.toml: {e}",
                        evidence=[
                            Evidence(
                                fact=str(e),
                                source="pyproject.toml",
                            )
                        ],
                        suggestions=[
                            Suggestion(
                                description="Check TOML syntax in pyproject.toml for missing quotes, brackets, or invalid keys.",
                            )
                        ],
                        file="pyproject.toml",
                        doc_url=rule_pkg002.doc_url,
                    )
                )
            return diagnostics

        # Check PKG-001: Missing metadata
        rule_pkg001 = get_rule_definition("PKG-001")
        if rule_pkg001:
            project_table = data.get("project")
            poetry_table = data.get("tool", {}).get("poetry")

            if project_table is None and poetry_table is None:
                diagnostics.append(
                    Diagnostic(
                        id=rule_pkg001.id,
                        severity=rule_pkg001.default_severity,
                        category=rule_pkg001.category,
                        title="Missing [project] metadata in pyproject.toml",
                        message="pyproject.toml does not contain a standard PEP 621 [project] table or tool metadata table.",
                        evidence=[
                            Evidence(
                                fact="Neither [project] nor [tool.poetry] table found in pyproject.toml",
                                source="pyproject.toml",
                            )
                        ],
                        suggestions=[
                            Suggestion(
                                description="Add a [project] table with name, version, and dependencies.",
                            )
                        ],
                        file="pyproject.toml",
                        doc_url=rule_pkg001.doc_url,
                    )
                )
            elif project_table is not None:
                if not project_table.get("name"):
                    diagnostics.append(
                        Diagnostic(
                            id=rule_pkg001.id,
                            severity=rule_pkg001.default_severity,
                            category=rule_pkg001.category,
                            title="Missing project name in [project] table",
                            message="[project] table in pyproject.toml is missing the required 'name' field.",
                            evidence=[
                                Evidence(
                                    fact="'name' field is missing or empty in [project]",
                                    source="pyproject.toml",
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description='Add name = "my-project" to [project].',
                                )
                            ],
                            file="pyproject.toml",
                            doc_url=rule_pkg001.doc_url,
                        )
                    )

        return diagnostics
