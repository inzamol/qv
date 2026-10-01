"""Security analyzer implementing DEP-006 (Vulnerable transitive/direct dependencies)."""

from __future__ import annotations

from qv.analyzers.security.lockfile_parser import LockfileParser
from qv.analyzers.security.osv_client import OsvClient
from qv.core.context import ProjectContext
from qv.core.models import Diagnostic, Evidence, Suggestion
from qv.rules.registry import get_rule_definition


class SecurityAnalyzer:
    """Audits lockfiles and resolved packages for known CVEs and vulnerabilities."""

    id = "security"
    name = "Security & Vulnerability Analyzer"
    description = (
        "Audits lockfiles and dependencies against OSV.dev advisory database for known CVEs."
    )

    def __init__(self, osv_client: OsvClient | None = None) -> None:
        self.osv_client = osv_client or OsvClient()

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DEP-006")
        if not rule:
            return diagnostics

        # Skip if offline mode configured
        if context.config.get("offline", False):
            return diagnostics

        # Parse resolved dependencies from lockfile or environment
        resolved_packages = LockfileParser.parse_context(context)
        if not resolved_packages:
            return diagnostics

        pkg_tuples = [(p.name, p.version) for p in resolved_packages]
        vulnerabilities_by_pkg = self.osv_client.query_packages(pkg_tuples)

        for pkg in resolved_packages:
            key = (pkg.name.lower(), pkg.version)
            vulns = vulnerabilities_by_pkg.get(key, [])
            if not vulns:
                continue

            rel_file = (
                pkg.source_file.relative_to(context.project_root)
                if pkg.source_file and pkg.source_file.is_relative_to(context.project_root)
                else (str(pkg.source_file) if pkg.source_file else "environment")
            )

            for vuln in vulns:
                alias_str = f" ({', '.join(vuln.aliases)})" if vuln.aliases else ""
                dep_type = "direct" if pkg.is_direct else "transitive"

                # Suggestions for upgrade
                suggestions: list[Suggestion] = []
                if vuln.fixed_versions:
                    latest_fix = vuln.fixed_versions[-1]
                    suggestions.append(
                        Suggestion(
                            description=f"Upgrade '{pkg.name}' to version >={latest_fix} to remediate this vulnerability.",
                            command=f"uv add '{pkg.name}>={latest_fix}'"
                            if context.package_manager == "uv"
                            else f"pip install --upgrade '{pkg.name}>={latest_fix}'",
                            is_safe=True,
                        )
                    )
                else:
                    suggestions.append(
                        Suggestion(
                            description=f"Review advisory {vuln.advisory_url} and upgrade '{pkg.name}' once a patch is released.",
                            is_safe=False,
                        )
                    )

                evidence_items = [
                    Evidence(
                        fact=f"Vulnerable {dep_type} package: {pkg.name}=={pkg.version}",
                        source=str(rel_file),
                    ),
                    Evidence(
                        fact=f"Advisory ID: {vuln.id}{alias_str}",
                        source="OSV.dev Advisory Database",
                    ),
                ]

                if vuln.fixed_versions:
                    evidence_items.append(
                        Evidence(
                            fact=f"Fixed in versions: {', '.join(vuln.fixed_versions)}",
                            source="Security Advisory",
                        )
                    )

                diagnostics.append(
                    Diagnostic(
                        id=rule.id,
                        severity=rule.default_severity,
                        category=rule.category,
                        title=f"Security vulnerability in {pkg.name} ({vuln.id})",
                        message=f"{vuln.summary} Affects {pkg.name}=={pkg.version}.",
                        affected_packages=[pkg.name],
                        evidence=evidence_items,
                        suggestions=suggestions,
                        file=str(rel_file),
                        doc_url=vuln.advisory_url or rule.doc_url,
                    )
                )

        return diagnostics
