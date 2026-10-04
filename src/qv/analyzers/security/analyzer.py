"""Security analyzer implementing DEP-006 (Vulnerable transitive/direct dependencies)."""

from __future__ import annotations

from qv.analyzers.security.lockfile_parser import LockfileParser
from qv.analyzers.security.osv_client import OsvClient, OsvUnavailableError
from qv.core.context import ProjectContext
from qv.core.models import AnalyzerStatus, Diagnostic, Evidence, Severity, Suggestion
from qv.rules.registry import get_rule_definition


class SecurityAnalyzer:
    """Audits lockfiles and resolved packages for known CVEs and vulnerabilities."""

    id = "security"
    name = "Security & Vulnerability Analyzer"
    description = (
        "Audits lockfiles and dependencies against OSV.dev advisory database for known CVEs."
    )
    rules: tuple[str, ...] = ("DEP-006",)

    def __init__(self, osv_client: OsvClient | None = None) -> None:
        self.osv_client = osv_client or OsvClient()
        self.status: AnalyzerStatus = AnalyzerStatus.OK

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        diagnostics: list[Diagnostic] = []
        self.status = AnalyzerStatus.OK
        rule = get_rule_definition("DEP-006")
        if not rule:
            return diagnostics

        # Skip if offline mode configured
        if context.config.get("offline", False):
            self.status = AnalyzerStatus.SKIPPED
            return diagnostics

        # Parse resolved dependencies from lockfile or environment
        resolved_packages = LockfileParser.parse_context(context)
        if not resolved_packages:
            return diagnostics

        pkg_tuples = [(p.name, p.version) for p in resolved_packages]
        try:
            vulnerabilities_by_pkg = self.osv_client.query_packages(pkg_tuples)
        except OsvUnavailableError as exc:
            self.status = AnalyzerStatus.UNKNOWN
            rule_sec = get_rule_definition("SEC-001")
            return [
                Diagnostic(
                    id="SEC-001" if rule_sec else "DEP-006",
                    severity=rule_sec.default_severity if rule_sec else Severity.WARNING,
                    category="security",
                    title="Security analysis unavailable",
                    message="Security analysis unavailable (Status: UNKNOWN).",
                    evidence=[
                        Evidence(
                            fact="Could not query OSV.dev advisory database (network unreachable or blocked)",
                            source="OSV.dev API",
                        ),
                        Evidence(
                            fact=f"Error: {exc}",
                            source="OsvClient",
                        ),
                    ],
                    suggestions=[
                        Suggestion(
                            description="Check internet connectivity or run with --offline to skip vulnerability checks.",
                            is_safe=True,
                        )
                    ],
                    metadata={"status": "UNKNOWN", "error": str(exc)},
                    doc_url=rule_sec.doc_url if rule_sec else None,
                )
            ]

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
                    if context.package_manager == "uv":
                        executable = "uv"
                        args = ["add", f"{pkg.name}>={latest_fix}"]
                    else:
                        executable = "pip"
                        args = ["install", "--upgrade", f"{pkg.name}>={latest_fix}"]
                    suggestions.append(
                        Suggestion(
                            description=f"Upgrade '{pkg.name}' to version >={latest_fix} to remediate this vulnerability.",
                            executable=executable,
                            args=args,
                            command=f"{executable} {' '.join(args)}",
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
