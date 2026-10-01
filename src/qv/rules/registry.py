"""Central registry of all supported diagnostic rules."""

from __future__ import annotations

from dataclasses import dataclass

from qv.core.models import Severity


@dataclass(frozen=True)
class RuleDefinition:
    """Metadata for a diagnostic rule."""

    id: str
    category: str
    title: str
    description: str
    default_severity: Severity
    remediation_hint: str
    doc_url: str | None = None


# Stable Registry of rules as defined in docs/rules.md
RULES_CATALOG: dict[str, RuleDefinition] = {
    # Dependency rules
    "DEP-001": RuleDefinition(
        id="DEP-001",
        category="dependency",
        title="Dependency constraint conflict",
        description="Two or more declared or transitive dependencies have incompatible version constraints.",
        default_severity=Severity.ERROR,
        remediation_hint="Upgrade the conflicting package or loosen the version pin to satisfy all requirements.",
        doc_url="https://github.com/inzamol/qv/blob/main/docs/rules.md#dep-001--dependency-constraint-conflict",
    ),
    "DEP-002": RuleDefinition(
        id="DEP-002",
        category="dependency",
        title="Missing dependency declaration",
        description="A third-party package is imported in source code but is not declared in project dependencies.",
        default_severity=Severity.ERROR,
        remediation_hint="Add the missing package to your pyproject.toml or requirements.txt.",
        doc_url="https://github.com/inzamol/qv/blob/main/docs/rules.md#dep-002--missing-dependency-declaration",
    ),
    "DEP-003": RuleDefinition(
        id="DEP-003",
        category="dependency",
        title="Unused declared dependency",
        description="A package is declared as a direct dependency but no imports were detected across project source files.",
        default_severity=Severity.WARNING,
        remediation_hint="Verify if this dependency is needed at runtime or remove it to keep dependencies lean.",
        doc_url="https://github.com/inzamol/qv/blob/main/docs/rules.md#dep-003--unused-declared-dependency",
    ),
    "DEP-004": RuleDefinition(
        id="DEP-004",
        category="dependency",
        title="Python compatibility mismatch",
        description="A package requires a Python version incompatible with the target project runtime.",
        default_severity=Severity.WARNING,
        remediation_hint="Update your target Python version or install a version of the package compatible with your Python runtime.",
        doc_url="https://github.com/inzamol/qv/blob/main/docs/rules.md#dep-004--python-compatibility-mismatch",
    ),
    "DEP-005": RuleDefinition(
        id="DEP-005",
        category="dependency",
        title="Installed/declaration mismatch",
        description="The package version installed in the virtualenv does not match the pinned requirement in project declaration.",
        default_severity=Severity.WARNING,
        remediation_hint="Sync your virtual environment using your package manager (e.g. `uv sync` or `poetry install`).",
        doc_url="https://github.com/inzamol/qv/blob/main/docs/rules.md#dep-005--installeddeclaration-mismatch",
    ),
    "DEP-006": RuleDefinition(
        id="DEP-006",
        category="dependency",
        title="Vulnerable transitive dependency",
        description="A security vulnerability has been identified in a direct or transitive dependency.",
        default_severity=Severity.ERROR,
        remediation_hint="Update the vulnerable dependency or apply vendor security patches.",
        doc_url="https://github.com/inzamol/qv/blob/main/docs/rules.md#dep-006--vulnerable-transitive-dependency",
    ),
    # Environment rules
    "ENV-001": RuleDefinition(
        id="ENV-001",
        category="environment",
        title="Python version drift",
        description="The active Python interpreter version differs from the project's target runtime specification.",
        default_severity=Severity.WARNING,
        remediation_hint="Ensure the virtual environment is built using the configured target Python version.",
        doc_url="https://github.com/inzamol/qv/blob/main/docs/rules.md#env-001--python-version-drift",
    ),
    "ENV-002": RuleDefinition(
        id="ENV-002",
        category="environment",
        title="Docker runtime drift",
        description="The Python version in Dockerfile/docker-compose differs from the project's target runtime.",
        default_severity=Severity.WARNING,
        remediation_hint="Update the base image tag in your Dockerfile to match your project's target Python version.",
        doc_url="https://github.com/inzamol/qv/blob/main/docs/rules.md#env-002--docker-runtime-drift",
    ),
    "ENV-003": RuleDefinition(
        id="ENV-003",
        category="environment",
        title="CI runtime drift",
        description="CI workflow test matrix does not cover or differs from declared project Python versions.",
        default_severity=Severity.WARNING,
        remediation_hint="Align your CI matrix with the Python versions specified in pyproject.toml.",
        doc_url="https://github.com/inzamol/qv/blob/main/docs/rules.md#env-003--ci-runtime-drift",
    ),
    # Import / Architecture rules
    "IMP-001": RuleDefinition(
        id="IMP-001",
        category="architecture",
        title="Circular import detected",
        description="An import cycle exists between two or more modules, which may cause runtime initialization errors.",
        default_severity=Severity.ERROR,
        remediation_hint="Refactor shared dependencies into a separate module or use deferred/lazy imports.",
        doc_url="https://github.com/inzamol/qv/blob/main/docs/rules.md#imp-001--circular-import-detected",
    ),
    "IMP-002": RuleDefinition(
        id="IMP-002",
        category="architecture",
        title="Unresolved local import",
        description="A local module imported in source code could not be resolved on the project's Python path.",
        default_severity=Severity.ERROR,
        remediation_hint="Verify the module name and ensure source directory is marked on the PYTHONPATH or package root.",
        doc_url="https://github.com/inzamol/qv/blob/main/docs/rules.md#imp-002--unresolved-local-import",
    ),
    # Packaging rules
    "PKG-001": RuleDefinition(
        id="PKG-001",
        category="packaging",
        title="Missing package metadata",
        description="Essential packaging metadata (such as project name, version, or description) is missing.",
        default_severity=Severity.WARNING,
        remediation_hint="Provide project name and version in pyproject.toml [project] table.",
        doc_url="https://github.com/inzamol/qv/blob/main/docs/rules.md#pkg-001--missing-package-metadata",
    ),
    "PKG-002": RuleDefinition(
        id="PKG-002",
        category="packaging",
        title="Invalid project configuration",
        description="The project configuration file contains syntax errors or invalid keys.",
        default_severity=Severity.ERROR,
        remediation_hint="Fix configuration syntax to conform to PEP 621 / tool specifications.",
        doc_url="https://github.com/inzamol/qv/blob/main/docs/rules.md#pkg-002--invalid-project-configuration",
    ),
}


def get_rule_definition(rule_id: str) -> RuleDefinition | None:
    """Retrieve rule definition by ID."""
    return RULES_CATALOG.get(rule_id.upper())
