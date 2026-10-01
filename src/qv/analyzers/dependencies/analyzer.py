"""Dependency analyzer implementing DEP-001, DEP-002, DEP-003, DEP-004, DEP-005."""

from __future__ import annotations

import sys

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from qv.core.context import ProjectContext
from qv.core.models import Diagnostic, Evidence, Suggestion
from qv.rules.registry import get_rule_definition

PEP594_REMOVED_MODULES = {
    "distutils",
    "imp",
    "cgi",
    "pipes",
    "asyncore",
    "asynchat",
    "smtpd",
    "crypt",
    "chunk",
    "telnetlib",
    "mailcap",
    "nntplib",
    "audioop",
}

# Known Python standard library modules (Python 3.10+)
STDLIB_MODULES = (
    set(sys.stdlib_module_names)
    if hasattr(sys, "stdlib_module_names")
    else {
        "abc",
        "argparse",
        "ast",
        "asyncio",
        "base64",
        "collections",
        "contextlib",
        "csv",
        "dataclasses",
        "datetime",
        "decimal",
        "difflib",
        "dis",
        "enum",
        "functools",
        "glob",
        "hashlib",
        "http",
        "importlib",
        "inspect",
        "io",
        "itertools",
        "json",
        "logging",
        "math",
        "multiprocessing",
        "os",
        "pathlib",
        "pickle",
        "pprint",
        "random",
        "re",
        "shutil",
        "socket",
        "sqlite3",
        "ssl",
        "string",
        "subprocess",
        "sys",
        "tempfile",
        "threading",
        "time",
        "traceback",
        "typing",
        "unittest",
        "urllib",
        "uuid",
        "warnings",
        "weakref",
        "xml",
        "zipfile",
        "__future__",
    }
) | PEP594_REMOVED_MODULES

# Known tools/packages that may not be imported directly in application code
IGNORED_UNUSED = {
    "pytest",
    "pytest-cov",
    "ruff",
    "black",
    "mypy",
    "pyright",
    "flake8",
    "isort",
    "hatchling",
    "flit",
    "setuptools",
    "wheel",
    "gunicorn",
    "uvicorn",
}


class DependencyAnalyzer:
    """Analyzes declared and installed dependencies for conflicts and anomalies."""

    id = "dependencies"
    name = "Dependency Analyzer"
    description = (
        "Checks for dependency conflicts, missing imports, unused packages, and version mismatches."
    )

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        diagnostics: list[Diagnostic] = []

        # Run individual sub-checks
        diagnostics.extend(self._check_installed_conflicts(context))
        diagnostics.extend(self._check_missing_dependencies(context))
        diagnostics.extend(self._check_unused_dependencies(context))
        diagnostics.extend(self._check_declaration_mismatch(context))

        return diagnostics

    def _check_installed_conflicts(self, context: ProjectContext) -> list[Diagnostic]:
        """DEP-001: Check if any installed package's dependencies conflict with other installed packages."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DEP-001")
        if not rule:
            return diagnostics

        for dist in context.installed_packages.values():
            for req_str in dist.requires:
                try:
                    req = Requirement(req_str)
                    # Ignore marker evaluation failure or unfulfilled markers for other OS/Python
                    if req.marker and not req.marker.evaluate():
                        continue

                    dep_name = req.name.lower()
                    if dep_name in context.installed_packages:
                        installed_dep = context.installed_packages[dep_name]
                        try:
                            dep_ver = Version(installed_dep.version)
                            if req.specifier and not req.specifier.contains(
                                dep_ver, prereleases=True
                            ):
                                diag = Diagnostic(
                                    id=rule.id,
                                    severity=rule.default_severity,
                                    category=rule.category,
                                    title=rule.title,
                                    message=f"{dist.name} requires {req.name}{req.specifier}, but installed is {installed_dep.name} {installed_dep.version}.",
                                    evidence=[
                                        Evidence(
                                            fact=f"{dist.name} declared requirement: {req_str}",
                                            source=f"{dist.name} metadata",
                                        ),
                                        Evidence(
                                            fact=f"Installed {installed_dep.name} version: {installed_dep.version}",
                                            source="Active environment",
                                        ),
                                    ],
                                    suggestions=[
                                        Suggestion(
                                            description=f"Upgrade {dist.name} or pin {installed_dep.name} to {req.specifier}.",
                                            command=f"{context.package_manager} add '{installed_dep.name}{req.specifier}'"
                                            if context.package_manager in ("uv", "poetry")
                                            else f"pip install '{installed_dep.name}{req.specifier}'",
                                        )
                                    ],
                                    affected_packages=[dist.name, installed_dep.name],
                                    doc_url=rule.doc_url,
                                )
                                diagnostics.append(diag)
                        except Exception:
                            pass
                except Exception:
                    pass

        return diagnostics

    def _check_missing_dependencies(self, context: ProjectContext) -> list[Diagnostic]:
        """DEP-002: Check for imported packages not declared in dependencies."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DEP-002")
        if not rule:
            return diagnostics

        declared_names = {d.name.lower().replace("-", "_"): d for d in context.dependencies}
        declared_raw_names = {d.name.lower(): d for d in context.dependencies}

        # Collect local top-level module names
        local_modules = {
            context.project_name.lower().replace("-", "_"),
            context.project_name.lower(),
        }
        for sf in context.source_files:
            parts = sf.relative_path.parts
            if parts:
                if parts[0] in ("src", "lib") and len(parts) > 1:
                    local_modules.add(parts[1].replace(".py", "").lower().replace("-", "_"))
                local_modules.add(parts[0].replace(".py", "").lower().replace("-", "_"))

        seen_missing: set[str] = set()

        for imp in context.imports:
            if imp.is_relative or not imp.module_name:
                continue

            top_level = imp.module_name.split(".")[0]
            top_level_norm = top_level.lower().replace("-", "_")

            if (
                top_level in STDLIB_MODULES
                or top_level in local_modules
                or top_level_norm in local_modules
                or top_level_norm in declared_names
                or top_level.lower() in declared_raw_names
            ):
                continue

            # If it's missing from declared dependencies
            if top_level_norm not in seen_missing:
                seen_missing.add(top_level_norm)
                rel_path = (
                    imp.source_file.relative_to(context.project_root)
                    if imp.source_file.is_relative_to(context.project_root)
                    else imp.source_file
                )
                diag = Diagnostic(
                    id=rule.id,
                    severity=rule.default_severity,
                    category=rule.category,
                    title=f"Missing dependency: {top_level}",
                    message=f"Module '{top_level}' is imported in {rel_path}:{imp.line_number} but is not declared in project dependencies.",
                    evidence=[
                        Evidence(
                            fact=f"Import statement: `import {imp.module_name}` in {rel_path}:{imp.line_number}",
                            source=str(rel_path),
                        )
                    ],
                    suggestions=[
                        Suggestion(
                            description=f"Add '{top_level}' to project dependencies in pyproject.toml.",
                            command=f"{context.package_manager} add {top_level}"
                            if context.package_manager in ("uv", "poetry")
                            else f"pip install {top_level}",
                        )
                    ],
                    affected_packages=[top_level],
                    file=str(rel_path),
                    line=imp.line_number,
                    doc_url=rule.doc_url,
                )
                diagnostics.append(diag)

        return diagnostics

    def _check_unused_dependencies(self, context: ProjectContext) -> list[Diagnostic]:
        """DEP-003: Check for declared direct dependencies that have no detected imports."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DEP-003")
        if not rule or not context.source_files:
            return diagnostics

        imported_top_levels = {
            imp.module_name.split(".")[0].lower().replace("-", "_")
            for imp in context.imports
            if imp.module_name
        }

        for dep in context.dependencies:
            if dep.is_dev:
                continue

            dep_norm = dep.name.lower().replace("-", "_")
            if dep.name.lower() in IGNORED_UNUSED or dep_norm in IGNORED_UNUSED:
                continue

            if dep_norm not in imported_top_levels and dep.name.lower() not in imported_top_levels:
                diag = Diagnostic(
                    id=rule.id,
                    severity=rule.default_severity,
                    category=rule.category,
                    title=f"Unused declared dependency: {dep.name}",
                    message=f"Package '{dep.name}' is declared in {dep.source_file.name} but no imports were detected in project source files.",
                    evidence=[
                        Evidence(
                            fact=f"Declared requirement: {dep.name}{dep.specifier} in {dep.source_file.name}",
                            source=str(dep.source_file),
                        )
                    ],
                    suggestions=[
                        Suggestion(
                            description=f"Remove '{dep.name}' from dependencies if not needed at runtime.",
                            command=f"{context.package_manager} remove {dep.name}"
                            if context.package_manager in ("uv", "poetry")
                            else None,
                        )
                    ],
                    affected_packages=[dep.name],
                    file=str(dep.source_file),
                    line=dep.line_number,
                    confidence=0.85,
                    doc_url=rule.doc_url,
                )
                diagnostics.append(diag)

        return diagnostics

    def _check_declaration_mismatch(self, context: ProjectContext) -> list[Diagnostic]:
        """DEP-005: Check for declared versions that do not match installed versions in active environment."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DEP-005")
        if not rule or not context.installed_packages:
            return diagnostics

        for dep in context.dependencies:
            dep_name_lower = dep.name.lower()
            if dep_name_lower in context.installed_packages and dep.specifier:
                installed = context.installed_packages[dep_name_lower]
                try:
                    spec = SpecifierSet(dep.specifier)
                    installed_ver = Version(installed.version)
                    if not spec.contains(installed_ver, prereleases=True):
                        diag = Diagnostic(
                            id=rule.id,
                            severity=rule.default_severity,
                            category=rule.category,
                            title=f"Installed/declaration mismatch for {dep.name}",
                            message=f"Declared requirement is '{dep.name}{dep.specifier}', but environment has '{installed.name} {installed.version}'.",
                            evidence=[
                                Evidence(
                                    fact=f"Declared specifier: {dep.specifier} in {dep.source_file.name}",
                                    source=str(dep.source_file),
                                ),
                                Evidence(
                                    fact=f"Installed version in environment: {installed.version}",
                                    source="Active environment",
                                ),
                            ],
                            suggestions=[
                                Suggestion(
                                    description="Synchronize the virtual environment with project manifest.",
                                    command=f"{context.package_manager} sync"
                                    if context.package_manager in ("uv", "poetry")
                                    else f"pip install -r {dep.source_file.name}",
                                )
                            ],
                            affected_packages=[dep.name],
                            doc_url=rule.doc_url,
                        )
                        diagnostics.append(diag)
                except Exception:
                    pass

        return diagnostics
