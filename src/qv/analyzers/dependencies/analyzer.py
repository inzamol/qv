"""Dependency analyzer implementing DEP-001, DEP-002, DEP-003, DEP-004, DEP-005."""

from __future__ import annotations

import sys

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from qv.core.context import ProjectContext
from qv.core.models import Diagnostic, Evidence, Severity, Suggestion
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

ALL_PYTHON_3_STDLIB = {
    "tomllib",  # Added in Python 3.11
    "zoneinfo",  # Added in Python 3.9
    "wsgiref",
    "concurrent",
    "ctypes",
    "curses",
    "email",
    "html",
    "mimetypes",
    "tarfile",
    "zipfile",
    "gzip",
    "bz2",
    "lzma",
    "venv",
    "ensurepip",
    "trace",
    "tracemalloc",
    "secrets",
    "token",
    "tokenize",
    "profile",
    "cProfile",
    "pstats",
    "timeit",
    "gc",
    "signal",
    "errno",
    "selectors",
    "sched",
    "queue",
    "site",
    "stat",
    "reprlib",
    "copy",
    "copyreg",
    "fnmatch",
    "linecache",
    "posixpath",
    "ntpath",
    "genericpath",
}

# Known Python standard library modules (Python 3.10+)
STDLIB_MODULES = (
    (set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else set())
    | {
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
    | ALL_PYTHON_3_STDLIB
    | PEP594_REMOVED_MODULES
)

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
    "build",
}

KNOWN_IMPORT_TO_PKG: dict[str, str] = {
    "yaml": "pyyaml",
    "cv2": "opencv-python",
    "pil": "pillow",
    "dateutil": "python-dateutil",
    "bs4": "beautifulsoup4",
    "sklearn": "scikit-learn",
    "attr": "attrs",
    "attrs": "attrs",
    "dotenv": "python-dotenv",
    "googleapiclient": "google-api-python-client",
    "jose": "python-jose",
    "jwt": "pyjwt",
    "magic": "python-magic",
    "multipart": "python-multipart",
    "pptx": "python-pptx",
    "docx": "python-docx",
    "serial": "pyserial",
    "slugify": "python-slugify",
    "websocket": "websocket-client",
    "socketio": "python-socketio",
    "engineio": "python-engineio",
    "fitz": "pymupdf",
    "dns": "dnspython",
    "setuptools": "setuptools",
    "pkg_resources": "setuptools",
    "prometheus_client": "prometheus-client",
}

BUILD_TOOLS = {
    "setuptools",
    "wheel",
    "pip",
    "build",
    "flit_core",
    "hatchling",
    "poetry_core",
    "poetry-core",
    "pkg_resources",
    "distutils",
}


class DependencyAnalyzer:
    """Analyzes declared and installed dependencies for conflicts and anomalies."""

    id = "dependencies"
    name = "Dependency Analyzer"
    description = (
        "Checks for dependency conflicts, missing imports, unused packages, and version mismatches."
    )
    rules: tuple[str, ...] = (
        "DEP-001",
        "DEP-002",
        "DEP-003",
        "DEP-004",
        "DEP-005",
    )

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        diagnostics: list[Diagnostic] = []

        # Run individual sub-checks
        diagnostics.extend(self._check_installed_conflicts(context))
        diagnostics.extend(self._check_missing_dependencies(context))
        diagnostics.extend(self._check_unused_dependencies(context))
        diagnostics.extend(self._check_python_compatibility(context))
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
                                if context.package_manager in ("uv", "poetry"):
                                    sugg_exe = context.package_manager
                                    sugg_args = ["add", f"{installed_dep.name}{req.specifier}"]
                                else:
                                    sugg_exe = "pip"
                                    sugg_args = ["install", f"{installed_dep.name}{req.specifier}"]

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
                                            executable=sugg_exe,
                                            args=sugg_args,
                                            command=f"{sugg_exe} {' '.join(sugg_args)}",
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
            local_modules.add(sf.path.stem.lower().replace("-", "_"))
            if sf.module_name:
                for part in sf.module_name.split("."):
                    local_modules.add(part.lower().replace("-", "_"))
            parts = list(sf.relative_path.parts)
            if parts:
                if parts[0] in ("src", "lib") and len(parts) > 1:
                    local_modules.add(parts[1].replace(".py", "").lower().replace("-", "_"))
                local_modules.add(parts[0].replace(".py", "").lower().replace("-", "_"))

        has_build_manifest = any(
            m.name in ("setup.py", "setup.cfg", "pyproject.toml") for m in context.manifest_files
        )

        seen_missing: set[str] = set()

        for imp in context.imports:
            if imp.is_relative or not imp.module_name:
                continue

            top_level = imp.module_name.split(".")[0]
            top_level_norm = top_level.lower().replace("-", "_")
            mapped_pkg = KNOWN_IMPORT_TO_PKG.get(top_level.lower(), top_level.lower()).replace(
                "-", "_"
            )

            if (
                top_level in STDLIB_MODULES
                or top_level in local_modules
                or top_level_norm in local_modules
                or top_level_norm in declared_names
                or top_level.lower() in declared_raw_names
                or mapped_pkg in declared_names
                or mapped_pkg in declared_raw_names
            ):
                continue

            # Check build tools exemption for build/setup files or projects with build manifest
            if top_level_norm in BUILD_TOOLS or mapped_pkg in BUILD_TOOLS:
                if has_build_manifest or imp.source_file.name in (
                    "setup.py",
                    "conftest.py",
                    "conf.py",
                ):
                    continue

            # If it's missing from declared dependencies
            if top_level_norm not in seen_missing and mapped_pkg not in seen_missing:
                seen_missing.add(top_level_norm)
                seen_missing.add(mapped_pkg)
                rel_path = (
                    imp.source_file.relative_to(context.project_root)
                    if imp.source_file.is_relative_to(context.project_root)
                    else imp.source_file
                )

                # Check if this package is provided transitively by a declared dependency
                transitive_provider: str | None = None
                for dep in context.dependencies:
                    dep_dist = context.installed_packages.get(
                        dep.name.lower().replace("-", "_")
                    ) or context.installed_packages.get(dep.name.lower())
                    if dep_dist:
                        for req_str in dep_dist.requires:
                            try:
                                req_name = Requirement(req_str).name.lower().replace("-", "_")
                                if req_name in (top_level_norm, mapped_pkg):
                                    transitive_provider = dep.name
                                    break
                            except Exception:
                                pass
                    if transitive_provider:
                        break

                evidence_list = [
                    Evidence(
                        fact=f"Import statement: `import {imp.module_name}` in {rel_path}:{imp.line_number}",
                        source=str(rel_path),
                    )
                ]
                if transitive_provider:
                    evidence_list.append(
                        Evidence(
                            fact=f"'{top_level}' is currently installed as a transitive dependency via '{transitive_provider}', but is not declared directly.",
                            source=f"{transitive_provider} metadata",
                        )
                    )

                target_manifest = (
                    context.manifest_files[0].name if context.manifest_files else "pyproject.toml"
                )

                if transitive_provider:
                    diag_severity = Severity.WARNING
                    diag_title = f"Undeclared transitive dependency: {top_level}"
                    diag_msg = (
                        f"Module '{top_level}' is imported in {rel_path}:{imp.line_number} and provided "
                        f"transitively by '{transitive_provider}', but is not declared directly in project dependencies."
                    )
                else:
                    diag_severity = Severity.ERROR
                    diag_title = f"Missing dependency: {top_level}"
                    diag_msg = f"Module '{top_level}' is imported in {rel_path}:{imp.line_number} but is not declared in project dependencies."

                if context.package_manager in ("uv", "poetry"):
                    add_exe = context.package_manager
                    add_args = ["add", top_level]
                else:
                    add_exe = "pip"
                    add_args = ["install", top_level]

                diag = Diagnostic(
                    id=rule.id,
                    severity=diag_severity,
                    category=rule.category,
                    title=diag_title,
                    message=diag_msg,
                    evidence=evidence_list,
                    suggestions=[
                        Suggestion(
                            description=f"Add '{top_level}' directly to project dependencies in {target_manifest}.",
                            executable=add_exe,
                            args=add_args,
                            command=f"{add_exe} {' '.join(add_args)}",
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

        imported_top_levels: set[str] = set()
        for imp in context.imports:
            mod_to_check = (
                imp.resolved_module
                if (imp.is_relative and imp.resolved_module)
                else imp.module_name
            )
            if mod_to_check:
                top = mod_to_check.split(".")[0].lower().replace("-", "_")
                imported_top_levels.add(top)
                if top in KNOWN_IMPORT_TO_PKG:
                    imported_top_levels.add(KNOWN_IMPORT_TO_PKG[top].lower().replace("-", "_"))
            for sym in imp.imported_symbols:
                imported_top_levels.add(sym.lower().replace("-", "_"))
                if sym.lower() in KNOWN_IMPORT_TO_PKG:
                    imported_top_levels.add(
                        KNOWN_IMPORT_TO_PKG[sym.lower()].lower().replace("-", "_")
                    )

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
                    title=f"No direct import detected: {dep.name}",
                    message=f"Package '{dep.name}' is declared in {dep.source_file.name}, but no direct import was detected across project source files.",
                    evidence=[
                        Evidence(
                            fact=f"Declared requirement: {dep.name}{dep.specifier} in {dep.source_file.name}",
                            source=str(dep.source_file),
                        ),
                        Evidence(
                            fact="No direct import statements matching this package were found in project source files.",
                            source="AST Import Analysis",
                        ),
                    ],
                    suggestions=[
                        Suggestion(
                            description=f"Verify if '{dep.name}' is used dynamically, as a runtime plugin/driver, or remove it if unused.",
                            executable=context.package_manager
                            if context.package_manager in ("uv", "poetry")
                            else None,
                            args=["remove", dep.name]
                            if context.package_manager in ("uv", "poetry")
                            else [],
                            command=f"{context.package_manager} remove {dep.name}"
                            if context.package_manager in ("uv", "poetry")
                            else None,
                            is_safe=False,
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

    def _check_python_compatibility(self, context: ProjectContext) -> list[Diagnostic]:
        """DEP-004: Check if any package has a Requires-Python constraint incompatible with project Python runtime."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DEP-004")
        if not rule or not context.installed_packages:
            return diagnostics

        try:
            runtime_ver = Version(context.python_runtime.version_str)
        except Exception:
            return diagnostics

        for dist in context.installed_packages.values():
            if not dist.requires_python:
                continue
            try:
                pkg_spec = SpecifierSet(dist.requires_python)
                if not pkg_spec.contains(runtime_ver, prereleases=True):
                    diag = Diagnostic(
                        id=rule.id,
                        severity=rule.default_severity,
                        category=rule.category,
                        title=f"Python compatibility mismatch for {dist.name}",
                        message=f"Package '{dist.name}' requires Python '{dist.requires_python}', which is incompatible with active Python {context.python_runtime.version_str}.",
                        evidence=[
                            Evidence(
                                fact=f"Package {dist.name} requires Python {dist.requires_python}",
                                source=f"{dist.name} metadata",
                            ),
                            Evidence(
                                fact=f"Active Python runtime: {context.python_runtime.version_str}",
                                source="Active Runtime",
                            ),
                        ],
                        suggestions=[
                            Suggestion(
                                description=f"Update Python environment to satisfy '{dist.requires_python}' or install a version of '{dist.name}' compatible with Python {context.python_runtime.version_str}.",
                                is_safe=False,
                            )
                        ],
                        affected_packages=[dist.name],
                        doc_url=rule.doc_url,
                    )
                    diagnostics.append(diag)
            except Exception:
                pass

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
                        if context.package_manager in ("uv", "poetry"):
                            sync_exe = context.package_manager
                            sync_args = ["sync"]
                        else:
                            sync_exe = "pip"
                            sync_args = ["install", "-r", dep.source_file.name]

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
                                    executable=sync_exe,
                                    args=sync_args,
                                    command=f"{sync_exe} {' '.join(sync_args)}",
                                )
                            ],
                            affected_packages=[dep.name],
                            doc_url=rule.doc_url,
                        )
                        diagnostics.append(diag)
                except Exception:
                    pass

        return diagnostics
