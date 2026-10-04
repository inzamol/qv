"""Environment analyzer implementing ENV-001, ENV-002, ENV-003."""

from __future__ import annotations

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from qv.core.context import ProjectContext
from qv.core.models import Diagnostic, Evidence, Suggestion
from qv.rules.registry import get_rule_definition


class EnvironmentAnalyzer:
    """Analyzes runtime environments, Dockerfiles, and CI matrices for drift."""

    id = "environment"
    name = "Environment Analyzer"
    description = (
        "Checks for Python runtime drift, Docker runtime drift, and CI test matrix mismatches."
    )
    rules: tuple[str, ...] = ("ENV-001", "ENV-002", "ENV-003")

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        diagnostics: list[Diagnostic] = []

        diagnostics.extend(self._check_python_version_drift(context))
        diagnostics.extend(self._check_docker_drift(context))
        diagnostics.extend(self._check_ci_drift(context))

        return diagnostics

    def _check_python_version_drift(self, context: ProjectContext) -> list[Diagnostic]:
        """ENV-001: Check if running Python satisfies project requires-python or config."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("ENV-001")
        if not rule:
            return diagnostics

        target_python = context.config.get("target_python")
        if target_python:
            try:
                spec = SpecifierSet(
                    target_python
                    if any(c in target_python for c in "<>=~!")
                    else f"=={target_python}.*"
                )
                current_ver = Version(context.python_runtime.version_str)
                if not spec.contains(current_ver):
                    diagnostics.append(
                        Diagnostic(
                            id=rule.id,
                            severity=rule.default_severity,
                            category=rule.category,
                            title=rule.title,
                            message=f"Active Python {context.python_runtime.version_str} does not match target Python {target_python}.",
                            evidence=[
                                Evidence(
                                    fact=f"Active Python version: {context.python_runtime.version_str}",
                                    source=context.python_runtime.executable
                                    or "Active Interpreter",
                                ),
                                Evidence(
                                    fact=f"Configured Python target: {target_python}",
                                    source="pyproject.toml",
                                ),
                            ],
                            suggestions=[
                                Suggestion(
                                    description=f"Use Python {target_python} for your virtual environment.",
                                    executable="uv" if context.package_manager == "uv" else None,
                                    args=["venv", "--python", target_python]
                                    if context.package_manager == "uv"
                                    else [],
                                    command=f"uv venv --python {target_python}"
                                    if context.package_manager == "uv"
                                    else None,
                                )
                            ],
                            doc_url=rule.doc_url,
                        )
                    )
            except Exception:
                pass

        return diagnostics

    def _check_docker_drift(self, context: ProjectContext) -> list[Diagnostic]:
        """ENV-002: Check Dockerfile Python version against target/active Python."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("ENV-002")
        if not rule or not context.docker.has_dockerfile or not context.docker.base_python_version:
            return diagnostics

        docker_py = context.docker.base_python_version
        target_python = context.config.get("target_python")
        active_py = f"{context.python_runtime.major}.{context.python_runtime.minor}"

        is_drift = False
        mismatch_msg = ""
        target_source = "pyproject.toml"
        expected_py = active_py

        if target_python:
            try:
                spec = SpecifierSet(
                    target_python
                    if any(c in target_python for c in "<>=~!")
                    else f"=={target_python}.*"
                )
                if not spec.contains(Version(docker_py)):
                    is_drift = True
                    mismatch_msg = f"Dockerfile base image uses Python {docker_py}, which does not satisfy project target Python {target_python}."
                    expected_py = target_python.lstrip("<>=~!")
            except Exception:
                if docker_py != active_py:
                    is_drift = True
                    mismatch_msg = f"Dockerfile base image uses Python {docker_py}, while local runtime is {active_py}."
                    target_source = "Local environment"
        elif docker_py != active_py:
            is_drift = True
            mismatch_msg = f"Dockerfile base image uses Python {docker_py}, while local runtime is {active_py}."
            target_source = "Local environment"

        if is_drift:
            rel_docker = (
                context.docker.dockerfile_path.relative_to(context.project_root)
                if context.docker.dockerfile_path
                and context.docker.dockerfile_path.is_relative_to(context.project_root)
                else "Dockerfile"
            )
            diagnostics.append(
                Diagnostic(
                    id=rule.id,
                    severity=rule.default_severity,
                    category=rule.category,
                    title=rule.title,
                    message=mismatch_msg,
                    evidence=[
                        Evidence(
                            fact=f"Dockerfile base image: {context.docker.base_image}",
                            source=str(rel_docker),
                        ),
                        Evidence(
                            fact=f"Target Python version: {target_python or active_py}",
                            source=target_source,
                        ),
                    ],
                    suggestions=[
                        Suggestion(
                            description=f"Update base image in {rel_docker} to use python:{expected_py}-slim.",
                            code_snippet=f"FROM python:{expected_py}-slim",
                        )
                    ],
                    file=str(rel_docker),
                    doc_url=rule.doc_url,
                )
            )

        return diagnostics

    def _check_ci_drift(self, context: ProjectContext) -> list[Diagnostic]:
        """ENV-003: Check CI workflow python versions against active/target python."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("ENV-003")
        if not rule or not context.ci.has_ci or not context.ci.matrix_python_versions:
            return diagnostics

        target_python = context.config.get("target_python")
        active_major_minor = f"{context.python_runtime.major}.{context.python_runtime.minor}"

        if target_python:
            try:
                spec = SpecifierSet(
                    target_python
                    if any(c in target_python for c in "<>=~!")
                    else f"=={target_python}.*"
                )
                incompatible_ci = [
                    v for v in context.ci.matrix_python_versions if not spec.contains(Version(v))
                ]
                if incompatible_ci:
                    diagnostics.append(
                        Diagnostic(
                            id=rule.id,
                            severity=rule.default_severity,
                            category=rule.category,
                            title=rule.title,
                            message=f"CI matrix versions ({', '.join(incompatible_ci)}) do not satisfy project target Python ({target_python}).",
                            evidence=[
                                Evidence(
                                    fact=f"CI test matrix versions: {', '.join(context.ci.matrix_python_versions)}",
                                    source="CI workflows",
                                ),
                                Evidence(
                                    fact=f"Target Python specification: {target_python}",
                                    source="pyproject.toml",
                                ),
                            ],
                            suggestions=[
                                Suggestion(
                                    description=f"Update CI matrix to include versions satisfying '{target_python}'.",
                                )
                            ],
                            doc_url=rule.doc_url,
                        )
                    )
                    return diagnostics
            except Exception:
                pass

        if active_major_minor not in context.ci.matrix_python_versions:
            diagnostics.append(
                Diagnostic(
                    id=rule.id,
                    severity=rule.default_severity,
                    category=rule.category,
                    title=rule.title,
                    message=f"Local Python {active_major_minor} is not tested in CI matrix ({', '.join(context.ci.matrix_python_versions)}).",
                    evidence=[
                        Evidence(
                            fact=f"CI test matrix versions: {', '.join(context.ci.matrix_python_versions)}",
                            source="CI workflows",
                        ),
                        Evidence(
                            fact=f"Local Python version: {active_major_minor}",
                            source="Local environment",
                        ),
                    ],
                    suggestions=[
                        Suggestion(
                            description=f"Add '{active_major_minor}' to your CI matrix configuration.",
                        )
                    ],
                    doc_url=rule.doc_url,
                )
            )

        return diagnostics
