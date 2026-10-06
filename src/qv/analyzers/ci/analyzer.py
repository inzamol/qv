"""CI/CD Workflow Analyzer implementing rules CI-001 through CI-006."""

from __future__ import annotations

import re

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from qv.core.analyzer import Analyzer
from qv.core.context import ProjectContext
from qv.core.models import AnalyzerStatus, Diagnostic, Evidence, Severity, Suggestion
from qv.rules.registry import get_rule_definition

DEPRECATED_ACTIONS: dict[str, str] = {
    "actions/checkout@v1": "Upgrade to actions/checkout@v4 (Node.js 20 runner).",
    "actions/checkout@v2": "Upgrade to actions/checkout@v4 (Node.js 20 runner).",
    "actions/checkout@v3": "Upgrade to actions/checkout@v4 (Node.js 20 runner).",
    "actions/setup-python@v1": "Upgrade to actions/setup-python@v5.",
    "actions/setup-python@v2": "Upgrade to actions/setup-python@v5.",
    "actions/setup-python@v3": "Upgrade to actions/setup-python@v5.",
    "actions/setup-python@v4": "Upgrade to actions/setup-python@v5.",
    "actions/upload-artifact@v1": "Upgrade to actions/upload-artifact@v4.",
    "actions/upload-artifact@v2": "Upgrade to actions/upload-artifact@v4.",
    "actions/upload-artifact@v3": "Upgrade to actions/upload-artifact@v4.",
    "actions/download-artifact@v1": "Upgrade to actions/download-artifact@v4.",
    "actions/download-artifact@v2": "Upgrade to actions/download-artifact@v4.",
    "actions/download-artifact@v3": "Upgrade to actions/download-artifact@v4.",
}

QUALITY_GATE_KEYWORDS = frozenset(
    {
        "pytest",
        "unittest",
        "ruff",
        "flake8",
        "black",
        "pyright",
        "mypy",
        "pylint",
        "tox",
        "nox",
        "qv",
        "coverage",
        "mkdocs",
        "sphinx",
        "build",
        "publish",
        "release",
        "deploy",
    }
)


class CIAnalyzer(Analyzer):
    """Analyzes CI/CD configurations for matrix drift, reproducibility, and best practices."""

    id = "ci"
    name = "CI Analyzer"
    description = (
        "Validates CI/CD configurations (.github/workflows, .gitlab-ci.yml) against "
        "project specifications, Python versions, lockfiles, and quality gates."
    )
    rules: tuple[str, ...] = (
        "CI-001",
        "CI-002",
        "CI-003",
        "CI-004",
        "CI-005",
        "CI-006",
    )

    def __init__(self) -> None:
        self.status: AnalyzerStatus = AnalyzerStatus.OK

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        """Analyze CI workflows present in the project context."""
        diagnostics: list[Diagnostic] = []

        if not context.ci.has_ci or not context.ci.workflow_files:
            self.status = AnalyzerStatus.SKIPPED
            return diagnostics

        self.status = AnalyzerStatus.OK

        # Retrieve target python requirements from context
        requires_python_str: str | None = None
        target_py = context.config.get("target_python")
        if target_py:
            requires_python_str = str(target_py)
        else:
            # Try to read requires-python from pyproject.toml if present
            for mf in context.manifest_files:
                if mf.name == "pyproject.toml":
                    try:
                        content = mf.read_text(encoding="utf-8")
                        m = re.search(r'requires-python\s*=\s*["\']([^"\']+)["\']', content)
                        if m:
                            requires_python_str = m.group(1)
                            break
                    except Exception:
                        pass

        for wf in context.ci.workflow_files:
            file_rel = str(wf.relative_to(context.project_root)).replace("\\", "/")
            try:
                content = wf.read_text(encoding="utf-8")
                lines = content.splitlines()
            except Exception:
                continue

            diagnostics.extend(self._check_python_matrix(lines, file_rel, requires_python_str))
            diagnostics.extend(self._check_unfrozen_dependencies(lines, file_rel))
            diagnostics.extend(self._check_deprecated_actions(lines, file_rel))
            diagnostics.extend(self._check_quality_gates(content, lines, file_rel))
            diagnostics.extend(self._check_secrets_in_workflow(lines, file_rel))
            diagnostics.extend(self._check_concurrency(content, lines, file_rel))

        return diagnostics

    def _check_python_matrix(
        self,
        lines: list[str],
        file_rel: str,
        requires_python_str: str | None,
    ) -> list[Diagnostic]:
        """CI-001: CI matrix Python version mismatch with requires-python."""
        diagnostics: list[Diagnostic] = []
        if not requires_python_str:
            return diagnostics

        try:
            spec = SpecifierSet(requires_python_str)
        except Exception:
            return diagnostics

        for line_idx, line in enumerate(lines, 1):
            if "python-version" in line or "matrix:" in line or "python:" in line:
                # Find quoted or bare version numbers 3.x
                versions = re.findall(r'["\']?(3\.\d+)["\']?', line)
                for v in versions:
                    try:
                        parsed_v = Version(v)
                        if parsed_v not in spec:
                            rule_def = get_rule_definition("CI-001")
                            doc_url = rule_def.doc_url if rule_def else ""
                            diagnostics.append(
                                Diagnostic(
                                    id="CI-001",
                                    severity=Severity.WARNING,
                                    category="ci",
                                    title="CI Python matrix version mismatch",
                                    message=(
                                        f"CI workflow tests Python version '{v}' which does not satisfy "
                                        f"project 'requires-python = \"{requires_python_str}\"'."
                                    ),
                                    file=file_rel,
                                    line=line_idx,
                                    evidence=[
                                        Evidence(
                                            fact=f"Matrix version '{v}' not in '{requires_python_str}' on line {line_idx}.",
                                            source=file_rel,
                                        )
                                    ],
                                    suggestions=[
                                        Suggestion(
                                            description=f"Align CI matrix version '{v}' with supported range '{requires_python_str}'.",
                                        )
                                    ],
                                    doc_url=doc_url,
                                )
                            )
                    except InvalidVersion:
                        continue
        return diagnostics

    def _check_unfrozen_dependencies(self, lines: list[str], file_rel: str) -> list[Diagnostic]:
        """CI-002: Unfrozen dependency installation in CI."""
        diagnostics: list[Diagnostic] = []
        for line_idx, line in enumerate(lines, 1):
            stripped = line.strip()
            # Detect unpinned pip install without lockfile or hash verification
            if (
                re.search(r"\bpip\s+install\s+(?:-r\s+\S+|\.|\w+)", stripped)
                and "--require-hashes" not in stripped
                and "--frozen" not in stripped
                and "pip install -e" not in stripped
                and "uv " not in stripped
                and "poetry " not in stripped
            ):
                # If doing pip install -r requirements.txt or pip install .
                if "pip install ." in stripped or "requirements.txt" in stripped:
                    rule_def = get_rule_definition("CI-002")
                    doc_url = rule_def.doc_url if rule_def else ""
                    diagnostics.append(
                        Diagnostic(
                            id="CI-002",
                            severity=Severity.WARNING,
                            category="ci",
                            title="Unfrozen dependency installation in CI",
                            message=(
                                f"CI step '{stripped}' installs dependencies without lockfile enforcement "
                                f"or hash verification, risking non-deterministic builds."
                            ),
                            file=file_rel,
                            line=line_idx,
                            evidence=[
                                Evidence(
                                    fact=f"Unfrozen install command '{stripped}' on line {line_idx}.",
                                    source=file_rel,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description="Use a lockfile (e.g. 'uv sync --frozen', 'poetry install --sync', or 'pip-sync').",
                                )
                            ],
                            doc_url=doc_url,
                        )
                    )
        return diagnostics

    def _check_deprecated_actions(self, lines: list[str], file_rel: str) -> list[Diagnostic]:
        """CI-003: Deprecated or outdated CI action pin."""
        diagnostics: list[Diagnostic] = []
        for line_idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("uses:") or "uses:" in stripped:
                for deprecated_action, hint in DEPRECATED_ACTIONS.items():
                    if deprecated_action in stripped:
                        rule_def = get_rule_definition("CI-003")
                        doc_url = rule_def.doc_url if rule_def else ""
                        diagnostics.append(
                            Diagnostic(
                                id="CI-003",
                                severity=Severity.INFO,
                                category="ci",
                                title="Deprecated or outdated CI action version",
                                message=f"Action '{deprecated_action}' is deprecated. {hint}",
                                file=file_rel,
                                line=line_idx,
                                evidence=[
                                    Evidence(
                                        fact=f"Deprecated action reference '{deprecated_action}' on line {line_idx}.",
                                        source=file_rel,
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description=hint,
                                    )
                                ],
                                doc_url=doc_url,
                            )
                        )
        return diagnostics

    def _check_quality_gates(
        self, content: str, lines: list[str], file_rel: str
    ) -> list[Diagnostic]:
        """CI-004: Missing quality gate in workflow."""
        diagnostics: list[Diagnostic] = []
        # Only check workflows that trigger on pull_request or push to main
        is_pr_or_push = bool(re.search(r"\b(pull_request|push)\b", content))
        if not is_pr_or_push:
            return diagnostics

        has_quality_gate = any(
            re.search(rf"\b{kw}\b", content, re.IGNORECASE) for kw in QUALITY_GATE_KEYWORDS
        )
        if not has_quality_gate:
            rule_def = get_rule_definition("CI-004")
            doc_url = rule_def.doc_url if rule_def else ""
            diagnostics.append(
                Diagnostic(
                    id="CI-004",
                    severity=Severity.INFO,
                    category="ci",
                    title="Missing test or quality gate in CI workflow",
                    message=(
                        f"Workflow '{file_rel}' triggers on pull_request/push but contains no "
                        f"test suite, linter, or health checks (e.g. pytest, ruff, qv, pyright)."
                    ),
                    file=file_rel,
                    line=1,
                    evidence=[
                        Evidence(
                            fact=f"No quality gate tool found in {file_rel}.",
                            source=file_rel,
                        )
                    ],
                    suggestions=[
                        Suggestion(
                            description="Add a test or lint step (e.g. 'pytest', 'ruff check', or 'qv scan --ci').",
                        )
                    ],
                    doc_url=doc_url,
                )
            )
        return diagnostics

    def _check_secrets_in_workflow(self, lines: list[str], file_rel: str) -> list[Diagnostic]:
        """CI-005: Insecure hardcoded secret or token in workflow."""
        diagnostics: list[Diagnostic] = []
        secret_patterns = [
            (
                r'(?:api_key|token|password|secret)\s*[:=]\s*["\'](?!(\$\{\{|\$))[A-Za-z0-9_\-]{16,}["\']',
                "Hardcoded API key or secret token literal",
            ),
            (r"ghp_[A-Za-z0-9]{20,}", "Exposed GitHub Personal Access Token (ghp_*)"),
            (r"AKIA[0-9A-Z]{16}", "Exposed AWS Access Key ID"),
        ]

        for line_idx, line in enumerate(lines, 1):
            for pat, desc in secret_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    rule_def = get_rule_definition("CI-005")
                    doc_url = rule_def.doc_url if rule_def else ""
                    diagnostics.append(
                        Diagnostic(
                            id="CI-005",
                            severity=Severity.ERROR,
                            category="ci",
                            title="Insecure secret or token in CI workflow",
                            message=f"{desc} detected in workflow file.",
                            file=file_rel,
                            line=line_idx,
                            evidence=[
                                Evidence(
                                    fact=f"Potential secret literal on line {line_idx}.",
                                    source=file_rel,
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description="Store credentials in repository secrets (${{ secrets.MY_SECRET }}).",
                                )
                            ],
                            doc_url=doc_url,
                        )
                    )
        return diagnostics

    def _check_concurrency(self, content: str, lines: list[str], file_rel: str) -> list[Diagnostic]:
        """CI-006: Missing concurrency cancellation in pull request workflow."""
        diagnostics: list[Diagnostic] = []
        is_pr = "pull_request" in content
        has_concurrency = "concurrency:" in content

        if is_pr and not has_concurrency:
            rule_def = get_rule_definition("CI-006")
            doc_url = rule_def.doc_url if rule_def else ""
            diagnostics.append(
                Diagnostic(
                    id="CI-006",
                    severity=Severity.INFO,
                    category="ci",
                    title="Missing concurrency cancellation in PR workflow",
                    message=(
                        f"Pull request workflow '{file_rel}' lacks a 'concurrency' group with "
                        f"'cancel-in-progress: true', causing redundant runner usage on repeated pushes."
                    ),
                    file=file_rel,
                    line=1,
                    evidence=[
                        Evidence(
                            fact=f"No concurrency configuration found in {file_rel}.",
                            source=file_rel,
                        )
                    ],
                    suggestions=[
                        Suggestion(
                            description=(
                                "Add concurrency group:\n"
                                "concurrency:\n"
                                "  group: ${{ github.workflow }}-${{ github.ref }}\n"
                                "  cancel-in-progress: true"
                            ),
                        )
                    ],
                    doc_url=doc_url,
                )
            )
        return diagnostics
