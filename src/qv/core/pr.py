"""GitHub PR Intelligence and Differential Change Analysis."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from qv.core.baseline import compute_diagnostic_fingerprint
from qv.core.config import QvConfig
from qv.core.engine import AnalysisEngine
from qv.core.models import Diagnostic, ScanResult, Severity
from qv.core.project import load_project
from qv.rules.registry import RULES_CATALOG


@dataclass
class FileDiffInfo:
    """Represents git change metadata for a single file."""

    path: str  # Normalized relative POSIX path (e.g. "src/qv/main.py")
    status: str = "M"  # 'A' (added), 'M' (modified), 'D' (deleted), 'R' (renamed)
    added_lines: set[int] = field(default_factory=set)  # 1-indexed line numbers
    deleted_lines: set[int] = field(default_factory=set)


@dataclass
class ResolvedIssue:
    """Represents a diagnostic issue present in the base branch/baseline that is now resolved."""

    id: str
    title: str
    message: str
    severity: Severity = Severity.WARNING
    file: str | None = None
    line: int | None = None
    category: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert resolved issue to dictionary format."""
        return {
            "id": self.id,
            "title": self.title,
            "message": self.message,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "category": self.category,
        }


@dataclass
class PRAnalysisResult:
    """Result of Pull Request change analysis."""

    project_name: str
    project_path: str
    changed_files_count: int
    changed_files: list[str]
    affected_checks_count: int
    new_issues: list[Diagnostic]
    resolved_issues: list[ResolvedIssue]
    existing_issues_count: int = 0
    total_issues_head: int = 0
    total_issues_base: int = 0
    base_ref: str | None = None
    head_ref: str | None = None
    python_version: str = "3.12"
    package_manager: str = "uv"

    @property
    def new_errors_count(self) -> int:
        """Return the count of new blocking error diagnostics."""
        return sum(1 for d in self.new_issues if d.severity == Severity.ERROR)

    @property
    def new_warnings_count(self) -> int:
        """Return the count of new warning diagnostics."""
        return sum(1 for d in self.new_issues if d.severity == Severity.WARNING)

    @property
    def has_blocking_errors(self) -> bool:
        """Return True if any new blocking errors were introduced."""
        return self.new_errors_count > 0

    def to_dict(self) -> dict[str, Any]:
        """Convert PR analysis result to structured dictionary format."""
        return {
            "project_name": self.project_name,
            "project_path": self.project_path,
            "python_version": self.python_version,
            "package_manager": self.package_manager,
            "base_ref": self.base_ref,
            "head_ref": self.head_ref,
            "changed_files_count": self.changed_files_count,
            "changed_files": self.changed_files,
            "affected_checks_count": self.affected_checks_count,
            "new_issues": [d.model_dump() for d in self.new_issues],
            "resolved_issues": [r.to_dict() for r in self.resolved_issues],
            "new_errors_count": self.new_errors_count,
            "new_warnings_count": self.new_warnings_count,
            "existing_issues_count": self.existing_issues_count,
            "total_issues_head": self.total_issues_head,
            "total_issues_base": self.total_issues_base,
            "has_blocking_errors": self.has_blocking_errors,
        }


PROJECT_CONFIG_FILES = {
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "pdm.lock",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
}


def _normalize_path(path_str: str) -> str:
    """Normalize file path to POSIX format without leading './' or leading '/'."""
    norm = path_str.replace("\\", "/").strip()
    while norm.startswith("./"):
        norm = norm[2:]
    while norm.startswith("/"):
        norm = norm[1:]
    return norm


class PRAnalyzer:
    """Analyzes only the changed code in a Pull Request against a base branch or baseline."""

    def __init__(self, project_root: Path | str = ".") -> None:
        """Initialize PR analyzer with project root path."""
        self.project_root = Path(project_root).resolve()

    def detect_base_ref(self) -> str | None:
        """Detect the best base ref from GitHub Actions environment or git repository."""
        # 1. GitHub Actions environment
        gh_base = os.getenv("GITHUB_BASE_REF")
        if gh_base:
            # Check if origin/<base> or <base> exists in git
            for candidate in [f"origin/{gh_base}", gh_base]:
                if self._git_ref_exists(candidate):
                    return candidate
            return gh_base

        # 2. Check common git branches
        common_candidates = [
            "origin/main",
            "origin/master",
            "main",
            "master",
            "HEAD~1",
        ]
        for candidate in common_candidates:
            if self._git_ref_exists(candidate):
                return candidate

        return None

    def _is_git_repo(self) -> bool:
        """Check if project_root is within a git repository."""
        try:
            res = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=str(self.project_root),
                capture_output=True,
                text=True,
                check=False,
            )
            return res.returncode == 0 and res.stdout.strip() == "true"
        except Exception:
            return False

    def _git_ref_exists(self, ref: str) -> bool:
        """Check if a git ref exists in current repo."""
        if not self._is_git_repo():
            return False
        try:
            res = subprocess.run(
                ["git", "rev-parse", "--verify", ref],
                cwd=str(self.project_root),
                capture_output=True,
                text=True,
                check=False,
            )
            return res.returncode == 0
        except Exception:
            return False

    @staticmethod
    def parse_unified_diff(diff_text: str) -> dict[str, FileDiffInfo]:
        """Parse unified diff text into a mapping of normalized relative file paths to FileDiffInfo."""
        file_diffs: dict[str, FileDiffInfo] = {}
        current_file: str | None = None
        current_info: FileDiffInfo | None = None

        hunk_header_re = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

        for line in diff_text.splitlines():
            if line.startswith("diff --git "):
                # e.g. diff --git a/foo/bar.py b/foo/bar.py
                parts = line.split(" ")
                if len(parts) >= 4:
                    raw_b_path = parts[3].removeprefix("b/")
                    current_file = _normalize_path(raw_b_path)
                    current_info = FileDiffInfo(path=current_file, status="M")
                    file_diffs[current_file] = current_info
            elif line.startswith("new file mode ") and current_info:
                current_info.status = "A"
            elif line.startswith("deleted file mode ") and current_info:
                current_info.status = "D"
            elif line.startswith("rename from ") and current_info:
                current_info.status = "R"
            elif line.startswith("rename to ") and current_info:
                new_path = _normalize_path(line.removeprefix("rename to ").strip())
                current_file = new_path
                current_info.path = new_path
                file_diffs[new_path] = current_info
            elif line.startswith("+++ b/"):
                target_raw = line.removeprefix("+++ b/").strip()
                if target_raw != "/dev/null":
                    current_file = _normalize_path(target_raw)
                    if current_file not in file_diffs:
                        current_info = FileDiffInfo(path=current_file, status="M")
                        file_diffs[current_file] = current_info
                    else:
                        current_info = file_diffs[current_file]
            elif line.startswith("@@ ") and current_info:
                match = hunk_header_re.match(line)
                if match:
                    new_start = int(match.group(3))
                    new_count = int(match.group(4)) if match.group(4) is not None else 1
                    if new_count > 0:
                        for l_num in range(new_start, new_start + new_count):
                            current_info.added_lines.add(l_num)

        return file_diffs

    def get_git_diff_info(self, base_ref: str, head_ref: str = "HEAD") -> dict[str, FileDiffInfo]:
        """Fetch git diff against base_ref and return file diff info mapping."""
        # First test if triple dot or double dot works
        diff_args = ["git", "diff", "-U0", f"{base_ref}...{head_ref}"]
        res = subprocess.run(
            diff_args,
            cwd=str(self.project_root),
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode != 0 or not res.stdout.strip():
            # Fallback to direct diff
            diff_args = ["git", "diff", "-U0", base_ref, head_ref]
            res = subprocess.run(
                diff_args,
                cwd=str(self.project_root),
                capture_output=True,
                text=True,
                check=False,
            )

        if res.returncode != 0:
            return {}

        return self.parse_unified_diff(res.stdout)

    def _extract_base_scan(self, base_ref: str, config: QvConfig) -> ScanResult | None:
        """Attempt to scan project at base_ref via temporary checkout/archive."""
        temp_dir = tempfile.mkdtemp(prefix="qv_base_")
        try:
            # Use git archive to export base_ref files without modifying current workspace
            archive_proc = subprocess.Popen(
                ["git", "archive", base_ref],
                cwd=str(self.project_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            # Use python tarfile to extract
            import tarfile

            if archive_proc.stdout:
                with tarfile.open(fileobj=archive_proc.stdout, mode="r|*") as tar:
                    tar.extractall(path=temp_dir)
            archive_proc.wait()

            if archive_proc.returncode == 0:
                base_project = load_project(Path(temp_dir))
                base_engine = AnalysisEngine(config=config)
                return base_engine.run(base_project.context)
        except Exception:
            pass
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
        return None

    def _load_baseline_diagnostics(self, baseline_path: Path) -> list[dict[str, Any]]:
        """Load baseline record dictionaries."""
        import json

        if not baseline_path.exists() or not baseline_path.is_file():
            return []
        try:
            data = json.loads(baseline_path.read_text(encoding="utf-8"))
            return data.get("diagnostics", [])
        except Exception:
            return []

    def _compute_affected_checks(
        self,
        changed_files: list[str],
        new_diagnostics: list[Diagnostic],
        resolved_diagnostics: list[ResolvedIssue],
    ) -> int:
        """Compute the count of distinct checks/rules that apply to the changed files."""
        has_python = any(f.endswith(".py") for f in changed_files)
        has_deps = any(
            Path(f).name in PROJECT_CONFIG_FILES or f.endswith(".txt") or f.endswith(".toml")
            for f in changed_files
        )
        has_docker = any("docker" in f.lower() for f in changed_files)
        has_ci = any(".github" in f.lower() or "gitlab" in f.lower() for f in changed_files)

        applicable_rules: set[str] = set()
        for rule_id, rule_def in RULES_CATALOG.items():
            cat = rule_def.category.lower()
            if has_python and cat in ("imports", "architecture", "framework", "ast"):
                applicable_rules.add(rule_id)
            elif has_deps and cat in ("dependency", "dependencies", "packaging", "security"):
                applicable_rules.add(rule_id)
            elif has_docker and cat in ("docker", "container", "environment"):
                applicable_rules.add(rule_id)
            elif has_ci and cat in ("ci", "workflow", "environment"):
                applicable_rules.add(rule_id)

        # Include all rules from new and resolved issues
        for d in new_diagnostics:
            applicable_rules.add(d.id)
        for r in resolved_diagnostics:
            applicable_rules.add(r.id)

        # Base check count is either applicable rules or total evaluated
        count = len(applicable_rules)
        return max(count, len(new_diagnostics) + len(resolved_diagnostics))

    def analyze(
        self,
        base_ref: str | None = None,
        head_ref: str | None = "HEAD",
        baseline_path: Path | None = None,
        changed_files_list: list[str] | None = None,
        diff_text: str | None = None,
        config: QvConfig | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> PRAnalysisResult:
        """Run Pull Request intelligence analysis."""
        # 1. Load current project and run analysis
        project = load_project(self.project_root)
        active_config = config or project.config
        engine = AnalysisEngine(config=active_config)
        head_result = engine.run(project.context, on_progress=on_progress)

        # 2. Determine changed files and line diffs
        file_diffs: dict[str, FileDiffInfo] = {}
        if diff_text:
            file_diffs = self.parse_unified_diff(diff_text)
        elif base_ref:
            file_diffs = self.get_git_diff_info(base_ref, head_ref or "HEAD")
        else:
            detected_base = self.detect_base_ref()
            if detected_base:
                base_ref = detected_base
                file_diffs = self.get_git_diff_info(detected_base, head_ref or "HEAD")

        # Merge explicitly specified changed files
        if changed_files_list:
            for cf in changed_files_list:
                norm_cf = _normalize_path(cf)
                if norm_cf not in file_diffs:
                    file_diffs[norm_cf] = FileDiffInfo(path=norm_cf, status="A")

        # If no changed files detected (e.g. no git history or diff), default to all files touched by head diagnostics
        if not file_diffs and not base_ref and not baseline_path:
            for d in head_result.diagnostics:
                if d.file:
                    norm_f = _normalize_path(d.file)
                    file_diffs[norm_f] = FileDiffInfo(path=norm_f, status="A")

        changed_files_keys = list(file_diffs.keys())

        # 3. Obtain base diagnostics (from git base ref scan or baseline snapshot)
        base_scan_result: ScanResult | None = None
        baseline_records: list[dict[str, Any]] = []

        if baseline_path and baseline_path.exists():
            baseline_records = self._load_baseline_diagnostics(baseline_path)
        elif base_ref:
            base_scan_result = self._extract_base_scan(base_ref, active_config)

        # 4. Partition head diagnostics into new vs unchanged
        new_issues: list[Diagnostic] = []
        resolved_issues: list[ResolvedIssue] = []

        if base_scan_result is not None:
            base_fps = {compute_diagnostic_fingerprint(d): d for d in base_scan_result.diagnostics}
            head_fps = {compute_diagnostic_fingerprint(d): d for d in head_result.diagnostics}

            for fp, diag in head_fps.items():
                if fp not in base_fps:
                    new_issues.append(diag)

            for fp, b_diag in base_fps.items():
                if fp not in head_fps:
                    resolved_issues.append(
                        ResolvedIssue(
                            id=b_diag.id,
                            title=b_diag.title,
                            message=b_diag.message,
                            severity=b_diag.severity,
                            file=b_diag.file,
                            line=b_diag.line,
                            category=b_diag.category,
                        )
                    )

            total_base_count = len(base_scan_result.diagnostics)

        elif baseline_records:
            base_fps_set = {r.get("fingerprint") for r in baseline_records if "fingerprint" in r}
            # Reconstruct baseline map
            base_map = {r.get("fingerprint"): r for r in baseline_records if "fingerprint" in r}
            head_fps_set = set()

            for diag in head_result.diagnostics:
                fp = compute_diagnostic_fingerprint(diag)
                head_fps_set.add(fp)
                if fp not in base_fps_set:
                    new_issues.append(diag)

            for fp, r_data in base_map.items():
                if fp not in head_fps_set:
                    resolved_issues.append(
                        ResolvedIssue(
                            id=r_data.get("id", "UNKNOWN"),
                            title=r_data.get("title", ""),
                            message=r_data.get("message", r_data.get("title", "")),
                            severity=Severity(r_data.get("severity", "warning")),
                            file=r_data.get("file"),
                            line=r_data.get("line"),
                            category=r_data.get("category"),
                        )
                    )

            total_base_count = len(baseline_records)

        else:
            # Diff-line and changed-file heuristic matching
            for diag in head_result.diagnostics:
                if not diag.file:
                    new_issues.append(diag)
                    continue

                norm_file = _normalize_path(diag.file)
                is_changed = False

                # Exact or suffix match in changed files
                for cf, info in file_diffs.items():
                    if (
                        norm_file == cf
                        or norm_file.endswith("/" + cf)
                        or cf.endswith("/" + norm_file)
                    ):
                        # File is changed!
                        if info.status == "A" or not info.added_lines:
                            is_changed = True
                        elif diag.line is None or diag.line in info.added_lines:
                            is_changed = True
                        elif Path(norm_file).name in PROJECT_CONFIG_FILES:
                            # Project config files (requirements.txt, etc.) affect whole project
                            is_changed = True
                        break

                if is_changed:
                    new_issues.append(diag)

            total_base_count = max(0, len(head_result.diagnostics) - len(new_issues))

        existing_count = len(head_result.diagnostics) - len(new_issues)
        affected_checks = self._compute_affected_checks(
            changed_files=changed_files_keys,
            new_diagnostics=new_issues,
            resolved_diagnostics=resolved_issues,
        )

        return PRAnalysisResult(
            project_name=head_result.project_name,
            project_path=head_result.project_path,
            changed_files_count=len(changed_files_keys),
            changed_files=changed_files_keys,
            affected_checks_count=affected_checks,
            new_issues=new_issues,
            resolved_issues=resolved_issues,
            existing_issues_count=existing_count,
            total_issues_head=len(head_result.diagnostics),
            total_issues_base=total_base_count,
            base_ref=base_ref,
            head_ref=head_ref,
            python_version=head_result.python_version,
            package_manager=head_result.package_manager,
        )
