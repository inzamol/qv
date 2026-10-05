"""Doctor reporter providing a high-level project health scorecard."""

from __future__ import annotations

import io
import json
from dataclasses import asdict, dataclass
from typing import Any

from rich.console import Console

from qv.core.models import ScanResult, Severity


@dataclass
class CategoryHealth:
    """Health scorecard breakdown for a specific category."""

    id: str
    name: str
    score: int
    errors_count: int
    warnings_count: int
    info_count: int
    bar: str


@dataclass
class DoctorProblem:
    """Highlighted top problem in the project."""

    id: str
    title: str
    severity: str
    category: str
    file: str | None = None
    line: int | None = None


@dataclass
class DoctorReport:
    """Complete data structure for the doctor health report."""

    project_name: str
    project_path: str
    python_version: str
    package_manager: str
    health_score: int
    categories: list[CategoryHealth]
    errors_count: int
    warnings_count: int
    info_count: int
    checks_passed: int
    top_problems: list[DoctorProblem]
    explain_hint: str | None

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Convert report to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


CORE_CATEGORY_MAPPING: dict[str, tuple[str, str]] = {
    "dependency": ("dependencies", "Dependencies"),
    "dependencies": ("dependencies", "Dependencies"),
    "security": ("security", "Security"),
    "packaging": ("packaging", "Packaging"),
    "architecture": ("architecture", "Architecture"),
    "imports": ("architecture", "Architecture"),
    "compatibility": ("architecture", "Architecture"),
    "environment": ("environment", "Environment"),
    "ci": ("environment", "Environment"),
    "docker": ("environment", "Environment"),
    "framework": ("framework", "Framework"),
    "fastapi": ("framework", "Framework"),
    "sqlalchemy": ("framework", "Framework"),
    "sql": ("framework", "Framework"),
}

STANDARD_PILLARS = [
    ("dependencies", "Dependencies"),
    ("security", "Security"),
    ("packaging", "Packaging"),
    ("architecture", "Architecture"),
    ("environment", "Environment"),
    ("framework", "Framework"),
]


def make_bar(score: int, width: int = 10) -> str:
    """Return a Unicode block bar of ``width`` characters for a percentage score.

    The filled length is rounded to the nearest integer (ties to even) and
    clamped to the bar's bounds. Scores outside 0–100 produce empty or full
    bars; a nonpositive width produces an empty string.
    """
    filled_count = max(0, min(width, round((score / 100) * width)))
    empty_count = width - filled_count
    return "█" * filled_count + "░" * empty_count


class DoctorReporter:
    """Generates and renders the signature 'qv doctor' project health scorecard."""

    def __init__(self, console: Console | None = None, top_n: int = 3) -> None:
        """Use the supplied console, or create one with automatic color detection.

        ``top_n`` limits highlighted diagnostics, including repeated rule IDs.
        Nonpositive values still highlight one problem when findings exist.
        """
        self.console = console or Console(color_system="auto")
        self.top_n = top_n

    def build_report(self, result: ScanResult) -> DoctorReport:
        """Build a health scorecard and select top problems from scan findings.

        Category aliases are grouped into six standard pillars, always included.
        Other categories are included only when they have errors or warnings.
        Each category starts at 100, loses 15 points per error and 5 per warning,
        and is floored at zero; informational findings incur no penalty. Overall
        health is the rounded mean of category scores. Summary counts are copied
        from ``result.summary``.

        Problems are ordered by descending severity, then confidence, preserving
        input order for ties. Up to ``top_n`` diagnostics are selected (one for
        nonpositive limits), and rule IDs may repeat. With no findings, problems
        are empty and the explanation hint is None.
        """
        # Group diagnostics by standardized category
        category_counts: dict[str, dict[str, int]] = {
            pillar_id: {"errors": 0, "warnings": 0, "info": 0} for pillar_id, _ in STANDARD_PILLARS
        }

        for diag in result.diagnostics:
            raw_cat = (diag.category or "").lower()
            mapped = CORE_CATEGORY_MAPPING.get(raw_cat)
            pillar_id = mapped[0] if mapped else raw_cat

            if pillar_id not in category_counts:
                category_counts[pillar_id] = {"errors": 0, "warnings": 0, "info": 0}

            if diag.severity == Severity.ERROR:
                category_counts[pillar_id]["errors"] += 1
            elif diag.severity == Severity.WARNING:
                category_counts[pillar_id]["warnings"] += 1
            elif diag.severity == Severity.INFO:
                category_counts[pillar_id]["info"] += 1

        def _calc_category(
            cat_id: str, display_name: str, counts_dict: dict[str, int]
        ) -> CategoryHealth:
            errs = counts_dict.get("errors", 0)
            warns = counts_dict.get("warnings", 0)
            infos = counts_dict.get("info", 0)
            score_val = max(0, min(100, 100 - (errs * 15 + warns * 5)))
            return CategoryHealth(
                id=cat_id,
                name=display_name,
                score=score_val,
                errors_count=errs,
                warnings_count=warns,
                info_count=infos,
                bar=make_bar(score_val, width=10),
            )

        categories: list[CategoryHealth] = [
            _calc_category(p_id, p_name, category_counts.get(p_id, {}))
            for p_id, p_name in STANDARD_PILLARS
        ]

        # Include any non-standard categories if they have findings
        for c_id, counts in category_counts.items():
            if not any(p[0] == c_id for p in STANDARD_PILLARS) and (
                counts.get("errors", 0) > 0 or counts.get("warnings", 0) > 0
            ):
                categories.append(_calc_category(c_id, c_id.title(), counts))

        # Calculate overall health score from categories
        if categories:
            overall_health = round(sum(c.score for c in categories) / len(categories))
        else:
            overall_health = result.summary.health_score

        # Extract top problems sorted stably by severity (ERROR first, then WARNING, then INFO)
        sorted_diags = sorted(
            result.diagnostics,
            key=lambda d: (-d.severity.rank, -d.confidence),
        )

        top_problems: list[DoctorProblem] = []
        seen_rules: set[str] = set()
        for diag in sorted_diags:
            if diag.id in seen_rules and len(seen_rules) >= self.top_n:
                continue
            seen_rules.add(diag.id)

            # Format a concise title
            if diag.affected_packages and ("missing" in diag.title.lower() or diag.id == "DEP-002"):
                title = f"Missing dependency: {', '.join(diag.affected_packages)}"
            elif diag.affected_packages and "conflict" in diag.title.lower():
                title = f"Version conflict: {', '.join(diag.affected_packages)}"
            elif diag.id == "ENV-001":
                title = "Python version drift"
            elif diag.id == "ENV-003":
                title = "Python version mismatch"
            else:
                title = diag.title

            top_problems.append(
                DoctorProblem(
                    id=diag.id,
                    title=title,
                    severity=diag.severity.value,
                    category=diag.category,
                    file=diag.file,
                    line=diag.line,
                )
            )
            if len(top_problems) >= self.top_n:
                break

        explain_hint = f"qv explain {top_problems[0].id}" if top_problems else None

        return DoctorReport(
            project_name=result.project_name,
            project_path=result.project_path,
            python_version=result.python_version,
            package_manager=result.package_manager,
            health_score=overall_health,
            categories=categories,
            errors_count=result.summary.errors_count,
            warnings_count=result.summary.warnings_count,
            info_count=result.summary.info_count,
            checks_passed=result.summary.checks_passed,
            top_problems=top_problems,
            explain_hint=explain_hint,
        )

    def render(self, result: ScanResult) -> str:
        """Render doctor report to plain string without ANSI escape codes for file/text output."""
        string_io = io.StringIO()
        out_console = Console(file=string_io, color_system=None, force_terminal=False, width=80)
        self.print_result(result, console=out_console)
        return string_io.getvalue()

    def print_result(self, result: ScanResult, console: Console | None = None) -> None:
        """Print the doctor health report to the Rich console."""
        con = console or self.console
        report = self.build_report(result)

        # Header
        con.print()
        con.print("[bold cyan]QV Project Health[/bold cyan]")
        con.print("[dim]────────────────────────────────────────[/dim]")
        con.print()

        # Categories Breakdown
        for cat in report.categories:
            score_color = "green" if cat.score >= 85 else "yellow" if cat.score >= 60 else "red"
            filled_count = max(0, min(10, round((cat.score / 100) * 10)))
            empty_count = 10 - filled_count
            filled_bar = "█" * filled_count
            empty_bar = "░" * empty_count

            con.print(
                f"{cat.name:<18} [{score_color}]{cat.score:>3}/100[/{score_color}]   "
                f"[{score_color}]{filled_bar}[/{score_color}][dim]{empty_bar}[/dim]"
            )

        # Overall Health Score
        con.print()
        overall_color = (
            "green"
            if report.health_score >= 85
            else "yellow"
            if report.health_score >= 60
            else "red"
        )
        con.print(
            f"[bold]Health Score:[/bold] [{overall_color} bold]{report.health_score}/100[/{overall_color} bold]"
        )
        con.print()

        # Summary Counts
        if report.errors_count > 0:
            err_label = (
                "high-priority issue" if report.errors_count == 1 else "high-priority issues"
            )
            con.print(f"[bold red]{report.errors_count} {err_label}[/bold red]")
        else:
            con.print("[dim]0 high-priority issues[/dim]")

        if report.warnings_count > 0:
            warn_label = "warning" if report.warnings_count == 1 else "warnings"
            con.print(f"[bold yellow]{report.warnings_count} {warn_label}[/bold yellow]")
        else:
            con.print("[dim]0 warnings[/dim]")

        con.print(f"[bold green]{report.checks_passed} checks passed[/bold green]")
        con.print()

        # Top Problems
        if report.top_problems:
            con.print("[bold]Top problems:[/bold]")
            for idx, prob in enumerate(report.top_problems, 1):
                sev_color = (
                    "red"
                    if prob.severity == "error"
                    else "yellow"
                    if prob.severity == "warning"
                    else "blue"
                )
                con.print(
                    f"  {idx}. [{sev_color} bold]{prob.id:<8}[/{sev_color} bold]  {prob.title}"
                )
            con.print()
            con.print(f"Run [cyan]`{report.explain_hint}`[/cyan] for details.")
            con.print()
        else:
            con.print("[bold green]✓ No issues detected. Project is in great health![/bold green]")
            con.print()
