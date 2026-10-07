"""Pull Request Intelligence reporter for terminal, GitHub annotations, and Markdown summaries."""

from __future__ import annotations

import io
import os

from rich.console import Console

from qv.core.models import Severity
from qv.core.pr import PRAnalysisResult


class PRReporter:
    """Renders PR Intelligence reports to terminal, GitHub Actions step summary, and PR comment markdown."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console(color_system="auto")

    def print_result(self, result: PRAnalysisResult, console: Console | None = None) -> None:
        """Print rich terminal PR analysis matching issue specification."""
        con = console or self.console

        con.print()
        con.print("[bold cyan]QV Pull Request Analysis[/bold cyan]")
        con.print()
        con.print(f"Changed files: [bold]{result.changed_files_count}[/bold]")
        con.print(f"Affected checks: [bold]{result.affected_checks_count}[/bold]")
        con.print()

        # New issues section
        if result.new_issues:
            con.print("[bold red]New issues[/bold red]")
            con.print("[dim]──────────[/dim]")
            for d in result.new_issues:
                color = "red" if d.severity == Severity.ERROR else "yellow"
                loc = f"{d.file}:{d.line}" if d.file and d.line else (d.file if d.file else "")
                loc_str = f"  [cyan]{loc}[/cyan]" if loc else ""
                con.print(f"[{color}]{d.id}[/{color}]{loc_str}")
                con.print(f"{d.title or d.message}")
                con.print()
        else:
            con.print("[bold green]✓ No new issues introduced in this PR![/bold green]")
            con.print()

        # Resolved section
        if result.resolved_issues:
            con.print("[bold green]Resolved[/bold green]")
            con.print("[dim]────────[/dim]")
            for r in result.resolved_issues:
                loc = (
                    f"  [dim]{r.file}:{r.line}[/dim]"
                    if r.file and r.line
                    else (f"  [dim]{r.file}[/dim]" if r.file else "")
                )
                con.print(f"[bold green]{r.id}[/bold green]{loc}")
                if r.title:
                    con.print(f"[dim]{r.title}[/dim]")
                con.print()

    def render(self, result: PRAnalysisResult, no_color: bool = False) -> str:
        """Render terminal output to string."""
        string_io = io.StringIO()
        out_console = Console(
            file=string_io,
            force_terminal=not no_color,
            no_color=no_color,
            width=90,
        )
        self.print_result(result, console=out_console)
        return string_io.getvalue()

    def render_markdown(self, result: PRAnalysisResult) -> str:
        """Render GitHub PR comment and Step Summary Markdown."""
        lines: list[str] = [
            f"# 🔍 QV Pull Request Analysis: {result.project_name}",
            "",
            "| Metric | Count |",
            "|---|---|",
            f"| **Changed Files** | `{result.changed_files_count}` |",
            f"| **Affected Checks** | `{result.affected_checks_count}` |",
            f"| **New Errors** | 🔴 `{result.new_errors_count}` |",
            f"| **New Warnings** | 🟡 `{result.new_warnings_count}` |",
            f"| **Resolved Issues** | 🟢 `{len(result.resolved_issues)}` |",
            "",
        ]

        if result.new_issues:
            lines.extend(
                [
                    f"### 🔴 New Issues ({len(result.new_issues)})",
                    "",
                    "| Severity | Rule ID | Title | Location | Message |",
                    "|---|---|---|---|---|",
                ]
            )
            for d in result.new_issues:
                sev_icon = "🔴 Error" if d.severity == Severity.ERROR else "🟡 Warning"
                loc = (
                    f"`{d.file}:{d.line}`"
                    if d.file and d.line
                    else (f"`{d.file}`" if d.file else "—")
                )
                lines.append(f"| {sev_icon} | `{d.id}` | **{d.title}** | {loc} | {d.message} |")
            lines.append("")

        if result.resolved_issues:
            lines.extend(
                [
                    f"### 🟢 Resolved Issues ({len(result.resolved_issues)})",
                    "",
                ]
            )
            for r in result.resolved_issues:
                loc = (
                    f" (`{r.file}:{r.line}`)"
                    if r.file and r.line
                    else (f" (`{r.file}`)" if r.file else "")
                )
                lines.append(f"- **`{r.id}`** — {r.title}{loc}")
            lines.append("")

        if not result.new_issues and not result.resolved_issues:
            lines.append("✨ **No new issues or regressions detected in this PR.**")
            lines.append("")

        return "\n".join(lines)

    def emit_annotations(self, result: PRAnalysisResult) -> None:
        """Print GitHub workflow command annotations for newly introduced diagnostic findings."""
        for d in result.new_issues:
            level = "error" if d.severity == Severity.ERROR else "warning"
            file_part = f"file={d.file}" if d.file else ""
            line_part = f",line={d.line}" if d.line else ""
            title_part = f",title={d.id}: {d.title}"

            options = f"{file_part}{line_part}{title_part}".lstrip(",")
            opt_str = f" {options}" if options else ""
            print(f"::{level}{opt_str}::{d.message}")

    def write_step_summary(self, result: PRAnalysisResult) -> None:
        """Write rich Markdown summary table to GITHUB_STEP_SUMMARY environment file."""
        summary_path = os.getenv("GITHUB_STEP_SUMMARY")
        if not summary_path:
            return

        markdown_content = self.render_markdown(result)
        try:
            with open(summary_path, "a", encoding="utf-8") as f:
                f.write(markdown_content + "\n")
        except Exception:
            pass
