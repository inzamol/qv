"""Terminal reporter using Rich for structured, human-readable diagnostics."""

from __future__ import annotations

import io

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from qv.core.models import ScanResult, Severity


class TerminalReporter:
    """Renders diagnostics to rich terminal output."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console(color_system="auto")

    def render(self, result: ScanResult) -> str:
        """Render scan result to string for display."""
        string_io = io.StringIO()
        out_console = Console(file=string_io, force_terminal=True, width=90)
        self.print_result(result, console=out_console)
        return string_io.getvalue()

    def print_result(self, result: ScanResult, console: Console | None = None) -> None:
        """Print the scan result directly to console."""
        con = console or self.console

        # Header
        con.print()
        con.print("[bold cyan]🔍 qv[/bold cyan]")
        con.print(f"[dim]Project:[/dim] [bold]{result.project_name}[/bold]")
        con.print(f"[dim]Python:[/dim]  [green]{result.python_version}[/green]")
        con.print(f"[dim]Package Manager:[/dim] [blue]{result.package_manager}[/blue]")
        con.print()

        # Summary Badges
        summary = result.summary
        err_badge = (
            f"[bold red]🔴 {summary.errors_count} Errors[/bold red]"
            if summary.errors_count
            else "[dim]0 Errors[/dim]"
        )
        warn_badge = (
            f"[bold yellow]🟡 {summary.warnings_count} Warnings[/bold yellow]"
            if summary.warnings_count
            else "[dim]0 Warnings[/dim]"
        )
        pass_badge = f"[bold green]🟢 {summary.checks_passed} Checks Passed[/bold green]"

        con.print(f"{err_badge}   {warn_badge}   {pass_badge}")
        con.print()

        # Diagnostics listing
        if not result.diagnostics:
            con.print(
                "[bold green]✨ Everything looks healthy! No diagnostic issues found.[/bold green]"
            )
        else:
            for diag in result.diagnostics:
                color = (
                    "red"
                    if diag.severity == Severity.ERROR
                    else "yellow"
                    if diag.severity == Severity.WARNING
                    else "blue"
                )
                icon = (
                    "🔴"
                    if diag.severity == Severity.ERROR
                    else "🟡"
                    if diag.severity == Severity.WARNING
                    else "ℹ️"
                )

                title_text = Text()
                title_text.append(f"{icon} {diag.id} ", style=f"bold {color}")
                title_text.append(f"{diag.title}", style="bold white")

                body = []
                body.append(f"[bold]{diag.message}[/bold]")

                if diag.file:
                    loc = f"[dim]Location:[/dim] {diag.file}"
                    if diag.line:
                        loc += f":{diag.line}"
                    body.append(loc)

                if diag.evidence:
                    body.append("\n[bold dim]Evidence:[/bold dim]")
                    for ev in diag.evidence:
                        body.append(f"  • {ev.fact}")

                if diag.suggestions:
                    body.append("\n[bold cyan]Suggested fix:[/bold cyan]")
                    for sug in diag.suggestions:
                        body.append(f"  {sug.description}")
                        if sug.command:
                            body.append(f"  [bold green]$ {sug.command}[/bold green]")
                        if sug.code_snippet:
                            body.append(
                                f"  [dim]```[/dim]\n  [white]{sug.code_snippet}[/white]\n  [dim]```[/dim]"
                            )

                panel = Panel(
                    "\n".join(body),
                    title=title_text,
                    border_style=color,
                    padding=(0, 1),
                )
                con.print(panel)

        # Health score footer
        score_color = (
            "green"
            if summary.health_score >= 85
            else "yellow"
            if summary.health_score >= 60
            else "red"
        )
        con.print(
            f"[bold]Health Score:[/bold] [{score_color}]{summary.health_score}/100[/{score_color}]"
        )
        con.print()
