"""Interactive Terminal Explorer (TUI) for qv."""

from __future__ import annotations

import sys
from pathlib import Path

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from qv.core.models import ScanResult, Severity
from qv.remediation.engine import RemediationEngine
from qv.visualizers.tree import TreeVisualizer


def _getch() -> str:
    """Read a single keypress cross-platform."""
    if sys.platform == "win32":
        import msvcrt

        ch = msvcrt.getch()
        if ch in (b"\x00", b"\xe0"):  # Arrow keys prefix on Windows
            ch2 = msvcrt.getch()
            if ch2 == b"H":
                return "up"
            if ch2 == b"P":
                return "down"
            if ch2 == b"K":
                return "left"
            if ch2 == b"M":
                return "right"
        if ch == b"\r":
            return "enter"
        if ch == b"\x1b":
            return "esc"
        if ch == b" ":
            return "space"
        try:
            return ch.decode("utf-8", errors="ignore").lower()
        except Exception:
            return ""
    else:
        import termios
        import tty

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                ch2 = sys.stdin.read(1)
                if ch2 == "[":
                    ch3 = sys.stdin.read(1)
                    if ch3 == "A":
                        return "up"
                    if ch3 == "B":
                        return "down"
                return "esc"
            if ch == "\r" or ch == "\n":
                return "enter"
            if ch == " ":
                return "space"
            return ch.lower()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


class TuiExplorer:
    """Interactive terminal dashboard for exploring diagnostic findings."""

    def __init__(self, result: ScanResult, console: Console | None = None) -> None:
        self.result = result
        self.console = console or Console()
        self.selected_idx = 0
        self.scroll_offset = 0
        self.expanded = True
        self.show_tree = False
        self.status_message = ""

    def _get_visible_count(self) -> int:
        """Calculate number of list rows visible given terminal height."""
        term_height = self.console.height or 24
        # Subtract header (4), footer (3), panel borders (2), table header (1), scroll indicators (2)
        return max(4, term_height - 12)

    def run(self) -> None:
        """Launch the interactive dashboard loop."""
        if not self.result.diagnostics:
            self.console.print(
                Panel(
                    "[bold green]✨ Project is 100% healthy! No issues to inspect.[/bold green]",
                    title="qv inspect",
                )
            )
            return

        with Live(
            self._render_view(),
            console=self.console,
            screen=True,
            auto_refresh=False,
        ) as live:
            while True:
                live.update(self._render_view(), refresh=True)
                key = _getch()

                if key in ("q", "esc"):
                    break
                elif key in ("up", "k"):
                    if self.selected_idx > 0:
                        self.selected_idx -= 1
                        if self.selected_idx < self.scroll_offset:
                            self.scroll_offset = self.selected_idx
                    self.status_message = ""
                elif key in ("down", "j"):
                    if self.selected_idx < len(self.result.diagnostics) - 1:
                        self.selected_idx += 1
                        visible_count = self._get_visible_count()
                        if self.selected_idx >= self.scroll_offset + visible_count:
                            self.scroll_offset = self.selected_idx - visible_count + 1
                    self.status_message = ""
                elif key in ("enter", "space"):
                    self.expanded = not self.expanded
                elif key == "t":
                    self.show_tree = not self.show_tree
                    self.status_message = (
                        "Switched to Tree View" if self.show_tree else "Switched to Diagnostics"
                    )
                elif key == "f":
                    self._apply_fix_on_selected()

    def _apply_fix_on_selected(self) -> None:
        if not self.result.diagnostics:
            return
        selected = self.result.diagnostics[self.selected_idx]
        engine = RemediationEngine(project_root=Path(self.result.project_path))
        plan = engine.plan_fixes(self.result, rule_filter=selected.id)
        if not plan.actions:
            self.status_message = (
                f"[yellow]No automated fix available for rule {selected.id}[/yellow]"
            )
            return

        res = engine.apply_plan(plan, dry_run=False)
        if res.success:
            self.status_message = (
                f"[bold green]✔ Successfully applied fix for {selected.id}![/bold green]"
            )
        else:
            self.status_message = f"[red]✖ Fix failed for {selected.id}[/red]"

    def _render_view(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=4),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3),
        )

        # Header
        score = self.result.health_score
        score_color = "green" if score >= 80 else ("yellow" if score >= 50 else "red")
        header_text = Text()
        header_text.append(
            f"🔍 qv Explorer  •  Project: {self.result.project_name}  •  ", style="bold cyan"
        )
        header_text.append(f"Health Score: {score}/100\n", style=f"bold {score_color}")
        header_text.append(
            f"Python: {self.result.python_version}  |  Package Manager: {self.result.package_manager.upper()}  |  "
            f"Errors: {self.result.error_count}  |  Warnings: {self.result.warning_count}  |  Checks Passed: {self.result.checks_passed}",
            style="dim",
        )
        layout["header"].update(Panel(header_text, border_style="cyan"))

        # Main view
        if self.show_tree:
            from qv.core.config import QvConfig
            from qv.core.project import ProjectDiscovery

            discovery = ProjectDiscovery(root=Path(self.result.project_path), config=QvConfig())
            context = discovery.discover_context()
            tree = TreeVisualizer(context=context).build_dependency_tree()
            layout["main"].update(
                Panel(tree, title="Dependency Tree (Press 't' to toggle)", border_style="blue")
            )
        else:
            layout["main"].split_row(
                Layout(name="list", ratio=1),
                Layout(name="details", ratio=1),
            )
            layout["main"]["list"].update(self._render_list_panel())
            layout["main"]["details"].update(self._render_details_panel())

        # Footer
        footer_text = Text()
        if self.status_message:
            footer_text.append(f"{self.status_message}  |  ", style="bold")
        footer_text.append(
            "[↑/k, ↓/j] Navigate  •  [Enter] Expand  •  [f] Apply Fix  •  [t] Tree View  •  [q] Quit",
            style="bold white",
        )
        layout["footer"].update(Panel(footer_text, border_style="dim"))

        return layout

    def _render_list_panel(self) -> Panel:
        table = Table(
            box=None, expand=True, show_header=True, header_style="bold dim", pad_edge=False
        )
        table.add_column("", width=3, no_wrap=True)
        table.add_column("Sev", width=5, no_wrap=True)
        table.add_column("Rule", width=8, no_wrap=True)
        table.add_column("Title", ratio=1, no_wrap=True, overflow="ellipsis")

        total_count = len(self.result.diagnostics)
        visible_count = self._get_visible_count()

        # Adjust scroll offset to ensure selected item is in viewport
        if self.selected_idx < self.scroll_offset:
            self.scroll_offset = self.selected_idx
        elif self.selected_idx >= self.scroll_offset + visible_count:
            self.scroll_offset = max(0, self.selected_idx - visible_count + 1)

        # Clamp scroll offset within valid bounds
        self.scroll_offset = max(0, min(self.scroll_offset, max(0, total_count - visible_count)))

        start_idx = self.scroll_offset
        end_idx = min(total_count, start_idx + visible_count)

        if start_idx > 0:
            table.add_row("", "", "▲", f"[dim italic]... {start_idx} more above ...[/dim italic]")

        for i in range(start_idx, end_idx):
            d = self.result.diagnostics[i]
            is_selected = i == self.selected_idx
            cursor = "👉" if is_selected else "  "
            style = (
                "bold white on blue"
                if is_selected
                else ("red" if d.severity == Severity.ERROR else "yellow")
            )
            sev_badge = "ERR" if d.severity == Severity.ERROR else "WARN"

            table.add_row(
                cursor,
                sev_badge,
                d.id,
                d.title,
                style=style,
            )

        if end_idx < total_count:
            remaining = total_count - end_idx
            table.add_row("", "", "▼", f"[dim italic]... {remaining} more below ...[/dim italic]")

        return Panel(
            table,
            title=f"Findings ({self.selected_idx + 1}/{total_count})",
            border_style="cyan",
        )

    def _render_details_panel(self) -> Panel:
        if not self.result.diagnostics:
            return Panel(Text("No findings selected", style="dim"), title="Details")

        selected = self.result.diagnostics[self.selected_idx]
        details_text = Text()

        # Severity & Title
        sev_style = "bold red" if selected.severity == Severity.ERROR else "bold yellow"
        details_text.append(
            f"[{selected.severity.value.upper()}] {selected.id}: {selected.title}\n",
            style=sev_style,
        )
        if selected.file:
            details_text.append(
                f"Location: {selected.file}{f':{selected.line}' if selected.line else ''}\n",
                style="cyan",
            )
        details_text.append("\n")

        # Message
        details_text.append(f"{selected.message}\n\n", style="white")

        # Evidence
        if selected.evidence:
            details_text.append("Evidence:\n", style="bold underline")
            for ev in selected.evidence:
                details_text.append(f"  • {ev.fact} ", style="bold")
                details_text.append(f"({ev.source})\n", style="dim")
            details_text.append("\n")

        # Suggestions
        if selected.suggestions:
            details_text.append("Remediation:\n", style="bold underline green")
            for sug in selected.suggestions:
                details_text.append(f"  👉 {sug.description}\n", style="green")
                if sug.command:
                    details_text.append(f"     $ {sug.command}\n", style="bold green")
                elif sug.code_snippet:
                    details_text.append(f"     {sug.code_snippet}\n", style="bold green")

        if selected.doc_url:
            details_text.append(f"\nDocumentation: {selected.doc_url}\n", style="dim blue")

        return Panel(
            details_text,
            title=f"Details: {selected.id}",
            border_style="green",
        )
