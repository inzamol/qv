"""qv CLI entry points."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from qv import __version__
from qv.analyzers.dependencies.analyzer import DependencyAnalyzer
from qv.analyzers.environment.drift import EnvironmentAnalyzer
from qv.analyzers.imports.analyzer import ImportAnalyzer
from qv.core.config import QvConfig
from qv.core.engine import AnalysisEngine
from qv.core.models import Severity
from qv.core.project import ProjectDiscovery
from qv.remediation.engine import RemediationEngine
from qv.reporters.github_annotator import GitHubAnnotator
from qv.reporters.html_reporter import HtmlReporter
from qv.reporters.json_reporter import JsonReporter
from qv.reporters.sarif import SarifReporter
from qv.reporters.terminal import TerminalReporter
from qv.rules.registry import RULES_CATALOG, get_rule_definition
from qv.tui.app import TuiExplorer
from qv.visualizers.tree import TreeVisualizer

if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")  # pyright: ignore[reportAttributeAccessIssue]
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")  # pyright: ignore[reportAttributeAccessIssue]
    except Exception:
        pass

console = Console()


@click.group(invoke_without_command=False)
@click.version_option(version=__version__, prog_name="qv")
def cli() -> None:
    """qv - Diagnose why a Python project is unhealthy."""
    pass


@cli.command("scan")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option("--strict", is_flag=True, help="Promote warnings to errors (fails CI on warnings).")
@click.option("--ci", "ci_mode", is_flag=True, help="Run in CI mode with non-interactive output.")
@click.option("--json", "as_json", is_flag=True, help="Output diagnostics in JSON format.")
@click.option(
    "--sarif", "as_sarif", is_flag=True, help="Output diagnostics in SARIF v2.1.0 format."
)
@click.option(
    "--output", "-o", type=click.Path(dir_okay=False, path_type=Path), help="Write output to file."
)
@click.option(
    "--offline", is_flag=True, help="Disable remote vulnerability/CVE queries (airgapped mode)."
)
@click.option(
    "--html",
    "html_output",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Generate interactive HTML dashboard report.",
)
@click.option(
    "--github-annotations",
    is_flag=True,
    help="Emit GitHub Actions inline workflow command annotations.",
)
def scan(
    path: Path,
    strict: bool,
    ci_mode: bool,
    as_json: bool,
    as_sarif: bool,
    output: Path | None,
    offline: bool,
    html_output: Path | None,
    github_annotations: bool,
) -> None:
    """Scan a Python project and report health findings."""
    try:
        pyproject_path = path / "pyproject.toml"
        config = QvConfig.from_pyproject(pyproject_path if pyproject_path.exists() else None)
        if strict or ci_mode:
            config.strict = True
        if offline:
            config.offline = True

        discovery = ProjectDiscovery(root=path, config=config)
        context = discovery.discover_context()

        engine = AnalysisEngine(config=config)
        result = engine.run(context)

        # Handle GitHub annotations & step summaries
        if github_annotations or ci_mode:
            annotator = GitHubAnnotator()
            if github_annotations:
                annotator.emit_annotations(result)
            annotator.write_step_summary(result)

        # Handle HTML report output
        if html_output:
            html_content = HtmlReporter().render(result)
            html_output.write_text(html_content, encoding="utf-8")
            console.print(f"[green]HTML report successfully written to {html_output}[/green]")

        # Select reporter
        if as_sarif:
            reporter = SarifReporter()
            rendered = reporter.render(result)
        elif as_json:
            reporter = JsonReporter()
            rendered = reporter.render(result)
        else:
            reporter = TerminalReporter(console=console)
            rendered = None

        if output:
            content_to_write = (
                rendered if rendered is not None else TerminalReporter().render(result)
            )
            output.write_text(content_to_write, encoding="utf-8")
            console.print(f"[green]Report successfully written to {output}[/green]")
        elif rendered is not None:
            click.echo(rendered)
        else:
            TerminalReporter(console=console).print_result(result)

        # Determine exit code
        if result.has_blocking_errors:
            sys.exit(1)
        if (strict or ci_mode) and result.summary.warnings_count > 0:
            sys.exit(1)
        sys.exit(0)

    except click.ClickException:
        raise
    except SystemExit:
        raise
    except Exception as e:
        console.print(f"[bold red]Analysis failed:[/bold red] {e}")
        sys.exit(3)


@cli.command("explain")
@click.argument("rule_id", type=str)
def explain(rule_id: str) -> None:
    """Explain a specific rule and its remediation strategies."""
    rule_def = get_rule_definition(rule_id)
    if not rule_def:
        console.print(f"[bold red]Error:[/bold red] Unknown rule ID '{rule_id}'.")
        console.print("Use one of: " + ", ".join(RULES_CATALOG.keys()))
        sys.exit(2)

    color = "red" if rule_def.default_severity == Severity.ERROR else "yellow"
    panel_content = (
        f"[bold]Category:[/bold] {rule_def.category.title()}\n"
        f"[bold]Default Severity:[/bold] [{color}]{rule_def.default_severity.value.upper()}[/{color}]\n\n"
        f"[bold]Description:[/bold]\n{rule_def.description}\n\n"
        f"[bold cyan]Remediation Recommendation:[/bold cyan]\n{rule_def.remediation_hint}\n\n"
        f"[bold dim]Documentation:[/bold dim]\n{rule_def.doc_url or 'N/A'}"
    )
    panel = Panel(
        panel_content,
        title=f"[bold]{rule_def.id} — {rule_def.title}[/bold]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)


@cli.command("init")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
def init_cmd(path: Path) -> None:
    """Initialize qv configuration in pyproject.toml without overwriting existing settings."""
    pyproject_path = path / "pyproject.toml"
    default_section = """
[tool.qv]
[tool.qv.rules]
DEP-001 = "error"
DEP-002 = "error"
DEP-003 = "warning"
DEP-004 = "warning"
DEP-005 = "warning"
IMP-001 = "error"
IMP-002 = "error"

[tool.qv.paths]
exclude = [
    ".venv",
    "build",
    "dist",
    "node_modules",
]
"""
    if not pyproject_path.exists():
        pyproject_path.write_text(default_section.lstrip(), encoding="utf-8")
        console.print(
            f"[green]Created {pyproject_path} with default [tool.qv] configuration.[/green]"
        )
        return

    content = pyproject_path.read_text(encoding="utf-8")
    if "[tool.qv]" in content or "[tool.pydoctor]" in content:
        console.print(
            "[yellow]pyproject.toml already contains [tool.qv] configuration. Skipping.[/yellow]"
        )
        return

    # Append to existing
    updated = content.rstrip() + "\n" + default_section
    pyproject_path.write_text(updated, encoding="utf-8")
    console.print(f"[green]Added [tool.qv] configuration to {pyproject_path}.[/green]")


@cli.command("dependency")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
def dependency_cmd(path: Path) -> None:
    """Run dependency-focused checks only."""
    discovery = ProjectDiscovery(root=path)
    context = discovery.discover_context()
    engine = AnalysisEngine(analyzers=[DependencyAnalyzer()])
    result = engine.run(context)
    TerminalReporter(console=console).print_result(result)
    sys.exit(1 if result.has_blocking_errors else 0)


@cli.command("environment")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
def environment_cmd(path: Path) -> None:
    """Run environment and runtime drift checks only."""
    discovery = ProjectDiscovery(root=path)
    context = discovery.discover_context()
    engine = AnalysisEngine(analyzers=[EnvironmentAnalyzer()])
    result = engine.run(context)
    TerminalReporter(console=console).print_result(result)
    sys.exit(1 if result.has_blocking_errors else 0)


@cli.command("architecture")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
def architecture_cmd(path: Path) -> None:
    """Run AST and import architecture checks only."""
    discovery = ProjectDiscovery(root=path)
    context = discovery.discover_context()
    engine = AnalysisEngine(analyzers=[ImportAnalyzer()])
    result = engine.run(context)
    TerminalReporter(console=console).print_result(result)
    sys.exit(1 if result.has_blocking_errors else 0)


@cli.command("fix")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Display proposed fixes and diffs without modifying any files.",
)
@click.option(
    "-y",
    "--yes",
    "auto_approve",
    is_flag=True,
    help="Automatically apply all safe fixes without prompting.",
)
@click.option(
    "--rule",
    "rule_filter",
    type=str,
    default=None,
    help="Filter remediation to a specific rule ID (e.g. DEP-002).",
)
@click.option(
    "--sync",
    "execute_sync",
    is_flag=True,
    help="Execute suggested package manager sync/install commands.",
)
def fix_cmd(
    path: Path,
    dry_run: bool,
    auto_approve: bool,
    rule_filter: str | None,
    execute_sync: bool,
) -> None:
    """Safely and automatically fix detectable diagnostic health issues."""
    try:
        pyproject_path = path / "pyproject.toml"
        config = QvConfig.from_pyproject(pyproject_path if pyproject_path.exists() else None)
        discovery = ProjectDiscovery(root=path, config=config)
        context = discovery.discover_context()

        engine = AnalysisEngine(
            analyzers=[
                DependencyAnalyzer(),
                EnvironmentAnalyzer(),
                ImportAnalyzer(),
            ],
            config=config,
        )
        scan_result = engine.run(context)

        remediation_engine = RemediationEngine(project_root=path)
        plan = remediation_engine.plan_fixes(scan_result, rule_filter=rule_filter)

        if not plan.actions:
            console.print("[green]✓ No automated fixes needed. Project is healthy![/green]")
            sys.exit(0)

        console.print(
            f"\n[bold cyan]Found {len(plan.actions)} actionable fix(es)[/bold cyan] ({plan.safe_fixes_count} safe):\n"
        )

        table = Table(
            title="Proposed Fixes",
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            show_lines=False,
        )
        table.add_column("Rule", style="bold yellow", no_wrap=True)
        table.add_column("Target", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Type", style="dim")

        for act in plan.actions:
            table.add_row(
                act.rule_id,
                act.target_file or "shell",
                act.description,
                act.action_type.value,
            )

        console.print(table)

        if dry_run:
            console.print("\n[yellow]Dry-run mode enabled. No changes written to disk.[/yellow]")
            sys.exit(0)

        if not auto_approve:
            if not click.confirm("\nApply these safe fixes to your project?", default=True):
                console.print("[yellow]Remediation cancelled by user.[/yellow]")
                sys.exit(0)

        result = remediation_engine.apply_plan(
            plan,
            dry_run=False,
            execute_commands=execute_sync,
        )

        console.print(
            f"\n[bold green]✓ Successfully applied {len(result.applied)} fix(es)![/bold green]"
        )
        for act in result.applied:
            console.print(f"  [green]+[/green] {act.description}")

        if result.skipped:
            console.print(f"\n[yellow]Skipped {len(result.skipped)} action(s):[/yellow]")
            for act in result.skipped:
                console.print(f"  [dim]- {act.description} (use --sync to run commands)[/dim]")

        if result.failed:
            console.print(f"\n[bold red]Failed {len(result.failed)} action(s):[/bold red]")
            for act, err in result.failed:
                console.print(f"  [red]✗ {act.description}: {err}[/red]")
            sys.exit(1)

        sys.exit(0)

    except (click.Abort, KeyboardInterrupt):
        console.print("\n[yellow]Remediation cancelled.[/yellow]")
        sys.exit(0)
    except click.ClickException:
        raise
    except SystemExit:
        raise
    except Exception as e:
        console.print(f"[bold red]Remediation failed:[/bold red] {e}")
        sys.exit(3)


@cli.command("tree")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option(
    "--imports",
    "-i",
    "show_imports",
    is_flag=True,
    help="Visualize internal source module imports and circular cycles.",
)
@click.option(
    "--dependencies",
    "-d",
    "show_dependencies",
    is_flag=True,
    help="Visualize direct and transitive package dependencies.",
)
@click.option(
    "--depth",
    "-L",
    "max_depth",
    type=int,
    default=5,
    help="Maximum depth level for the tree (default: 5).",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit dependency and module statistics as structured JSON.",
)
def tree_cmd(
    path: Path,
    show_imports: bool,
    show_dependencies: bool,
    max_depth: int,
    as_json: bool,
) -> None:
    """Visualize dependency trees and import architecture."""
    try:
        pyproject_path = path / "pyproject.toml"
        config = QvConfig.from_pyproject(pyproject_path if pyproject_path.exists() else None)
        discovery = ProjectDiscovery(root=path, config=config)
        context = discovery.discover_context()

        visualizer = TreeVisualizer(context=context)

        if as_json:
            import json

            click.echo(json.dumps(visualizer.to_dict(), indent=2))
            sys.exit(0)

        # If user explicitly requested imports
        if show_imports and not show_dependencies:
            console.print("\n[bold cyan]Internal Module Import Architecture[/bold cyan]\n")
            console.print(visualizer.build_import_tree(max_depth=max_depth))
            console.print()
        # If user explicitly requested dependencies
        elif show_dependencies and not show_imports:
            console.print("\n[bold cyan]Dependency Hierarchy[/bold cyan]\n")
            console.print(visualizer.build_dependency_tree(max_depth=max_depth))
            console.print()
        else:
            # Default: show dependency tree, and if circular imports exist, show import tree
            console.print("\n[bold cyan]Dependency Hierarchy[/bold cyan]\n")
            console.print(visualizer.build_dependency_tree(max_depth=max_depth))
            console.print("\n[bold cyan]Internal Module Import Architecture[/bold cyan]\n")
            console.print(visualizer.build_import_tree(max_depth=max_depth))
            console.print()

        sys.exit(0)

    except click.ClickException:
        raise
    except SystemExit:
        raise
    except Exception as e:
        console.print(f"[bold red]Tree visualization failed:[/bold red] {e}")
        sys.exit(3)


@cli.command("graph")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option("--imports", "-i", "show_imports", is_flag=True, help="Show import graph.")
@click.option(
    "--dependencies", "-d", "show_dependencies", is_flag=True, help="Show dependency graph."
)
@click.option("--depth", "-L", "max_depth", type=int, default=5, help="Maximum tree depth.")
@click.option("--json", "as_json", is_flag=True, help="Output JSON.")
@click.pass_context
def graph_cmd(
    ctx: click.Context,
    path: Path,
    show_imports: bool,
    show_dependencies: bool,
    max_depth: int,
    as_json: bool,
) -> None:
    """Alias for 'qv tree' command."""
    ctx.invoke(
        tree_cmd,
        path=path,
        show_imports=show_imports,
        show_dependencies=show_dependencies,
        max_depth=max_depth,
        as_json=as_json,
    )


@cli.command("inspect")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option("--offline", is_flag=True, help="Disable remote vulnerability/CVE queries.")
def inspect_cmd(path: Path, offline: bool) -> None:
    """Launch interactive terminal dashboard (TUI) to explore diagnostics and fixes."""
    try:
        pyproject_path = path / "pyproject.toml"
        config = QvConfig.from_pyproject(pyproject_path if pyproject_path.exists() else None)
        if offline:
            config.offline = True

        discovery = ProjectDiscovery(root=path, config=config)
        context = discovery.discover_context()

        engine = AnalysisEngine(config=config)
        result = engine.run(context)

        explorer = TuiExplorer(result=result, console=console)
        explorer.run()
    except Exception as e:
        console.print(f"[bold red]Error running interactive inspector: {e}[/bold red]")
        sys.exit(3)


@cli.command("ui")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option("--offline", is_flag=True, help="Disable remote vulnerability/CVE queries.")
@click.pass_context
def ui_cmd(ctx: click.Context, path: Path, offline: bool) -> None:
    """Alias for 'qv inspect' command."""
    ctx.invoke(inspect_cmd, path=path, offline=offline)


@cli.command("version")
def version_cmd() -> None:
    """Print qv version."""
    console.print(f"qv v{__version__}")


def main() -> None:
    """Main entrypoint for setuptools / script runner."""
    cli()


if __name__ == "__main__":
    main()
