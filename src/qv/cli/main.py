"""qv CLI entry points."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel

from qv import __version__
from qv.analyzers.dependencies.analyzer import DependencyAnalyzer
from qv.analyzers.environment.drift import EnvironmentAnalyzer
from qv.analyzers.imports.analyzer import ImportAnalyzer
from qv.core.config import QvConfig
from qv.core.engine import AnalysisEngine
from qv.core.models import Severity
from qv.core.project import ProjectDiscovery
from qv.reporters.json_reporter import JsonReporter
from qv.reporters.sarif import SarifReporter
from qv.reporters.terminal import TerminalReporter
from qv.rules.registry import RULES_CATALOG, get_rule_definition

if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
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
def scan(
    path: Path,
    strict: bool,
    ci_mode: bool,
    as_json: bool,
    as_sarif: bool,
    output: Path | None,
) -> None:
    """Scan a Python project and report health findings."""
    try:
        pyproject_path = path / "pyproject.toml"
        config = QvConfig.from_pyproject(pyproject_path if pyproject_path.exists() else None)
        if strict or ci_mode:
            config.strict = True

        discovery = ProjectDiscovery(root=path, config=config)
        context = discovery.discover_context()

        engine = AnalysisEngine(config=config)
        result = engine.run(context)

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


@cli.command("version")
def version_cmd() -> None:
    """Print qv version."""
    console.print(f"qv v{__version__}")


def main() -> None:
    """Main entrypoint for setuptools / script runner."""
    cli()


if __name__ == "__main__":
    main()
