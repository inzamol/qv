"""qv CLI entry points."""

from __future__ import annotations

import sys
from collections.abc import Callable, Generator
from contextlib import contextmanager
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from qv import __version__
from qv.analyzers.ci.analyzer import CIAnalyzer
from qv.analyzers.dependencies.analyzer import DependencyAnalyzer
from qv.analyzers.docker.analyzer import DockerAnalyzer
from qv.analyzers.environment.drift import EnvironmentAnalyzer
from qv.analyzers.imports.analyzer import ImportAnalyzer
from qv.core.baseline import filter_against_baseline, load_baseline_fingerprints, save_baseline
from qv.core.config import ConfigurationError
from qv.core.engine import AnalysisEngine
from qv.core.models import ScanResult, Severity
from qv.core.pr import PRAnalyzer
from qv.core.project import load_project
from qv.frameworks import AVAILABLE_FRAMEWORK_ANALYZERS
from qv.remediation.engine import RemediationEngine
from qv.remediation.models import FixActionType, FixPlan
from qv.reporters.doctor_reporter import DoctorReporter
from qv.reporters.github_annotator import GitHubAnnotator
from qv.reporters.html_reporter import HtmlReporter
from qv.reporters.json_reporter import JsonReporter
from qv.reporters.pr_reporter import PRReporter
from qv.reporters.sarif import SarifReporter
from qv.reporters.terminal import TerminalReporter
from qv.rules.registry import RULES_CATALOG, get_rule_definition
from qv.tui.app import TuiExplorer
from qv.visualizers.risk_graph import DependencyRiskGraph
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


@contextmanager
def _handle_cli_errors(action_name: str) -> Generator[None, None, None]:
    """Uniformly handle configuration, click, and unexpected runtime errors across CLI commands."""
    try:
        yield
    except ConfigurationError as e:
        console.print(f"[bold red]Configuration error:[/bold red] {e}")
        sys.exit(2)
    except click.ClickException:
        raise
    except SystemExit:
        raise
    except Exception as e:
        console.print(f"[bold red]{action_name} failed:[/bold red] {e}")
        sys.exit(3)
    finally:
        pass


def _run_analysis_pipeline(
    path: Path,
    strict: bool = False,
    ci_mode: bool = False,
    offline: bool = False,
    hide_warnings: bool = False,
    errors_only: bool = False,
    min_severity: str | None = None,
    html_output: Path | None = None,
    github_annotations: bool = False,
    baseline_path: Path | None = None,
) -> ScanResult:
    """Load project context, apply configuration flags, execute engine, and emit annotations/HTML."""
    project = load_project(path)
    config = project.config
    if strict or ci_mode:
        config.strict = True
    if offline:
        config.offline = True
    if hide_warnings:
        config.hide_warnings = True
    if errors_only:
        config.errors_only = True
    if min_severity:
        config.min_severity = Severity(min_severity.lower())

    engine = AnalysisEngine(config=config)
    result = engine.run(project.context)

    if baseline_path and baseline_path.exists() and baseline_path.is_file():
        fps = load_baseline_fingerprints(baseline_path)
        new_diags, suppressed = filter_against_baseline(result.diagnostics, fps)
        result = ScanResult.create(
            project_name=result.project_name,
            project_path=result.project_path,
            python_version=result.python_version,
            package_manager=result.package_manager,
            diagnostics=new_diags,
            checks_passed=result.summary.checks_passed + suppressed,
            root_causes=result.root_causes,
            analyzer_results=result.analyzer_results,
        )

    if github_annotations or ci_mode:
        annotator = GitHubAnnotator()
        if github_annotations:
            annotator.emit_annotations(result)
        annotator.write_step_summary(result)

    if html_output:
        html_content = HtmlReporter().render(result)
        html_output.write_text(html_content, encoding="utf-8")
        console.print(f"[green]HTML report successfully written to {html_output}[/green]")

    return result


def _render_and_dispatch_output(
    result: ScanResult,
    rendered: str | None,
    default_renderer: Callable[[], str],
    print_handler: Callable[[], None],
    output: Path | None,
    success_message: str,
    strict: bool,
    ci_mode: bool,
) -> None:
    """Output rendered report to disk or terminal, exiting with appropriate exit code."""
    if output:
        content_to_write = rendered if rendered is not None else default_renderer()
        output.write_text(content_to_write, encoding="utf-8")
        console.print(f"[green]{success_message} {output}[/green]")
    elif rendered is not None:
        click.echo(rendered)
    else:
        print_handler()

    if result.has_blocking_errors or ((strict or ci_mode) and result.summary.warnings_count > 0):
        sys.exit(1)
    sys.exit(0)


@click.group(invoke_without_command=False)
@click.version_option(version=__version__, prog_name="qv")
def cli() -> None:
    """qv - Diagnose why a Python project is unhealthy."""
    pass


@cli.command("doctor")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option("--strict", is_flag=True, help="Promote warnings to errors (fails CI on warnings).")
@click.option("--ci", "ci_mode", is_flag=True, help="Run in CI mode with non-interactive output.")
@click.option("--json", "as_json", is_flag=True, help="Output health scorecard in JSON format.")
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
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Filter findings against existing baseline snapshot.",
)
@click.option(
    "--top",
    "top_n",
    type=int,
    default=3,
    help="Number of top problems to highlight (default: 3).",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["terminal", "json", "sarif", "html", "text"], case_sensitive=False),
    default=None,
    help="Output format (terminal, json, sarif, html, text).",
)
def doctor_cmd(
    path: Path,
    strict: bool,
    ci_mode: bool,
    as_json: bool,
    as_sarif: bool,
    output: Path | None,
    offline: bool,
    html_output: Path | None,
    github_annotations: bool,
    baseline_path: Path | None = None,
    top_n: int = 3,
    output_format: str | None = None,
) -> None:
    """Give a complete project health report and diagnosis.

    Print the scorecard, or overwrite --output with a UTF-8 report. SARIF takes
    precedence over JSON when both are requested. --format enables JSON or SARIF;
    its other values use the default scorecard unless a format flag is set.
    --html writes an additional dashboard. --top limits scorecard problems;
    nonpositive values still show one problem when findings exist.

    --strict and --ci promote warnings to errors. --ci or --github-annotations
    appends a summary when GITHUB_STEP_SUMMARY is set; summary write failures
    are ignored. Only --github-annotations emits workflow annotations.

    Raise SystemExit with code 0 on success, 1 for blocking errors (including
    analyzer failures) or warnings in strict/CI mode, 2 for configuration errors,
    or 3 for other caught failures, including report file write errors. Click
    exceptions and existing SystemExit exceptions propagate unchanged.
    """
    if output_format:
        fmt = output_format.lower()
        if fmt == "json":
            as_json = True
        elif fmt == "sarif":
            as_sarif = True

    with _handle_cli_errors("Doctor analysis"):
        result = _run_analysis_pipeline(
            path=path,
            strict=strict,
            ci_mode=ci_mode,
            offline=offline,
            html_output=html_output,
            github_annotations=github_annotations,
            baseline_path=baseline_path,
        )

        doctor_reporter = DoctorReporter(console=console, top_n=top_n)
        rendered = (
            SarifReporter().render(result)
            if as_sarif
            else doctor_reporter.build_report(result).to_json(indent=2)
            if as_json
            else None
        )

        _render_and_dispatch_output(
            result=result,
            rendered=rendered,
            default_renderer=lambda: doctor_reporter.render(result),
            print_handler=lambda: doctor_reporter.print_result(result),
            output=output,
            success_message="Health report successfully written to",
            strict=strict,
            ci_mode=ci_mode,
        )


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
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Filter findings against existing baseline snapshot.",
)
@click.option(
    "--hide-warnings",
    "--no-warnings",
    "-W",
    is_flag=True,
    help="Hide warning diagnostics from output.",
)
@click.option(
    "--errors-only",
    "-E",
    is_flag=True,
    help="Only show error diagnostics (hide warnings and info).",
)
@click.option(
    "--severity",
    "--min-severity",
    "min_severity",
    type=click.Choice(["error", "warning", "info"], case_sensitive=False),
    help="Filter findings by minimum severity level.",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["json", "sarif", "html", "terminal", "text"], case_sensitive=False),
    default=None,
    help="Output format (json, sarif, html, terminal, text).",
)
@click.option(
    "--pr",
    "is_pr",
    is_flag=True,
    help="Run Pull Request differential analysis (analyzes changed code vs base branch).",
)
@click.option(
    "--pr-base",
    "pr_base",
    type=str,
    default=None,
    help="Base git branch or ref for PR differential analysis.",
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
    baseline_path: Path | None = None,
    hide_warnings: bool = False,
    errors_only: bool = False,
    min_severity: str | None = None,
    output_format: str | None = None,
    is_pr: bool = False,
    pr_base: str | None = None,
) -> None:
    """Scan a Python project and report health findings."""
    if output_format:
        fmt = output_format.lower()
        if fmt == "json":
            as_json = True
        elif fmt == "sarif":
            as_sarif = True

    if is_pr:
        with _handle_cli_errors("PR analysis"):
            analyzer = PRAnalyzer(project_root=path)
            pr_result = analyzer.analyze(
                base_ref=pr_base,
                baseline_path=baseline_path,
            )
            reporter = PRReporter(console=console)

            if github_annotations or ci_mode:
                reporter.emit_annotations(pr_result)
                reporter.write_step_summary(pr_result)

            if as_sarif:
                new_scan_result = ScanResult.create(
                    project_name=pr_result.project_name,
                    project_path=pr_result.project_path,
                    python_version="3.12",
                    package_manager="uv",
                    diagnostics=pr_result.new_issues,
                )
                rendered = SarifReporter().render(new_scan_result)
            elif as_json:
                import json

                rendered = json.dumps(pr_result.to_dict(), indent=2)
            else:
                rendered = None

            _render_and_dispatch_output(
                result=ScanResult.create(
                    project_name=pr_result.project_name,
                    project_path=pr_result.project_path,
                    python_version="3.12",
                    package_manager="uv",
                    diagnostics=pr_result.new_issues,
                ),
                rendered=rendered,
                default_renderer=lambda: reporter.render(pr_result),
                print_handler=lambda: reporter.print_result(pr_result),
                output=output,
                success_message="PR report successfully written to",
                strict=strict,
                ci_mode=ci_mode,
            )
        return

    with _handle_cli_errors("Analysis"):
        result = _run_analysis_pipeline(
            path=path,
            strict=strict,
            ci_mode=ci_mode,
            offline=offline,
            hide_warnings=hide_warnings,
            errors_only=errors_only,
            min_severity=min_severity,
            html_output=html_output,
            github_annotations=github_annotations,
            baseline_path=baseline_path,
        )

        rendered = (
            SarifReporter().render(result)
            if as_sarif
            else JsonReporter().render(result)
            if as_json
            else None
        )

        terminal_reporter = TerminalReporter(console=console)
        _render_and_dispatch_output(
            result=result,
            rendered=rendered,
            default_renderer=lambda: TerminalReporter().render(result),
            print_handler=lambda: terminal_reporter.print_result(result),
            output=output,
            success_message="Report successfully written to",
            strict=strict,
            ci_mode=ci_mode,
        )


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
@click.option(
    "--graph",
    "-g",
    is_flag=True,
    help="Visualize annotated dependency risk and usage graph.",
)
@click.option(
    "--risk",
    "-r",
    type=click.Choice(
        ["all", "critical", "high", "medium", "low", "healthy"], case_sensitive=False
    ),
    default=None,
    help="Filter dependency graph by risk level.",
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
    "--no-annotate",
    is_flag=True,
    help="Hide detailed node annotation metadata.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Output dependency risk graph or scan diagnostics as structured JSON.",
)
def dependency_cmd(
    path: Path,
    graph: bool,
    risk: str | None,
    max_depth: int,
    no_annotate: bool,
    as_json: bool,
) -> None:
    """Run dependency-focused checks or render annotated dependency risk graph."""
    with _handle_cli_errors("Dependency analysis"):
        project = load_project(path)
        engine = AnalysisEngine(config=project.config, analyzers=[DependencyAnalyzer()])
        result = engine.run(project.context)

        # If user explicitly requests graph or risk filtering
        if graph or risk is not None:
            risk_graph = DependencyRiskGraph(
                context=project.context,
                diagnostics=result.diagnostics,
            )
            if as_json:
                import json

                click.echo(json.dumps(risk_graph.to_dict(), indent=2))
                sys.exit(0)

            console.print("\n[bold cyan]Dependency Risk & Usage Graph[/bold cyan]\n")
            console.print(
                risk_graph.build_tree(
                    annotate=not no_annotate,
                    risk_filter=risk,
                    max_depth=max_depth,
                )
            )
            console.print()
            sys.exit(0)

        if as_json:
            reporter = JsonReporter()
            click.echo(reporter.render(result))
        else:
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
    with _handle_cli_errors("Environment analysis"):
        project = load_project(path)
        engine = AnalysisEngine(config=project.config, analyzers=[EnvironmentAnalyzer()])
        result = engine.run(project.context)
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
    with _handle_cli_errors("Architecture analysis"):
        project = load_project(path)
        engine = AnalysisEngine(config=project.config, analyzers=[ImportAnalyzer()])
        result = engine.run(project.context)
        TerminalReporter(console=console).print_result(result)
        sys.exit(1 if result.has_blocking_errors else 0)


@cli.command("docker")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
def docker_cmd(path: Path) -> None:
    """Run Docker and container configuration checks only."""
    with _handle_cli_errors("Docker analysis"):
        project = load_project(path)
        engine = AnalysisEngine(config=project.config, analyzers=[DockerAnalyzer()])
        result = engine.run(project.context)
        TerminalReporter(console=console).print_result(result)
        sys.exit(1 if result.has_blocking_errors else 0)


@cli.command("ci")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
def ci_cmd(path: Path) -> None:
    """Run CI/CD workflow checks only."""
    with _handle_cli_errors("CI workflow analysis"):
        project = load_project(path)
        engine = AnalysisEngine(config=project.config, analyzers=[CIAnalyzer()])
        result = engine.run(project.context)
        TerminalReporter(console=console).print_result(result)
        sys.exit(1 if result.has_blocking_errors else 0)


@cli.group("baseline")
def baseline_group() -> None:
    """Manage diagnostic baseline snapshots for legacy codebases."""
    pass


@baseline_group.command("record")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    default=Path(".qv-baseline.json"),
    help="Target baseline snapshot file (default: .qv-baseline.json).",
)
def baseline_record_cmd(path: Path, output: Path) -> None:
    """Record current diagnostic snapshot into baseline file."""
    with _handle_cli_errors("Baseline recording"):
        project = load_project(path)
        engine = AnalysisEngine(config=project.config)
        result = engine.run(project.context)
        save_baseline(result, output)
        console.print(
            f"[bold green]✓ Recorded {len(result.diagnostics)} diagnostic finding(s) into baseline {output}[/bold green]"
        )
        sys.exit(0)


@baseline_group.command("verify")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option(
    "--baseline",
    "-b",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=Path(".qv-baseline.json"),
    help="Path to baseline snapshot file (default: .qv-baseline.json).",
)
@click.option("--strict", is_flag=True, help="Fail if any new diagnostics are detected.")
def baseline_verify_cmd(path: Path, baseline: Path, strict: bool) -> None:
    """Verify project against baseline snapshot, reporting only newly introduced violations."""
    with _handle_cli_errors("Baseline verification"):
        project = load_project(path)
        engine = AnalysisEngine(config=project.config)
        result = engine.run(project.context)
        fps = load_baseline_fingerprints(baseline)
        new_diags, suppressed = filter_against_baseline(result.diagnostics, fps)

        filtered_result = ScanResult.create(
            project_name=result.project_name,
            project_path=result.project_path,
            python_version=result.python_version,
            package_manager=result.package_manager,
            diagnostics=new_diags,
            checks_passed=result.summary.checks_passed + suppressed,
            root_causes=result.root_causes,
            analyzer_results=result.analyzer_results,
        )
        TerminalReporter(console=console).print_result(filtered_result)
        if suppressed:
            console.print(f"[dim]({suppressed} baseline findings suppressed)[/dim]\n")
        if filtered_result.has_blocking_errors or (
            strict and filtered_result.summary.warnings_count > 0
        ):
            sys.exit(1)
        sys.exit(0)


@cli.command("pr")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option(
    "--base",
    "-b",
    "base_ref",
    type=str,
    default=None,
    help="Base git branch or ref (default: auto-detect from GITHUB_BASE_REF or git history).",
)
@click.option(
    "--head",
    "head_ref",
    type=str,
    default="HEAD",
    help="Head git commit or ref (default: HEAD).",
)
@click.option("--strict", is_flag=True, help="Promote warnings to errors (fails CI on warnings).")
@click.option("--ci", "ci_mode", is_flag=True, help="Run in CI mode with non-interactive output.")
@click.option(
    "--github-annotations",
    is_flag=True,
    help="Emit GitHub Actions inline workflow command annotations for new issues.",
)
@click.option("--json", "as_json", is_flag=True, help="Output PR analysis in JSON format.")
@click.option(
    "--sarif", "as_sarif", is_flag=True, help="Output new PR issues in SARIF v2.1.0 format."
)
@click.option(
    "--comment",
    is_flag=True,
    help="Output formatted Markdown suitable for GitHub PR comments.",
)
@click.option(
    "--output", "-o", type=click.Path(dir_okay=False, path_type=Path), help="Write output to file."
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Filter findings against existing baseline snapshot.",
)
@click.option(
    "--files",
    "files_list",
    type=str,
    default=None,
    help="Comma-separated list of changed files (e.g. 'users.py,models.py').",
)
@click.option(
    "--diff",
    "diff_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to unified diff patch file.",
)
def pr_cmd(
    path: Path,
    base_ref: str | None,
    head_ref: str,
    strict: bool,
    ci_mode: bool,
    github_annotations: bool,
    as_json: bool,
    as_sarif: bool,
    comment: bool,
    output: Path | None,
    baseline_path: Path | None,
    files_list: str | None,
    diff_file: Path | None,
) -> None:
    """Analyze changed code in a Pull Request and report newly introduced vs resolved issues."""
    with _handle_cli_errors("Pull Request analysis"):
        changed_files = (
            [f.strip() for f in files_list.split(",") if f.strip()] if files_list else None
        )
        diff_text = diff_file.read_text(encoding="utf-8") if diff_file else None

        analyzer = PRAnalyzer(project_root=path)
        pr_result = analyzer.analyze(
            base_ref=base_ref,
            head_ref=head_ref,
            baseline_path=baseline_path,
            changed_files_list=changed_files,
            diff_text=diff_text,
        )

        reporter = PRReporter(console=console)

        if ci_mode or github_annotations:
            reporter.emit_annotations(pr_result)
            reporter.write_step_summary(pr_result)

        if as_sarif:
            new_scan_result = ScanResult.create(
                project_name=pr_result.project_name,
                project_path=pr_result.project_path,
                python_version="3.12",
                package_manager="uv",
                diagnostics=pr_result.new_issues,
            )
            sarif_text = SarifReporter().render(new_scan_result)
            if output:
                output.write_text(sarif_text, encoding="utf-8")
                console.print(f"[green]SARIF report successfully written to {output}[/green]")
            else:
                click.echo(sarif_text)
        elif as_json:
            import json

            json_text = json.dumps(pr_result.to_dict(), indent=2)
            if output:
                output.write_text(json_text, encoding="utf-8")
                console.print(f"[green]JSON report successfully written to {output}[/green]")
            else:
                click.echo(json_text)
        elif comment:
            md_text = reporter.render_markdown(pr_result)
            if output:
                output.write_text(md_text, encoding="utf-8")
                console.print(
                    f"[green]PR comment markdown successfully written to {output}[/green]"
                )
            else:
                click.echo(md_text)
        else:
            if output:
                rendered_term = reporter.render(pr_result)
                output.write_text(rendered_term, encoding="utf-8")
                console.print(f"[green]PR report successfully written to {output}[/green]")
            else:
                reporter.print_result(pr_result)

        if pr_result.has_blocking_errors or (
            (strict or ci_mode) and pr_result.new_warnings_count > 0
        ):
            sys.exit(1)
        sys.exit(0)


@cli.command("pr-analysis")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option("--base", "-b", "base_ref", type=str, default=None, help="Base git branch or ref.")
@click.option("--head", "head_ref", type=str, default="HEAD", help="Head git ref.")
@click.option("--strict", is_flag=True, help="Promote warnings to errors.")
@click.option("--ci", "ci_mode", is_flag=True, help="Run in CI mode.")
@click.option("--github-annotations", is_flag=True, help="Emit GitHub workflow annotations.")
@click.option("--json", "as_json", is_flag=True, help="Output JSON.")
@click.option("--sarif", "as_sarif", is_flag=True, help="Output SARIF.")
@click.option("--comment", is_flag=True, help="Output PR comment markdown.")
@click.option(
    "--output", "-o", type=click.Path(dir_okay=False, path_type=Path), help="Output file."
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Baseline file.",
)
@click.option("--files", "files_list", type=str, default=None, help="Changed files list.")
@click.option(
    "--diff",
    "diff_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Diff file.",
)
@click.pass_context
def pr_analysis_alias(
    ctx: click.Context,
    path: Path,
    base_ref: str | None,
    head_ref: str,
    strict: bool,
    ci_mode: bool,
    github_annotations: bool,
    as_json: bool,
    as_sarif: bool,
    comment: bool,
    output: Path | None,
    baseline_path: Path | None,
    files_list: str | None,
    diff_file: Path | None,
) -> None:
    """Alias for 'qv pr' command."""
    ctx.invoke(
        pr_cmd,
        path=path,
        base_ref=base_ref,
        head_ref=head_ref,
        strict=strict,
        ci_mode=ci_mode,
        github_annotations=github_annotations,
        as_json=as_json,
        as_sarif=as_sarif,
        comment=comment,
        output=output,
        baseline_path=baseline_path,
        files_list=files_list,
        diff_file=diff_file,
    )


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
    "--diff",
    is_flag=True,
    help="Show unified diff preview of proposed file modifications.",
)
@click.option(
    "-i",
    "--interactive",
    is_flag=True,
    help="Interactively review and select each individual fix.",
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
    diff: bool,
    interactive: bool,
    auto_approve: bool,
    rule_filter: str | None,
    execute_sync: bool,
) -> None:
    """Safely and automatically fix detectable diagnostic health issues."""
    try:
        project = load_project(path)
        engine = AnalysisEngine(
            analyzers=[
                DependencyAnalyzer(),
                EnvironmentAnalyzer(),
                ImportAnalyzer(),
            ],
            config=project.config,
        )
        scan_result = engine.run(project.context)

        remediation_engine = RemediationEngine(project_root=project.root)
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
            target = act.target_file
            if not target and act.action_type == FixActionType.EXECUTE_COMMAND:
                if act.executable:
                    target = f"{act.executable} {' '.join(act.args)}"
                else:
                    target = act.command or "command"
            table.add_row(
                act.rule_id,
                target or "pyproject.toml",
                act.description,
                act.action_type.value,
            )

        console.print(table)

        if diff:
            console.print("\n[bold cyan]Proposed File Diffs:[/bold cyan]")
            for act in plan.actions:
                if act.diff:
                    console.print(
                        Panel(
                            act.diff,
                            title=f"[yellow]{act.rule_id}[/yellow] — {act.target_file or 'command'}",
                            border_style="dim",
                        )
                    )

        if dry_run:
            console.print("\n[yellow]Dry-run mode enabled. No changes written to disk.[/yellow]")
            sys.exit(0)

        if interactive:
            selected_actions = []
            for act in plan.actions:
                if click.confirm(
                    f"Apply fix for [{act.rule_id}] on {act.target_file or 'command'} ({act.description})?",
                    default=act.is_safe,
                ):
                    selected_actions.append(act)
            plan = FixPlan(project_path=plan.project_path, actions=selected_actions)
            result = remediation_engine.apply_plan(
                plan,
                dry_run=False,
                execute_commands=execute_sync,
                only_safe=False,
            )
        elif auto_approve:
            result = remediation_engine.apply_plan(
                plan,
                dry_run=False,
                execute_commands=execute_sync,
                only_safe=True,
            )
        else:
            prompt_msg = (
                "\nApply these safe fixes to your project?"
                if plan.safe_fixes_count == len(plan.actions)
                else "\nApply these fixes to your project (including review-required changes)?"
            )
            default_val = plan.safe_fixes_count == len(plan.actions)
            if not click.confirm(prompt_msg, default=default_val):
                console.print("[yellow]Remediation cancelled by user.[/yellow]")
                sys.exit(0)

            result = remediation_engine.apply_plan(
                plan,
                dry_run=False,
                execute_commands=execute_sync,
                only_safe=False,
            )

        console.print(
            f"\n[bold green]✓ Successfully applied {len(result.applied)} fix(es)![/bold green]"
        )
        for act in result.applied:
            console.print(f"  [green]+[/green] {act.description}")

        if result.skipped:
            console.print(f"\n[yellow]Skipped {len(result.skipped)} action(s):[/yellow]")
            for act in result.skipped:
                if not act.is_safe:
                    reason = "requires review before removal"
                elif act.action_type == FixActionType.EXECUTE_COMMAND:
                    reason = "use --sync to run commands"
                else:
                    reason = "requires review"
                console.print(f"  [dim]- {act.description} ({reason})[/dim]")

        if result.failed:
            console.print(f"\n[bold red]Failed {len(result.failed)} action(s):[/bold red]")
            for act, err in result.failed:
                console.print(f"  [red]✗ {act.description}: {err}[/red]")
            sys.exit(1)

        sys.exit(0)

    except ConfigurationError as e:
        console.print(f"[bold red]Configuration error:[/bold red] {e}")
        sys.exit(2)
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
    "--risk",
    "-r",
    "show_risk",
    is_flag=True,
    help="Annotate dependency tree with risk levels, AST imports, and driver classifications.",
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
    show_risk: bool,
    max_depth: int,
    as_json: bool,
) -> None:
    """Visualize dependency trees, risk graphs, and import architecture."""
    with _handle_cli_errors("Tree visualization"):
        project = load_project(path)

        if show_risk:
            engine = AnalysisEngine(config=project.config, analyzers=[DependencyAnalyzer()])
            result = engine.run(project.context)
            risk_graph = DependencyRiskGraph(
                context=project.context,
                diagnostics=result.diagnostics,
            )
            if as_json:
                import json

                click.echo(json.dumps(risk_graph.to_dict(), indent=2))
                sys.exit(0)

            console.print("\n[bold cyan]Dependency Risk & Usage Graph[/bold cyan]\n")
            console.print(risk_graph.build_tree(annotate=True, max_depth=max_depth))
            console.print()
            sys.exit(0)

        visualizer = TreeVisualizer(context=project.context)

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
@click.option(
    "--risk", "-r", "show_risk", is_flag=True, help="Show dependency risk and classification graph."
)
@click.option("--depth", "-L", "max_depth", type=int, default=5, help="Maximum tree depth.")
@click.option("--json", "as_json", is_flag=True, help="Output JSON.")
@click.pass_context
def graph_cmd(
    ctx: click.Context,
    path: Path,
    show_imports: bool,
    show_dependencies: bool,
    show_risk: bool,
    max_depth: int,
    as_json: bool,
) -> None:
    """Alias for 'qv tree' command (or dependency risk graph with --risk)."""
    ctx.invoke(
        tree_cmd,
        path=path,
        show_imports=show_imports,
        show_dependencies=show_dependencies,
        show_risk=show_risk,
        max_depth=max_depth,
        as_json=as_json,
    )


@cli.command("framework")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option(
    "--name",
    "-n",
    type=str,
    default=None,
    help="Filter by framework plugin name (e.g. 'fastapi', 'sqlalchemy', 'sql').",
)
@click.option("--json", "as_json", is_flag=True, help="Output JSON results.")
@click.option("--sarif", "as_sarif", is_flag=True, help="Output SARIF results.")
def framework_cmd(path: Path, name: str | None, as_json: bool, as_sarif: bool) -> None:
    """Run framework-specific doctors (FastAPI, SQLAlchemy)."""
    with _handle_cli_errors("Framework analysis"):
        project = load_project(path)

        # Select framework analyzers
        analyzers_to_run = []
        for cls in AVAILABLE_FRAMEWORK_ANALYZERS:
            inst = cls()
            if name:
                target_name = name.lower()
                if target_name in (inst.id.lower(), inst.name.lower()) or (
                    target_name == "sql" and inst.id == "sqlalchemy"
                ):
                    analyzers_to_run.append(inst)
            else:
                analyzers_to_run.append(inst)

        if not analyzers_to_run:
            console.print(
                f"[bold red]Unknown framework '{name}'. Available: fastapi, sqlalchemy, django, celery[/bold red]"
            )
            sys.exit(2)

        engine = AnalysisEngine(config=project.config, analyzers=analyzers_to_run)
        result = engine.run(project.context)

        if as_json:
            reporter = JsonReporter()
            click.echo(reporter.render(result))
        elif as_sarif:
            reporter = SarifReporter()
            click.echo(reporter.render(result))
        else:
            TerminalReporter(console=console).print_result(result)

        if result.has_blocking_errors:
            sys.exit(1)
        sys.exit(0)


@cli.command("frameworks")
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option("--name", "-n", type=str, default=None, help="Filter by framework plugin name.")
@click.option("--json", "as_json", is_flag=True, help="Output JSON results.")
@click.option("--sarif", "as_sarif", is_flag=True, help="Output SARIF results.")
@click.pass_context
def frameworks_cmd(
    ctx: click.Context, path: Path, name: str | None, as_json: bool, as_sarif: bool
) -> None:
    """Alias for 'qv framework' command."""
    ctx.invoke(framework_cmd, path=path, name=name, as_json=as_json, as_sarif=as_sarif)


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
        project = load_project(path)
        if offline:
            project.config.offline = True

        engine = AnalysisEngine(config=project.config)
        result = engine.run(project.context)

        explorer = TuiExplorer(result=result, console=console)
        explorer.run()
    except ConfigurationError as e:
        console.print(f"[bold red]Configuration error:[/bold red] {e}")
        sys.exit(2)
    except click.ClickException:
        raise
    except SystemExit:
        raise
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
