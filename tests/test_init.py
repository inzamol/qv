"""Unit and CLI integration tests for qv init and workflow generation."""

from pathlib import Path

from click.testing import CliRunner

from qv.analyzers.ci.analyzer import CIAnalyzer
from qv.cli.main import cli
from qv.core.config import QvConfig
from qv.core.models import Severity
from qv.core.project import load_project


def test_init_new_project_creates_pyproject(tmp_path: Path) -> None:
    """Create the default QV configuration and verify its parsed settings."""
    runner = CliRunner()
    result = runner.invoke(cli, ["init", str(tmp_path)])
    assert result.exit_code == 0
    assert "Created" in result.output

    pyproject_file = tmp_path / "pyproject.toml"
    assert pyproject_file.exists()
    content = pyproject_file.read_text(encoding="utf-8")

    expected_snippet = """[tool.qv]
min_severity = "warning"

[tool.qv.dependencies]
ignore = [
    "amqp",
]

[tool.qv.rules]
DEP-003 = "warning"
SQL-014 = "error"

[tool.qv.paths]
exclude = [
    "tests",
    "migrations",
]
"""
    assert expected_snippet.strip() in content.strip()

    # Validate parsing into QvConfig
    cfg = QvConfig.from_pyproject(pyproject_file)
    assert cfg.min_severity == Severity.WARNING
    assert "amqp" in cfg.ignored_dependencies
    assert cfg.rules["DEP-003"].severity == Severity.WARNING
    assert cfg.rules["SQL-014"].severity == Severity.ERROR
    assert cfg.paths.exclude == ["tests", "migrations"]


def test_init_existing_pyproject_without_qv(tmp_path: Path) -> None:
    """Add QV defaults while preserving existing project metadata."""
    pyproject_file = tmp_path / "pyproject.toml"
    pyproject_file.write_text(
        """[project]
name = "my-awesome-app"
version = "1.0.0"
""",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["init", str(tmp_path)])
    assert result.exit_code == 0
    assert "Initialized" in result.output

    content = pyproject_file.read_text(encoding="utf-8")
    assert 'name = "my-awesome-app"' in content
    assert 'version = "1.0.0"' in content
    assert "[tool.qv]" in content
    assert 'min_severity = "warning"' in content

    cfg = QvConfig.from_pyproject(pyproject_file)
    assert cfg.min_severity == Severity.WARNING
    assert "amqp" in cfg.ignored_dependencies


def test_init_existing_pyproject_with_qv_no_force(tmp_path: Path) -> None:
    """Preserve existing QV settings and suggest --force when skipping them."""
    pyproject_file = tmp_path / "pyproject.toml"
    initial_content = """[project]
name = "custom-app"

[tool.qv]
min_severity = "info"
"""
    pyproject_file.write_text(initial_content, encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["init", str(tmp_path)])
    assert result.exit_code == 0
    assert "already exists" in result.output
    assert "--force" in result.output

    # Content unchanged
    assert pyproject_file.read_text(encoding="utf-8") == initial_content


def test_init_existing_pyproject_with_qv_force(tmp_path: Path) -> None:
    """Replace QV settings with defaults while retaining project metadata."""
    pyproject_file = tmp_path / "pyproject.toml"
    initial_content = """[project]
name = "custom-app"

[tool.qv]
min_severity = "info"
"""
    pyproject_file.write_text(initial_content, encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["init", str(tmp_path), "--force"])
    assert result.exit_code == 0
    assert "Overwrote" in result.output

    content = pyproject_file.read_text(encoding="utf-8")
    assert 'name = "custom-app"' in content
    assert 'min_severity = "warning"' in content
    assert "SQL-014" in content


def test_init_ci_github_standard(tmp_path: Path) -> None:
    """Generate a standard GitHub workflow that passes CI analyzer checks."""
    runner = CliRunner()
    result = runner.invoke(cli, ["init", str(tmp_path), "--ci", "github"])
    assert result.exit_code == 0

    wf_file = tmp_path / ".github" / "workflows" / "qv.yml"
    assert wf_file.exists()
    wf_content = wf_file.read_text(encoding="utf-8")
    assert "actions/checkout@v4" in wf_content
    assert "actions/setup-python@v5" in wf_content
    assert "qv scan --ci --github-annotations" in wf_content
    assert "cancel-in-progress: true" in wf_content

    # Validate against CIAnalyzer
    project = load_project(tmp_path)
    analyzer = CIAnalyzer()
    diags = analyzer.analyze(project.context)
    assert len(diags) == 0


def test_init_ci_github_uv(tmp_path: Path) -> None:
    """Generate a uv GitHub workflow that passes CI analyzer checks."""
    (tmp_path / "uv.lock").write_text("", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["init", str(tmp_path), "--ci", "github"])
    assert result.exit_code == 0

    wf_file = tmp_path / ".github" / "workflows" / "qv.yml"
    assert wf_file.exists()
    wf_content = wf_file.read_text(encoding="utf-8")
    assert "astral-sh/setup-uv@v5" in wf_content
    assert "uvx --from python-qv qv scan --ci --github-annotations" in wf_content

    # Validate against CIAnalyzer
    project = load_project(tmp_path)
    analyzer = CIAnalyzer()
    diags = analyzer.analyze(project.context)
    assert len(diags) == 0


def test_init_ci_github_no_force_skips(tmp_path: Path) -> None:
    """Preserve an existing GitHub workflow when --force is absent."""
    wf_file = tmp_path / ".github" / "workflows" / "qv.yml"
    wf_file.parent.mkdir(parents=True)
    custom_content = "# Existing custom workflow\n"
    wf_file.write_text(custom_content, encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["init", str(tmp_path), "--ci", "github"])
    assert result.exit_code == 0
    assert "already exists" in result.output
    assert wf_file.read_text(encoding="utf-8") == custom_content


def test_init_ci_github_force_overwrites(tmp_path: Path) -> None:
    """Replace an existing GitHub workflow when --force is supplied."""
    wf_file = tmp_path / ".github" / "workflows" / "qv.yml"
    wf_file.parent.mkdir(parents=True)
    wf_file.write_text("# Existing custom workflow\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["init", str(tmp_path), "--ci", "github", "-f"])
    assert result.exit_code == 0
    assert "Overwrote" in result.output
    wf_content = wf_file.read_text(encoding="utf-8")
    assert "actions/checkout@v4" in wf_content


def test_init_dry_run_does_not_modify_disk(tmp_path: Path) -> None:
    """Preview configuration and workflow content without creating either file."""
    runner = CliRunner()
    result = runner.invoke(cli, ["init", str(tmp_path), "--dry-run", "--ci", "github"])
    assert result.exit_code == 0

    pyproject_file = tmp_path / "pyproject.toml"
    wf_file = tmp_path / ".github" / "workflows" / "qv.yml"

    assert not pyproject_file.exists()
    assert not wf_file.exists()
    assert "[tool.qv]" in result.output
    assert "min_severity" in result.output
    assert "QV Project Health Scan" in result.output


def test_init_invalid_pyproject_syntax(tmp_path: Path) -> None:
    """Report malformed TOML as a configuration error with exit code 2."""
    pyproject_file = tmp_path / "pyproject.toml"
    pyproject_file.write_text("invalid toml syntax [[[[", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["init", str(tmp_path)])
    assert result.exit_code == 2
    assert "Configuration error" in result.output
