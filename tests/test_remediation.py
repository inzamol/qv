"""Tests for automated remediation engine and qv fix CLI command."""

from pathlib import Path

from click.testing import CliRunner

from qv.cli.main import cli
from qv.core.models import Diagnostic, ScanResult, ScanSummary, Severity
from qv.remediation.engine import RemediationEngine
from qv.remediation.models import FixActionType


def test_remediation_plan_dep002(tmp_path: Path):
    engine = RemediationEngine(project_root=tmp_path)
    scan_result = ScanResult(
        project_name="demo",
        project_path=str(tmp_path),
        python_version="3.12.0",
        package_manager="uv",
        summary=ScanSummary(errors_count=1),
        diagnostics=[
            Diagnostic(
                id="DEP-002",
                severity=Severity.ERROR,
                category="dependency",
                title="Missing dependency",
                message="Package httpx is missing",
                affected_packages=["httpx"],
            )
        ],
    )

    plan = engine.plan_fixes(scan_result)
    assert plan.total_fixes == 1
    assert plan.actions[0].action_type == FixActionType.ADD_DEPENDENCY
    assert plan.actions[0].metadata["package"] == "httpx"


def test_remediation_apply_add_dep_pyproject(tmp_path: Path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "demo"
version = "0.1.0"
dependencies = [
    "click>=8.0",
]
""",
        encoding="utf-8",
    )

    engine = RemediationEngine(project_root=tmp_path)
    scan_result = ScanResult(
        project_name="demo",
        project_path=str(tmp_path),
        python_version="3.12.0",
        package_manager="uv",
        summary=ScanSummary(errors_count=1),
        diagnostics=[
            Diagnostic(
                id="DEP-002",
                severity=Severity.ERROR,
                category="dependency",
                title="Missing dependency",
                message="Package httpx is missing",
                affected_packages=["httpx"],
            )
        ],
    )

    plan = engine.plan_fixes(scan_result)
    result = engine.apply_plan(plan, dry_run=False)

    assert result.success
    assert len(result.applied) == 1
    updated = pyproject.read_text(encoding="utf-8")
    assert '"httpx"' in updated
    assert '"click>=8.0"' in updated


def test_remediation_apply_remove_dep_pyproject(tmp_path: Path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "demo"
version = "0.1.0"
dependencies = [
    "click>=8.0",
    "unused-pkg>=1.0",
]
""",
        encoding="utf-8",
    )

    engine = RemediationEngine(project_root=tmp_path)
    scan_result = ScanResult(
        project_name="demo",
        project_path=str(tmp_path),
        python_version="3.12.0",
        package_manager="uv",
        summary=ScanSummary(warnings_count=1),
        diagnostics=[
            Diagnostic(
                id="DEP-003",
                severity=Severity.WARNING,
                category="dependency",
                title="Unused dependency",
                message="Package unused-pkg is unused",
                affected_packages=["unused-pkg"],
            )
        ],
    )

    plan = engine.plan_fixes(scan_result)
    result = engine.apply_plan(plan, dry_run=False)

    assert result.success
    assert len(result.applied) == 1
    updated = pyproject.read_text(encoding="utf-8")
    assert "unused-pkg" not in updated
    assert "click>=8.0" in updated


def test_remediation_apply_requirements_txt(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.31.0\n", encoding="utf-8")

    engine = RemediationEngine(project_root=tmp_path)
    scan_result = ScanResult(
        project_name="demo",
        project_path=str(tmp_path),
        python_version="3.12.0",
        package_manager="pip",
        summary=ScanSummary(errors_count=1),
        diagnostics=[
            Diagnostic(
                id="DEP-002",
                severity=Severity.ERROR,
                category="dependency",
                title="Missing dependency",
                message="Package pydantic is missing",
                affected_packages=["pydantic"],
            )
        ],
    )

    plan = engine.plan_fixes(scan_result)
    result = engine.apply_plan(plan, dry_run=False)

    assert result.success
    updated = req_file.read_text(encoding="utf-8")
    assert "pydantic" in updated
    assert "requests==2.31.0" in updated


def test_cli_fix_dry_run(tmp_path: Path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "demo"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )
    # Create python file importing httpx (missing dependency)
    app_file = tmp_path / "app.py"
    app_file.write_text("import httpx\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["fix", str(tmp_path), "--dry-run", "--rule", "DEP-002"])
    assert result.exit_code == 0
    assert "Proposed Fixes" in result.output
    assert "Dry-run mode enabled" in result.output
    # Ensure pyproject.toml is unchanged in dry-run
    content = pyproject.read_text(encoding="utf-8")
    assert "httpx" not in content


def test_cli_fix_apply_yes(tmp_path: Path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "demo"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )
    app_file = tmp_path / "app.py"
    app_file.write_text("import httpx\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["fix", str(tmp_path), "-y", "--rule", "DEP-002"])
    assert result.exit_code == 0
    assert "Successfully applied" in result.output
    # Verify httpx was added to pyproject.toml
    content = pyproject.read_text(encoding="utf-8")
    assert "httpx" in content


def test_remediation_execute_command_structured(tmp_path: Path, monkeypatch):
    """Test that command execution uses structured arguments with shell=False."""
    import subprocess

    from qv.remediation.models import FixAction

    engine = RemediationEngine(project_root=tmp_path)
    recorded_calls = []

    def mock_run(cmd, shell=False, cwd=None, check=True, capture_output=True):
        recorded_calls.append({"cmd": cmd, "shell": shell, "cwd": cwd})
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", mock_run)

    action = FixAction(
        id="fix-cmd-1",
        rule_id="DEP-005",
        action_type=FixActionType.EXECUTE_COMMAND,
        description="Sync lockfile",
        executable="uv",
        args=["sync", "--frozen"],
    )

    engine._execute_command(action)

    assert len(recorded_calls) == 1
    assert recorded_calls[0]["cmd"] == ["uv", "sync", "--frozen"]
    assert recorded_calls[0]["shell"] is False
    assert recorded_calls[0]["cwd"] == tmp_path.resolve()


def test_remediation_rejects_unauthorized_executable(tmp_path: Path):
    """Test that executables not in the allowed list are rejected."""
    import pytest

    from qv.remediation.models import FixAction

    engine = RemediationEngine(project_root=tmp_path)

    action = FixAction(
        id="fix-cmd-bad",
        rule_id="SEC-001",
        action_type=FixActionType.EXECUTE_COMMAND,
        description="Run malicious script",
        executable="bash",
        args=["-c", "echo pwned"],
    )

    with pytest.raises(ValueError, match="not an allowed remediation command"):
        engine._execute_command(action)


def test_remediation_rejects_empty_executable(tmp_path: Path):
    """Test that empty executables are rejected."""
    import pytest

    from qv.remediation.models import FixAction

    engine = RemediationEngine(project_root=tmp_path)

    action = FixAction(
        id="fix-cmd-empty",
        rule_id="SEC-001",
        action_type=FixActionType.EXECUTE_COMMAND,
        description="Run empty command",
        executable="",
        args=[],
    )

    with pytest.raises(ValueError, match="executable cannot be empty"):
        engine._execute_command(action)


def test_remediation_shell_metacharacters_not_interpreted(tmp_path: Path, monkeypatch):
    """Security test: Ensure shell metacharacters are treated as literal arguments."""
    import subprocess

    from qv.remediation.models import FixAction

    engine = RemediationEngine(project_root=tmp_path)
    recorded_calls = []

    def mock_run(cmd, shell=False, cwd=None, check=True, capture_output=True):
        recorded_calls.append({"cmd": cmd, "shell": shell})
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", mock_run)

    # An argument containing shell injection attempt
    malicious_arg = "requests; rm -rf /; echo $(whoami)"
    action = FixAction(
        id="fix-cmd-meta",
        rule_id="DEP-002",
        action_type=FixActionType.EXECUTE_COMMAND,
        description="Add dependency",
        executable="pip",
        args=["install", malicious_arg],
    )

    engine._execute_command(action)

    assert len(recorded_calls) == 1
    assert recorded_calls[0]["shell"] is False
    assert recorded_calls[0]["cmd"] == ["pip", "install", malicious_arg]
