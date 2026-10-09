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


def test_remediation_plan_dep003_requires_review(tmp_path: Path):
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
                title="No direct import detected: celery",
                message="Package celery is unimported",
                affected_packages=["celery"],
            )
        ],
    )

    plan = engine.plan_fixes(scan_result)
    assert plan.total_fixes == 1
    assert plan.safe_fixes_count == 0
    assert plan.actions[0].is_safe is False

    # apply_plan with only_safe=True should skip DEP-003
    result_safe = engine.apply_plan(plan, only_safe=True)
    assert len(result_safe.applied) == 0
    assert len(result_safe.skipped) == 1
    assert result_safe.skipped[0].id == plan.actions[0].id


def test_cli_fix_dep003_skipped_with_yes(tmp_path: Path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "demo"
version = "0.1.0"
dependencies = [
    "celery>=5.2.0",
]
""",
        encoding="utf-8",
    )
    app_file = tmp_path / "app.py"
    app_file.write_text("x = 1\n", encoding="utf-8")

    runner = CliRunner()
    # qv fix -y should NOT automatically remove inferred unimported dependency
    result = runner.invoke(cli, ["fix", str(tmp_path), "-y"])
    assert result.exit_code == 0
    assert "Skipped 1 action(s)" in result.output
    assert "requires review" in result.output
    # Verify celery was NOT removed
    content = pyproject.read_text(encoding="utf-8")
    assert "celery>=5.2.0" in content


def test_cli_fix_dep003_applied_with_interactive_confirmation(tmp_path: Path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "demo"
version = "0.1.0"
dependencies = [
    "celery>=5.2.0",
]
""",
        encoding="utf-8",
    )
    app_file = tmp_path / "app.py"
    app_file.write_text("x = 1\n", encoding="utf-8")

    runner = CliRunner()
    # interactive qv fix confirmed by user
    result = runner.invoke(cli, ["fix", str(tmp_path)], input="y\n")
    assert result.exit_code == 0
    assert "Successfully applied 1 fix(es)" in result.output
    content = pyproject.read_text(encoding="utf-8")
    assert "celery" not in content


def test_remediation_requirements_exact_package_removal(tmp_path: Path):
    """Test removing 'requests' from requirements.txt does not remove 'requests-cache' or 'requests-toolbelt'."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        "requests\nrequests-cache\nrequests-toolbelt\n",
        encoding="utf-8",
    )

    engine = RemediationEngine(project_root=tmp_path)
    engine._remove_dependency_from_requirements("requests")

    content = req_file.read_text(encoding="utf-8")
    assert "requests\n" not in content
    assert "requests-cache" in content
    assert "requests-toolbelt" in content


def test_remediation_requirements_preserves_comments_and_options(tmp_path: Path):
    """Test removing dependency preserves pip options, comments, and constraints."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        """# Production dependencies
-r base.txt
--extra-index-url https://pypi.org/simple
requests>=2.31.0 # HTTP client
requests-cache==1.2.0
requests-toolbelt~=0.10.1
""",
        encoding="utf-8",
    )

    engine = RemediationEngine(project_root=tmp_path)
    engine._remove_dependency_from_requirements("requests")

    content = req_file.read_text(encoding="utf-8")
    assert "requests>=2.31.0" not in content
    assert "# Production dependencies" in content
    assert "-r base.txt" in content
    assert "--extra-index-url https://pypi.org/simple" in content
    assert "requests-cache==1.2.0" in content
    assert "requests-toolbelt~=0.10.1" in content


def test_remediation_pyproject_exact_package_prefix_preservation(tmp_path: Path):
    """Test removing 'requests' from pyproject.toml preserves 'requests-cache' and 'requests-toolbelt'."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "demo"
version = "0.1.0"
dependencies = [
    "requests>=2.31.0",
    "requests-cache>=1.0.0",
    "requests-toolbelt>=0.10.0",
]
""",
        encoding="utf-8",
    )

    engine = RemediationEngine(project_root=tmp_path)
    engine._remove_dependency_from_pyproject("requests")

    content = pyproject.read_text(encoding="utf-8")
    assert '"requests>=2.31.0"' not in content
    assert '"requests-cache>=1.0.0"' in content
    assert '"requests-toolbelt>=0.10.0"' in content


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


def test_remediation_toml_structure_preservation_issue_5(tmp_path: Path):
    """Test Issue #5: Modifying dependencies in [project] does not corrupt [tool.some-tool]."""
    pyproject = tmp_path / "pyproject.toml"
    initial_content = """# Main project configuration
[project]
name = "demo"
version = "0.1.0"
dependencies = [
    "requests",
]

# Custom tool table with its own dependencies
[tool.some-tool]
dependencies = [
    "internal-package",
]
"""
    pyproject.write_text(initial_content, encoding="utf-8")

    engine = RemediationEngine(project_root=tmp_path)

    # 1. Add a dependency 'httpx'
    scan_add = ScanResult(
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
    plan_add = engine.plan_fixes(scan_add)
    result_add = engine.apply_plan(plan_add)
    assert result_add.success

    updated = pyproject.read_text(encoding="utf-8")
    # Verify [project] dependencies updated
    assert '"httpx"' in updated
    assert '"requests"' in updated
    # Verify [tool.some-tool] dependencies kept untouched
    assert '"internal-package"' in updated
    assert "[tool.some-tool]" in updated

    # 2. Remove 'requests' from [project]
    scan_remove = ScanResult(
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
                message="Package requests is unused",
                affected_packages=["requests"],
            )
        ],
    )
    plan_remove = engine.plan_fixes(scan_remove)
    result_remove = engine.apply_plan(plan_remove)
    assert result_remove.success

    updated_after_remove = pyproject.read_text(encoding="utf-8")
    assert '"requests"' not in updated_after_remove
    assert '"httpx"' in updated_after_remove
    # Verify tool section still untouched
    assert '"internal-package"' in updated_after_remove


def test_remediation_initialize_metadata_preserves_tables(tmp_path: Path):
    """Test PKG-001 initialization preserves existing tables in pyproject.toml."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[tool.ruff]
line-length = 100
""",
        encoding="utf-8",
    )

    engine = RemediationEngine(project_root=tmp_path)
    scan_result = ScanResult(
        project_name="demo-pkg",
        project_path=str(tmp_path),
        python_version="3.12.0",
        package_manager="uv",
        summary=ScanSummary(errors_count=1),
        diagnostics=[
            Diagnostic(
                id="PKG-001",
                severity=Severity.ERROR,
                category="packaging",
                title="Missing metadata",
                message="pyproject.toml lacks [project] table",
            )
        ],
    )

    plan = engine.plan_fixes(scan_result)
    result = engine.apply_plan(plan)
    assert result.success

    content = pyproject.read_text(encoding="utf-8")
    assert "[project]" in content
    assert "[tool.ruff]" in content
    assert "line-length = 100" in content


def test_valid_project_file_is_allowed(tmp_path: Path):
    """AC-01: Valid files within project root boundary must be allowed."""
    engine = RemediationEngine(project_root=tmp_path)

    # Validate relative file within project
    resolved = engine._validate_target_path("requirements.txt")
    assert resolved == (tmp_path / "requirements.txt").resolve()

    # Validate nested file within project
    sub_dir = tmp_path / "nested"
    sub_dir.mkdir()
    resolved_sub = engine._validate_target_path("nested/deps.txt")
    assert resolved_sub == (sub_dir / "deps.txt").resolve()

    # Writing to valid requirements file succeeds
    engine._add_dependency_to_requirements("httpx", target_file="requirements.txt")
    assert "httpx" in (tmp_path / "requirements.txt").read_text(encoding="utf-8")


def test_parent_directory_traversal_is_rejected(tmp_path: Path):
    """AC-01: Parent directory traversal (../) escaping project root must be rejected."""
    import pytest

    engine = RemediationEngine(project_root=tmp_path)

    with pytest.raises(ValueError, match="resolves outside project root"):
        engine._validate_target_path("../outside.txt")

    with pytest.raises(ValueError, match="resolves outside project root"):
        engine._validate_target_path("nested/../../outside.txt")

    with pytest.raises(ValueError, match="resolves outside project root"):
        engine._add_dependency_to_requirements("httpx", target_file="../outside_reqs.txt")


def test_absolute_external_path_is_rejected(tmp_path: Path):
    """AC-01: Absolute paths outside the project root must be rejected."""
    import pytest

    engine = RemediationEngine(project_root=tmp_path)
    external_path = tmp_path.parent / "external_reqs.txt"

    with pytest.raises(ValueError, match="resolves outside project root"):
        engine._validate_target_path(str(external_path))

    with pytest.raises(ValueError, match="resolves outside project root"):
        engine._add_dependency_to_requirements("httpx", target_file=str(external_path))


def test_symlink_outside_project_is_rejected(tmp_path: Path):
    """AC-01: Symlinks resolving outside the project root must be rejected."""
    import os

    import pytest

    engine = RemediationEngine(project_root=tmp_path)
    external_target = tmp_path.parent / "secret_file.txt"
    external_target.write_text("secret\n", encoding="utf-8")

    symlink_path = tmp_path / "symlink_file.txt"
    try:
        os.symlink(external_target, symlink_path)
    except OSError:
        pytest.skip("Symlink creation not supported in this environment")

    with pytest.raises(ValueError, match="resolves outside project root"):
        engine._validate_target_path("symlink_file.txt")

    with pytest.raises(ValueError, match="resolves outside project root"):
        engine._add_dependency_to_requirements("httpx", target_file="symlink_file.txt")


def test_dep003_remediation_safety_amqp_regression(tmp_path: Path):
    """AC-05: DEP-003 must never automatically remove 'amqp' when running remediation workflow."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "amqp-demo"
version = "0.1.0"
dependencies = [
    "amqp",
]
""",
        encoding="utf-8",
    )
    # Source file has no direct import of amqp
    main_py = tmp_path / "main.py"
    main_py.write_text("print('hello')\n", encoding="utf-8")

    runner = CliRunner()
    # Execute non-interactive remediation (qv fix -y)
    result = runner.invoke(cli, ["fix", str(tmp_path), "-y"])
    assert result.exit_code == 0

    # Ensure amqp was NOT automatically removed
    updated_toml = pyproject.read_text(encoding="utf-8")
    assert '"amqp"' in updated_toml
    assert "Skipped 1 action(s)" in result.output
    assert "requires review" in result.output


def test_remediation_rejects_project_root_itself(tmp_path: Path):
    """Ensure project root directory itself is rejected as a target file."""
    import pytest

    engine = RemediationEngine(project_root=tmp_path)
    with pytest.raises(ValueError, match="cannot be the project root directory itself"):
        engine._validate_target_path(".")

    with pytest.raises(ValueError, match="cannot be the project root directory itself"):
        engine._validate_target_path(str(tmp_path))


def test_all_file_remediation_methods_reject_external_paths(tmp_path: Path):
    """Ensure all file-modifying methods reject external paths and directory traversal (S2083)."""
    import pytest

    engine = RemediationEngine(project_root=tmp_path)
    bad_target = "../outside_manifest.toml"

    with pytest.raises(ValueError, match="resolves outside project root"):
        engine._add_dependency_to_pyproject("httpx", target_file=bad_target)

    with pytest.raises(ValueError, match="resolves outside project root"):
        engine._remove_dependency_from_pyproject("httpx", target_file=bad_target)

    with pytest.raises(ValueError, match="resolves outside project root"):
        engine._add_dependency_to_requirements("httpx", target_file=bad_target)

    with pytest.raises(ValueError, match="resolves outside project root"):
        engine._remove_dependency_from_requirements("httpx", target_file=bad_target)

    with pytest.raises(ValueError, match="resolves outside project root"):
        engine._initialize_pyproject_metadata("myproject", target_file=bad_target)


def test_plan_fixes_rejects_traversal_in_diag_file(tmp_path: Path):
    """Ensure plan_fixes ignores diag.file paths that attempt directory traversal."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[project]\nname='test'\nversion='0.1.0'\ndependencies=['unused']\n", encoding="utf-8"
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
                message="Package unused is unused",
                affected_packages=["unused"],
                file="../../outside_deps.txt",
            )
        ],
    )

    plan = engine.plan_fixes(scan_result)
    assert len(plan.actions) == 1
    # Must fallback to pyproject.toml within root, not the traversed relative file
    assert plan.actions[0].target_file == "pyproject.toml"
