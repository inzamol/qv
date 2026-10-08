"""Unit and integration tests for GitHub Marketplace Action implementation."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ACTION_RUNNER = REPO_ROOT / "scripts" / "run_action.py"
FIXTURE_PROJECT = REPO_ROOT / "tests" / "fixtures" / "action-project"
FIXTURE_CLEAN = REPO_ROOT / "tests" / "fixtures" / "action-project-clean"


def run_action_script(extra_env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Execute action runner with current environment and UTF-8 encoding."""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(extra_env)
    return subprocess.run(
        [sys.executable, str(ACTION_RUNNER)],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def test_action_yml_exists_and_valid():
    """Verify action.yml exists at repository root, is valid, and defines metadata."""
    action_yml = REPO_ROOT / "action.yml"
    assert action_yml.exists(), "action.yml must exist at repository root"

    content = action_yml.read_text(encoding="utf-8")
    assert 'name: "qv"' in content or "name: qv" in content
    assert "branding:" in content
    assert 'icon: "check-circle"' in content or "icon: check-circle" in content
    assert 'color: "blue"' in content or "color: blue" in content
    assert "runs:" in content
    assert 'using: "composite"' in content or "using: composite" in content
    assert "actions/setup-python@v5" in content
    assert "python-qv" in content


def test_action_clean_project(tmp_path: Path):
    """Test running action against a clean project with zero findings."""
    output_file = tmp_path / "clean.sarif"
    github_output = tmp_path / "github_output.txt"

    extra_env = {
        "INPUT_PATH": str(FIXTURE_CLEAN),
        "INPUT_FORMAT": "sarif",
        "INPUT_OUTPUT": str(output_file),
        "INPUT_FAIL_ON": "error",
        "INPUT_GITHUB_ANNOTATIONS": "false",
        "INPUT_OFFLINE": "true",
        "GITHUB_OUTPUT": str(github_output),
    }

    result = run_action_script(extra_env)

    assert result.returncode == 0, f"Failed: stdout={result.stdout}\nstderr={result.stderr}"
    assert "qv found 0 errors." in result.stdout
    assert output_file.exists()

    sarif_data = json.loads(output_file.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) == 0

    assert github_output.exists()
    out_content = github_output.read_text(encoding="utf-8")
    assert "errors=0" in out_content
    assert "exit-code=0" in out_content


def test_action_project_with_findings(tmp_path: Path):
    """Test running action against fixture project containing known findings (DEP-002)."""
    output_file = tmp_path / "results.sarif"
    github_output = tmp_path / "github_output.txt"

    extra_env = {
        "INPUT_PATH": str(FIXTURE_PROJECT),
        "INPUT_FORMAT": "sarif",
        "INPUT_OUTPUT": str(output_file),
        "INPUT_FAIL_ON": "error",
        "INPUT_GITHUB_ANNOTATIONS": "true",
        "INPUT_OFFLINE": "true",
        "GITHUB_OUTPUT": str(github_output),
    }

    result = run_action_script(extra_env)

    assert result.returncode == 1
    assert (
        "::error" in result.stdout or "::error" in result.stderr or "Errors:   2" in result.stdout
    )
    assert output_file.exists()

    sarif_data = json.loads(output_file.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    results = sarif_data["runs"][0]["results"]
    assert len(results) == 3

    errors = [r for r in results if r["level"] == "error"]
    assert len(errors) == 2
    assert all(r["ruleId"] == "DEP-002" for r in errors)

    warnings = [r for r in results if r["level"] == "warning"]
    assert len(warnings) == 1
    assert warnings[0]["ruleId"] == "DEP-003"

    out_content = github_output.read_text(encoding="utf-8")
    assert "findings=3" in out_content
    assert "errors=2" in out_content
    assert "warnings=1" in out_content
    assert "exit-code=1" in out_content


def test_action_fail_on_none(tmp_path: Path):
    """Test fail-on='none' exits with code 0 even when findings exist."""
    output_file = tmp_path / "results.sarif"
    github_output = tmp_path / "github_output.txt"

    extra_env = {
        "INPUT_PATH": str(FIXTURE_PROJECT),
        "INPUT_FORMAT": "sarif",
        "INPUT_OUTPUT": str(output_file),
        "INPUT_FAIL_ON": "none",
        "INPUT_OFFLINE": "true",
        "GITHUB_OUTPUT": str(github_output),
    }

    result = run_action_script(extra_env)

    # Should exit 0 because fail-on is none
    assert result.returncode == 0, f"Expected 0, got {result.returncode}"
    assert output_file.exists()


def test_action_missing_path():
    """Test validation fails when project path does not exist."""
    missing_dir = REPO_ROOT / "non_existent_directory_xyz"
    extra_env = {
        "INPUT_PATH": str(missing_dir),
    }

    result = run_action_script(extra_env)

    assert result.returncode == 1
    expected_msg = f"qv: project path does not exist: {missing_dir}"
    assert expected_msg in result.stderr or expected_msg in result.stdout


def test_action_invalid_format():
    """Test validation fails on invalid format input."""
    extra_env = {
        "INPUT_PATH": str(FIXTURE_CLEAN),
        "INPUT_FORMAT": "invalid_format_xyz",
    }

    result = run_action_script(extra_env)

    assert result.returncode == 1
    assert "qv: invalid format" in (result.stderr + result.stdout)


def test_action_invalid_fail_on():
    """Test validation fails on invalid fail-on severity threshold."""
    extra_env = {
        "INPUT_PATH": str(FIXTURE_CLEAN),
        "INPUT_FAIL_ON": "critical_invalid",
    }

    result = run_action_script(extra_env)

    assert result.returncode == 1
    assert "qv: invalid fail-on" in (result.stderr + result.stdout)


def test_action_safe_arguments(tmp_path: Path):
    """Test additional arguments are parsed and passed safely without shell injection."""
    output_file = tmp_path / "results.sarif"
    extra_env = {
        "INPUT_PATH": str(FIXTURE_CLEAN),
        "INPUT_OUTPUT": str(output_file),
        "INPUT_ARGS": "--hide-warnings --offline",
    }

    result = run_action_script(extra_env)

    assert result.returncode == 0


def test_action_unsafe_argument_characters(tmp_path: Path):
    """Test that shell metacharacters in args do not execute arbitrary shell commands."""
    canary = tmp_path / "injected_canary.txt"
    extra_env = {
        "INPUT_PATH": str(FIXTURE_CLEAN),
        "INPUT_ARGS": f"; touch {canary} && echo injected",
    }

    run_action_script(extra_env)

    # Shell injection canary file must NOT exist
    assert not canary.exists(), "Shell injection canary file must never be created!"


def test_action_terminal_format():
    """Test terminal format produces console output."""
    extra_env = {
        "INPUT_PATH": str(FIXTURE_CLEAN),
        "INPUT_FORMAT": "terminal",
        "INPUT_OUTPUT": "",
        "INPUT_OFFLINE": "true",
    }

    result = run_action_script(extra_env)

    assert result.returncode == 0
    assert "Analyzing project..." in result.stdout


def test_action_json_format(tmp_path: Path):
    """Test JSON format creates valid json report."""
    output_file = tmp_path / "results.json"
    extra_env = {
        "INPUT_PATH": str(FIXTURE_PROJECT),
        "INPUT_FORMAT": "json",
        "INPUT_OUTPUT": str(output_file),
        "INPUT_FAIL_ON": "none",
        "INPUT_OFFLINE": "true",
    }

    result = run_action_script(extra_env)

    assert result.returncode == 0
    assert output_file.exists()
    json_data = json.loads(output_file.read_text(encoding="utf-8"))
    assert "diagnostics" in json_data


def test_action_fail_on_warning(tmp_path: Path):
    """Test fail-on='warning' sets strict mode and causes failure when warnings exist."""
    output_file = tmp_path / "results.sarif"
    extra_env = {
        "INPUT_PATH": str(FIXTURE_PROJECT),
        "INPUT_FORMAT": "sarif",
        "INPUT_OUTPUT": str(output_file),
        "INPUT_FAIL_ON": "warning",
        "INPUT_OFFLINE": "true",
    }

    result = run_action_script(extra_env)

    assert result.returncode == 1


def test_action_baseline_file_handling(tmp_path: Path):
    """Test running with baseline path."""
    output_file = tmp_path / "results.sarif"
    fake_baseline = tmp_path / "baseline.json"
    fake_baseline.write_text("{}", encoding="utf-8")

    extra_env = {
        "INPUT_PATH": str(FIXTURE_CLEAN),
        "INPUT_FORMAT": "sarif",
        "INPUT_OUTPUT": str(output_file),
        "INPUT_BASELINE": str(fake_baseline),
        "INPUT_OFFLINE": "true",
    }

    result = run_action_script(extra_env)

    assert result.returncode == 0


def test_action_fail_on_none_propagates_cli_usage_error():
    """Test that CLI argument errors are NOT suppressed even when fail-on is 'none'."""
    extra_env = {
        "INPUT_PATH": str(FIXTURE_CLEAN),
        "INPUT_FAIL_ON": "none",
        "INPUT_ARGS": "--non-existent-unrecognized-argument-xyz",
    }

    result = run_action_script(extra_env)

    # Click exits with code 2 on unknown options; action must propagate failure, not return 0
    assert result.returncode != 0
    assert result.returncode == 2 or "No such option" in (result.stderr + result.stdout)


def test_action_cleans_stale_report_on_failure(tmp_path: Path):
    """Test that a pre-existing report is removed and not published if a subsequent scan fails."""
    stale_sarif = tmp_path / "stale.sarif"
    stale_sarif.write_text(
        '{"version":"2.1.0","runs":[{"results":[{"ruleId":"FAKE"}]}]}', encoding="utf-8"
    )
    github_output = tmp_path / "github_output.txt"

    extra_env = {
        "INPUT_PATH": str(FIXTURE_CLEAN),
        "INPUT_FORMAT": "sarif",
        "INPUT_OUTPUT": str(stale_sarif),
        "INPUT_FAIL_ON": "error",
        "INPUT_ARGS": "--invalid-option-causing-failure",
        "GITHUB_OUTPUT": str(github_output),
    }

    result = run_action_script(extra_env)

    assert result.returncode != 0
    assert not stale_sarif.exists(), (
        "Stale report must be removed before run and not persist on failure"
    )

    if github_output.exists():
        out_content = github_output.read_text(encoding="utf-8")
        assert "sarif-file=\n" in out_content or "sarif-file=" not in out_content
        assert "findings=0" in out_content
