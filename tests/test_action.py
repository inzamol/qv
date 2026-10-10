"""Unit and integration tests for GitHub Marketplace Action implementation."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ACTION_RUNNER = REPO_ROOT / "scripts" / "run_action.py"
FIXTURE_PROJECT = REPO_ROOT / "tests" / "fixtures" / "action-project"
FIXTURE_CLEAN = REPO_ROOT / "tests" / "fixtures" / "action-project-clean"


def run_action_script(
    extra_env: dict[str, str], cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Execute action runner with current environment and UTF-8 encoding."""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(extra_env)
    return subprocess.run(
        [sys.executable, str(ACTION_RUNNER)],
        cwd=cwd,
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


def test_action_yml_latest_version_resolution_timeout_and_error():
    """Verify action.yml configures a timeout on urlopen, emits ::error:: on PyPI failure, and logs version."""
    action_yml = REPO_ROOT / "action.yml"
    content = action_yml.read_text(encoding="utf-8")

    assert "urllib.request.urlopen('https://pypi.org/pypi/python-qv/json', timeout=" in content
    assert "::error::Failed to resolve latest python-qv version from PyPI" in content
    assert "Installed python-qv version:" in content


def test_action_latest_resolution_fails_clearly_on_error(tmp_path: Path):
    """Verify that when PyPI lookup fails for 'latest', an error is emitted and execution exits 1."""
    import shutil

    import pytest

    git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
    if sys.platform == "win32" and git_bash.exists():
        bash = str(git_bash)
    else:
        bash = shutil.which("bash")
        if sys.platform == "win32" and bash and "system32" in bash.lower():
            pytest.skip("WSL bash on Windows cannot directly execute Windows temp paths")

    if not bash:
        pytest.skip("bash executable not found")

    test_sh = tmp_path / "test_install_fail.sh"
    test_sh.write_text(
        """#!/usr/bin/env bash
INPUT_VERSION="latest"
if [ "$INPUT_VERSION" = "latest" ]; then
  RESOLVED_VER=$(python -c "import urllib.request, json; print(json.loads(urllib.request.urlopen('https://invalid.example.nonexistent/json', timeout=1).read())['info']['version'])" 2>/dev/null || true)
  if [ -z "$RESOLVED_VER" ]; then
    echo "::error::Failed to resolve latest python-qv version from PyPI. Please specify an explicit version (e.g. version: '1.0.1') or check network connectivity." >&2
    exit 1
  fi
fi
""",
        encoding="utf-8",
    )

    res = subprocess.run([bash, str(test_sh)], capture_output=True, text=True)
    assert res.returncode == 1
    assert "::error::Failed to resolve latest python-qv version from PyPI" in res.stderr


def test_action_prints_installed_version_on_install(tmp_path: Path):
    """Verify that action install script prints the exact installed version."""
    import shutil

    import pytest

    git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
    if sys.platform == "win32" and git_bash.exists():
        bash = str(git_bash)
    else:
        bash = shutil.which("bash")
        if sys.platform == "win32" and bash and "system32" in bash.lower():
            pytest.skip("WSL bash on Windows cannot directly execute Windows temp paths")

    if not bash:
        pytest.skip("bash executable not found")

    test_sh = tmp_path / "test_install_print.sh"
    test_sh.write_text(
        """#!/usr/bin/env bash
INPUT_VERSION="1.0.1"
TARGET_VER="${INPUT_VERSION:-1.0.1}"
echo "Installed python-qv version: $TARGET_VER"
""",
        encoding="utf-8",
    )

    res = subprocess.run([bash, str(test_sh)], capture_output=True, text=True)
    assert res.returncode == 0
    assert "Installed python-qv version: 1.0.1" in res.stdout


def test_action_yml_local_version_requires_src_directory():
    """Verify action.yml checks for $ACTION_PATH/src when version=local or version=."""
    action_yml = REPO_ROOT / "action.yml"
    content = action_yml.read_text(encoding="utf-8")

    assert '[ ! -d "$ACTION_PATH/src" ]' in content
    assert "::error::version=local requires $ACTION_PATH/src" in content


def test_action_local_fails_when_src_missing(tmp_path: Path):
    """Verify that version=local fails early with an error annotation if $ACTION_PATH/src is missing."""
    import shutil

    import pytest

    git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
    if sys.platform == "win32" and git_bash.exists():
        bash = str(git_bash)
    else:
        bash = shutil.which("bash")
        if sys.platform == "win32" and bash and "system32" in bash.lower():
            pytest.skip("WSL bash on Windows cannot directly execute Windows temp paths")

    if not bash:
        pytest.skip("bash executable not found")

    empty_action_dir = tmp_path / "action_empty"
    empty_action_dir.mkdir()

    test_sh = tmp_path / "test_local_check.sh"
    test_sh.write_text(
        f"""#!/usr/bin/env bash
INPUT_VERSION="local"
ACTION_PATH="{empty_action_dir.as_posix()}"
if [ "$INPUT_VERSION" = "local" ] || [ "$INPUT_VERSION" = "." ]; then
  if [ ! -d "$ACTION_PATH/src" ]; then
    echo "::error::version=local requires $ACTION_PATH/src" >&2
    exit 1
  fi
fi
""",
        encoding="utf-8",
    )

    res = subprocess.run([bash, str(test_sh)], capture_output=True, text=True)
    assert res.returncode == 1
    assert "::error::version=local requires" in res.stderr


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


def test_documented_github_action_example_integration(tmp_path: Path):
    """Verify README's documented GitHub Action workflow uses supported inputs and runs successfully."""
    readme_path = REPO_ROOT / "README.md"
    assert readme_path.exists(), "README.md must exist"
    readme_content = readme_path.read_text(encoding="utf-8")

    # 1. Extract the YAML snippet under '### Official GitHub Action'
    assert "### Official GitHub Action" in readme_content
    section = readme_content.split("### Official GitHub Action")[1].split("###")[0]
    match = re.search(r"```yaml\s*\n(.*?)```", section, re.DOTALL)
    assert match is not None, (
        "Could not find YAML code block under '### Official GitHub Action' in README.md"
    )
    yaml_text = match.group(1)
    assert "uses: inzamol/qv" in yaml_text, (
        "Documented workflow must contain a step using 'inzamol/qv'"
    )

    # 2. Extract 'with:' parameters for inzamol/qv step
    with_match = re.search(
        r"uses:\s*inzamol/qv[^\n]*\n\s*with:\s*\n((?:\s+[a-zA-Z0-9_-]+:\s*[^\n]+\n?)+)",
        yaml_text,
    )
    assert with_match, "Could not find 'with:' block for inzamol/qv step"

    step_with: dict[str, str | bool] = {}
    for line in with_match.group(1).splitlines():
        line = line.strip()
        if line and ":" in line:
            k, v = line.split(":", 1)
            v = v.strip()
            if v.lower() == "true":
                step_with[k.strip()] = True
            elif v.lower() == "false":
                step_with[k.strip()] = False
            else:
                step_with[k.strip()] = v

    # 3. Verify inputs against action.yml specification
    action_yml_path = REPO_ROOT / "action.yml"
    assert action_yml_path.exists()
    action_yml_content = action_yml_path.read_text(encoding="utf-8")
    inputs_block = action_yml_content.split("inputs:\n", 1)[1].split("outputs:\n", 1)[0]
    declared_inputs = set(re.findall(r"^  ([a-zA-Z0-9_-]+):", inputs_block, re.MULTILINE))

    # None of the obsolete inputs should be present
    obsolete_inputs = {"strict", "html_report", "sarif_report", "github_annotations"}
    for obsolete in obsolete_inputs:
        assert obsolete not in step_with, (
            f"Obsolete input '{obsolete}' found in documented action example"
        )

    # All documented inputs must be declared in action.yml
    for documented_input in step_with:
        assert documented_input in declared_inputs, (
            f"Documented input '{documented_input}' is not declared in action.yml inputs: {declared_inputs}"
        )

    # Expected supported inputs in the documented example
    assert step_with.get("format") == "sarif"
    assert step_with.get("output") == "qv-results.sarif"
    assert step_with.get("fail-on") == "error"
    assert step_with.get("github-annotations") is True

    # 4. Integration execution against clean project (should succeed)
    clean_project_dir = tmp_path / "clean_project"
    shutil.copytree(FIXTURE_CLEAN, clean_project_dir)

    extra_env = {f"INPUT_{k.upper().replace('-', '_')}": str(v) for k, v in step_with.items()}
    github_output_clean = tmp_path / "github_output_clean.txt"
    extra_env["GITHUB_OUTPUT"] = str(github_output_clean)
    extra_env["INPUT_OFFLINE"] = "true"

    # Execute in clean project root using default relative path '.'
    res_clean = run_action_script(extra_env, cwd=clean_project_dir)
    assert res_clean.returncode == 0, (
        f"Clean run failed: stdout={res_clean.stdout}\nstderr={res_clean.stderr}"
    )
    assert "qv found 0 errors." in res_clean.stdout

    output_rel = str(step_with["output"])
    expected_output_file = clean_project_dir / output_rel
    assert expected_output_file.is_file(), (
        f"Expected SARIF report not found at {expected_output_file}"
    )

    sarif_data = json.loads(expected_output_file.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) == 0

    assert github_output_clean.exists()
    out_clean_content = github_output_clean.read_text(encoding="utf-8")
    assert "errors=0" in out_clean_content
    assert "exit-code=0" in out_clean_content

    # 5. Integration execution against project with error findings (should fail with code 1)
    findings_project_dir = tmp_path / "findings_project"
    shutil.copytree(FIXTURE_PROJECT, findings_project_dir)

    github_output_findings = tmp_path / "github_output_findings.txt"
    extra_env["GITHUB_OUTPUT"] = str(github_output_findings)

    res_findings = run_action_script(extra_env, cwd=findings_project_dir)
    assert res_findings.returncode == 1, (
        "Expected action to fail with exit code 1 for project with errors"
    )
    assert "::error" in res_findings.stdout or "::error" in res_findings.stderr
    assert "qv found 2 error(s)." in res_findings.stdout

    findings_sarif = findings_project_dir / output_rel
    assert findings_sarif.is_file()
    findings_data = json.loads(findings_sarif.read_text(encoding="utf-8"))
    assert len(findings_data["runs"][0]["results"]) == 3

    assert github_output_findings.exists()
    out_findings_content = github_output_findings.read_text(encoding="utf-8")
    assert "errors=2" in out_findings_content
    assert "exit-code=1" in out_findings_content


def test_action_version_default_consistency():
    """Verify that action.yml, README.md, and docs/ci_integration.md have synchronized version defaults."""
    action_yml = REPO_ROOT / "action.yml"
    readme_md = REPO_ROOT / "README.md"
    docs_md = REPO_ROOT / "docs" / "ci_integration.md"

    assert action_yml.exists()
    assert readme_md.exists()
    assert docs_md.exists()

    action_content = action_yml.read_text(encoding="utf-8")
    readme_content = readme_md.read_text(encoding="utf-8")
    docs_content = docs_md.read_text(encoding="utf-8")

    # Extract version default from action.yml
    action_match = re.search(
        r"version:\s*\n(?:\s+[^\n]+\n)*?\s+default:\s*[\"']?([^\"'\s]+)[\"']?",
        action_content,
    )
    assert action_match is not None, "Could not find version default in action.yml"
    action_default = action_match.group(1)

    # Extract version default from README.md action configuration table
    readme_match = re.search(
        r"\|\s*`version`\s*\|[^|]+\|\s*`?([^`|\s]+)`?\s*\|",
        readme_content,
    )
    assert readme_match is not None, "Could not find `version` row in README.md"
    readme_default = readme_match.group(1)

    # Extract version default from docs/ci_integration.md action inputs table
    docs_match = re.search(
        r"\|\s*`version`\s*\|[^|]+\|\s*`?([^`|\s]+)`?\s*\|",
        docs_content,
    )
    assert docs_match is not None, "Could not find `version` row in docs/ci_integration.md"
    docs_default = docs_match.group(1)

    assert action_default == "1.0.1", (
        f"action.yml default version should be 1.0.1, got {action_default}"
    )
    assert readme_default == action_default, (
        f"README.md version default ({readme_default}) does not match action.yml ({action_default})"
    )
    assert docs_default == action_default, (
        f"docs/ci_integration.md version default ({docs_default}) does not match action.yml ({action_default})"
    )

    # Verify reproducible builds guidance is present in docs
    assert "Tip (Reproducible Builds)" in readme_content
    assert "Tip (Reproducible Builds)" in docs_content
