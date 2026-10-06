"""Unit tests for CI/CD Workflow Analyzer (CI-001 through CI-006)."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from qv.analyzers.ci.analyzer import CIAnalyzer
from qv.cli.main import cli
from qv.core.context import (
    CIConfig,
    DockerConfig,
    ProjectContext,
    PythonRuntime,
)


def _create_context(
    root: Path,
    ci_config: CIConfig,
    manifest_files: tuple[Path, ...] = (),
) -> ProjectContext:
    return ProjectContext(
        project_root=root,
        project_name="ci-test-proj",
        python_runtime=PythonRuntime(
            version_str="3.12.0",
            major=3,
            minor=12,
            micro=0,
            executable="/usr/bin/python",
            is_virtualenv=True,
            virtualenv_path=root / ".venv",
        ),
        package_manager="pip",
        manifest_files=manifest_files,
        lock_files=(),
        dependencies=(),
        installed_packages={},
        source_files=(),
        imports=(),
        docker=DockerConfig(has_dockerfile=False),
        ci=ci_config,
        config={"target_python": ">=3.11"},
    )


def test_ci_001_matrix_version_mismatch(tmp_path: Path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf_file = wf_dir / "ci.yml"
    wf_file.write_text(
        "name: CI\n"
        "on: [push]\n"
        "jobs:\n"
        "  test:\n"
        "    strategy:\n"
        "      matrix:\n"
        "        python-version: ['3.9', '3.10', '3.12']\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: pytest\n",
        encoding="utf-8",
    )

    ctx = _create_context(
        tmp_path,
        CIConfig(
            has_ci=True,
            provider="github_actions",
            workflow_files=(wf_file,),
            matrix_python_versions=("3.9", "3.10", "3.12"),
        ),
    )

    analyzer = CIAnalyzer()
    findings = analyzer.analyze(ctx)
    ids = [f.id for f in findings]
    assert "CI-001" in ids


def test_ci_002_unfrozen_dependencies(tmp_path: Path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf_file = wf_dir / "test.yml"
    wf_file.write_text(
        "name: Test\n"
        "on: [push]\n"
        "jobs:\n"
        "  run:\n"
        "    steps:\n"
        "      - run: pip install -r requirements.txt\n"
        "      - run: pytest\n",
        encoding="utf-8",
    )

    ctx = _create_context(
        tmp_path,
        CIConfig(
            has_ci=True,
            provider="github_actions",
            workflow_files=(wf_file,),
        ),
    )

    analyzer = CIAnalyzer()
    findings = analyzer.analyze(ctx)
    ids = [f.id for f in findings]
    assert "CI-002" in ids


def test_ci_003_deprecated_action(tmp_path: Path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf_file = wf_dir / "build.yml"
    wf_file.write_text(
        "name: Build\n"
        "on: [push]\n"
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v2\n"
        "      - uses: actions/setup-python@v3\n",
        encoding="utf-8",
    )

    ctx = _create_context(
        tmp_path,
        CIConfig(
            has_ci=True,
            provider="github_actions",
            workflow_files=(wf_file,),
        ),
    )

    analyzer = CIAnalyzer()
    findings = analyzer.analyze(ctx)
    ids = [f.id for f in findings]
    assert "CI-003" in ids


def test_ci_004_missing_quality_gate(tmp_path: Path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf_file = wf_dir / "pr.yml"
    wf_file.write_text(
        "name: PR\non: pull_request\njobs:\n  echo:\n    steps:\n      - run: echo 'hello world'\n",
        encoding="utf-8",
    )

    ctx = _create_context(
        tmp_path,
        CIConfig(
            has_ci=True,
            provider="github_actions",
            workflow_files=(wf_file,),
        ),
    )

    analyzer = CIAnalyzer()
    findings = analyzer.analyze(ctx)
    ids = [f.id for f in findings]
    assert "CI-004" in ids


def test_ci_005_hardcoded_secret(tmp_path: Path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf_file = wf_dir / "deploy.yml"
    wf_file.write_text(
        "name: Deploy\n"
        "on: push\n"
        "jobs:\n"
        "  deploy:\n"
        "    steps:\n"
        "      - run: echo ghp_abcdefghijklmnopqrstuvwxyz123456\n"
        "      - run: pytest\n",
        encoding="utf-8",
    )

    ctx = _create_context(
        tmp_path,
        CIConfig(
            has_ci=True,
            provider="github_actions",
            workflow_files=(wf_file,),
        ),
    )

    analyzer = CIAnalyzer()
    findings = analyzer.analyze(ctx)
    ids = [f.id for f in findings]
    assert "CI-005" in ids


def test_ci_006_missing_concurrency(tmp_path: Path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf_file = wf_dir / "ci.yml"
    wf_file.write_text(
        "name: PR Checks\n"
        "on:\n"
        "  pull_request:\n"
        "    branches: [main]\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - run: pytest\n",
        encoding="utf-8",
    )

    ctx = _create_context(
        tmp_path,
        CIConfig(
            has_ci=True,
            provider="github_actions",
            workflow_files=(wf_file,),
        ),
    )

    analyzer = CIAnalyzer()
    findings = analyzer.analyze(ctx)
    ids = [f.id for f in findings]
    assert "CI-006" in ids


def test_qv_ci_cli_command(tmp_path: Path):
    runner = CliRunner()
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[project]\nname = 'ci-proj'\nversion = '0.1.0'\nrequires-python = '>=3.11'\ndependencies = []\n",
        encoding="utf-8",
    )
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf = wf_dir / "ci.yml"
    wf.write_text(
        "name: CI\n"
        "on: [push]\n"
        "concurrency:\n"
        "  group: ${{ github.ref }}\n"
        "  cancel-in-progress: true\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: uv sync --frozen\n"
        "      - run: pytest\n",
        encoding="utf-8",
    )

    result = runner.invoke(cli, ["ci", str(tmp_path)])
    assert result.exit_code == 0
