"""Unit tests for Celery Background Tasks Analyzer (CEL-001 through CEL-004)."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from qv.cli.main import cli
from qv.core.context import (
    CIConfig,
    DependencyDeclaration,
    DockerConfig,
    ProjectContext,
    PythonRuntime,
    SourceFile,
)
from qv.frameworks.celery import CeleryAnalyzer


def _create_celery_context(root: Path, files: dict[str, str]) -> ProjectContext:
    source_files = []
    for rel_path_str, content in files.items():
        p = root / rel_path_str
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        source_files.append(
            SourceFile(
                path=p,
                relative_path=Path(rel_path_str),
                content=content,
                is_init=p.name == "__init__.py",
                module_name=rel_path_str.replace("/", ".").replace(".py", ""),
            )
        )

    return ProjectContext(
        project_root=root,
        project_name="celery-test-proj",
        python_runtime=PythonRuntime(
            version_str="3.12.0",
            major=3,
            minor=12,
            micro=0,
            executable="/usr/bin/python",
            is_virtualenv=True,
            virtualenv_path=root / ".venv",
        ),
        package_manager="uv",
        manifest_files=(root / "pyproject.toml",),
        lock_files=(),
        dependencies=(
            DependencyDeclaration(
                name="celery",
                specifier=">=5.3",
                source_file=root / "pyproject.toml",
            ),
        ),
        installed_packages={},
        source_files=tuple(source_files),
        imports=(),
        docker=DockerConfig(has_dockerfile=False),
        ci=CIConfig(has_ci=False),
        config={},
    )


def test_celery_001_pickle_serializer(tmp_path: Path):
    ctx = _create_celery_context(
        tmp_path,
        {
            "tasks.py": ("task_serializer = 'pickle'\nresult_serializer = 'pickle'\n"),
        },
    )
    analyzer = CeleryAnalyzer()
    findings = analyzer.analyze(ctx)
    ids = [f.id for f in findings]
    assert "CEL-001" in ids


def test_celery_002_missing_task_timeout(tmp_path: Path):
    ctx = _create_celery_context(
        tmp_path,
        {
            "tasks.py": (
                "from celery import shared_task\n\n"
                "@shared_task\n"
                "def process_data(data):\n"
                "    return len(data)\n"
            ),
        },
    )
    analyzer = CeleryAnalyzer()
    findings = analyzer.analyze(ctx)
    ids = [f.id for f in findings]
    assert "CEL-002" in ids


def test_celery_003_unbounded_retries(tmp_path: Path):
    ctx = _create_celery_context(
        tmp_path,
        {
            "tasks.py": (
                "from celery import shared_task\n\n"
                "@shared_task(time_limit=60, autoretry_for=(Exception,))\n"
                "def send_email(email):\n"
                "    pass\n"
            ),
        },
    )
    analyzer = CeleryAnalyzer()
    findings = analyzer.analyze(ctx)
    ids = [f.id for f in findings]
    assert "CEL-003" in ids


def test_celery_004_blocking_time_sleep(tmp_path: Path):
    ctx = _create_celery_context(
        tmp_path,
        {
            "tasks.py": (
                "import time\n"
                "from celery import shared_task\n\n"
                "@shared_task(time_limit=60)\n"
                "async def fetch_async(url):\n"
                "    time.sleep(5)\n"
            ),
        },
    )
    analyzer = CeleryAnalyzer()
    findings = analyzer.analyze(ctx)
    ids = [f.id for f in findings]
    assert "CEL-004" in ids


def test_qv_framework_celery_cli(tmp_path: Path):
    runner = CliRunner()
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[project]\nname = 'cel-proj'\nversion = '0.1.0'\ndependencies = ['celery>=5.3']\n",
        encoding="utf-8",
    )
    tasks = tmp_path / "tasks.py"
    tasks.write_text(
        "from celery import shared_task\n\n"
        "task_serializer = 'json'\n"
        "@shared_task(time_limit=300, soft_time_limit=240, max_retries=3)\n"
        "def clean_task():\n"
        "    return True\n",
        encoding="utf-8",
    )

    result = runner.invoke(cli, ["framework", str(tmp_path), "--name", "celery"])
    assert result.exit_code == 0
