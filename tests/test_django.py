"""Unit tests for Django Framework Analyzer (DJG-001 through DJG-006)."""

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
from qv.frameworks.django import DjangoAnalyzer


def _create_django_context(root: Path, files: dict[str, str]) -> ProjectContext:
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
        project_name="django-test-proj",
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
                name="django",
                specifier=">=5.0",
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


def test_django_001_hardcoded_debug_true(tmp_path: Path):
    ctx = _create_django_context(
        tmp_path,
        {
            "myproject/settings.py": "DEBUG = True\nSECRET_KEY = os.environ['KEY']\n",
        },
    )
    analyzer = DjangoAnalyzer()
    findings = analyzer.analyze(ctx)
    ids = [f.id for f in findings]
    assert "DJG-001" in ids


def test_django_002_hardcoded_secret_key(tmp_path: Path):
    ctx = _create_django_context(
        tmp_path,
        {
            "myproject/settings.py": "DEBUG = False\nSECRET_KEY = 'insecure-hardcoded-secret-key-12345'\n",
        },
    )
    analyzer = DjangoAnalyzer()
    findings = analyzer.analyze(ctx)
    ids = [f.id for f in findings]
    assert "DJG-002" in ids


def test_django_003_wildcard_allowed_hosts(tmp_path: Path):
    ctx = _create_django_context(
        tmp_path,
        {
            "myproject/settings.py": "DEBUG = False\nALLOWED_HOSTS = ['*']\n",
        },
    )
    analyzer = DjangoAnalyzer()
    findings = analyzer.analyze(ctx)
    ids = [f.id for f in findings]
    assert "DJG-003" in ids


def test_django_004_n_plus_one_in_loop(tmp_path: Path):
    ctx = _create_django_context(
        tmp_path,
        {
            "myapp/views.py": (
                "def render_posts(users):\n"
                "    for user in users:\n"
                "        posts = user.posts.all()\n"
                "        print(posts)\n"
            ),
        },
    )
    analyzer = DjangoAnalyzer()
    findings = analyzer.analyze(ctx)
    ids = [f.id for f in findings]
    assert "DJG-004" in ids


def test_django_005_foreign_key_missing_on_delete(tmp_path: Path):
    ctx = _create_django_context(
        tmp_path,
        {
            "myapp/models.py": (
                "from django.db import models\n\n"
                "class Post(models.Model):\n"
                "    author = models.ForeignKey('User')\n"
            ),
        },
    )
    analyzer = DjangoAnalyzer()
    findings = analyzer.analyze(ctx)
    ids = [f.id for f in findings]
    assert "DJG-005" in ids


def test_django_006_missing_csrf_middleware(tmp_path: Path):
    ctx = _create_django_context(
        tmp_path,
        {
            "myproject/settings.py": (
                "MIDDLEWARE = [\n"
                "    'django.middleware.security.SecurityMiddleware',\n"
                "    'django.contrib.sessions.middleware.SessionMiddleware',\n"
                "]\n"
            ),
        },
    )
    analyzer = DjangoAnalyzer()
    findings = analyzer.analyze(ctx)
    ids = [f.id for f in findings]
    assert "DJG-006" in ids


def test_qv_framework_django_cli(tmp_path: Path):
    runner = CliRunner()
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[project]\nname = 'dj-proj'\nversion = '0.1.0'\ndependencies = ['django>=5.0']\n",
        encoding="utf-8",
    )
    settings = tmp_path / "settings.py"
    settings.write_text(
        "import os\n"
        "DEBUG = os.getenv('DEBUG', 'False') == 'True'\n"
        "SECRET_KEY = os.environ['KEY']\n"
        "ALLOWED_HOSTS = ['localhost']\n"
        "MIDDLEWARE = ['django.middleware.csrf.CsrfViewMiddleware']\n",
        encoding="utf-8",
    )

    result = runner.invoke(cli, ["framework", str(tmp_path), "--name", "django"])
    assert result.exit_code == 0
