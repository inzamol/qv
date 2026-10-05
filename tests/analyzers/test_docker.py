"""Unit tests for Docker analyzer rules (DOC-001 through DOC-006)."""

from pathlib import Path

from click.testing import CliRunner

from qv.analyzers.docker.analyzer import DockerAnalyzer
from qv.cli.main import cli
from qv.core.context import (
    CIConfig,
    DockerConfig,
    ProjectContext,
    PythonRuntime,
)
from qv.core.engine import AnalysisEngine


def _create_context(tmp_path: Path, docker_config: DockerConfig) -> ProjectContext:
    runtime = PythonRuntime("3.12.0", 3, 12, 0)
    return ProjectContext(
        project_root=tmp_path,
        project_name="docker-test-project",
        python_runtime=runtime,
        package_manager="uv",
        manifest_files=(),
        lock_files=(),
        dependencies=(),
        installed_packages={},
        source_files=(),
        imports=(),
        docker=docker_config,
        ci=CIConfig(has_ci=False),
    )


def test_no_dockerfile_emits_no_diagnostics(tmp_path: Path):
    context = _create_context(tmp_path, DockerConfig(has_dockerfile=False))
    analyzer = DockerAnalyzer()
    diagnostics = analyzer.analyze(context)
    assert diagnostics == []


def test_doc_001_inefficient_layer_caching(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        "RUN pip install --no-cache-dir -r requirements.txt\n"
        "USER appuser\n"
        'CMD ["python", "main.py"]\n',
        encoding="utf-8",
    )
    (tmp_path / ".dockerignore").write_text(".venv\n", encoding="utf-8")

    context = _create_context(
        tmp_path,
        DockerConfig(
            has_dockerfile=True,
            dockerfile_path=dockerfile,
            base_image="python:3.12-slim",
            base_python_version="3.12",
            has_dockerignore=True,
            dockerignore_path=tmp_path / ".dockerignore",
        ),
    )

    analyzer = DockerAnalyzer()
    diagnostics = analyzer.analyze(context)
    caching_errors = [d for d in diagnostics if d.id == "DOC-001"]
    assert len(caching_errors) == 1
    assert "Broad 'COPY . .'" in caching_errors[0].message
    assert caching_errors[0].line == 3


def test_doc_001_layer_caching_good_pattern(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim\n"
        "WORKDIR /app\n"
        "COPY requirements.txt .\n"
        "RUN pip install --no-cache-dir -r requirements.txt\n"
        "COPY . .\n"
        "USER appuser\n"
        'CMD ["python", "main.py"]\n',
        encoding="utf-8",
    )
    (tmp_path / ".dockerignore").write_text(".venv\n", encoding="utf-8")

    context = _create_context(
        tmp_path,
        DockerConfig(
            has_dockerfile=True,
            dockerfile_path=dockerfile,
            base_image="python:3.12-slim",
            base_python_version="3.12",
            has_dockerignore=True,
            dockerignore_path=tmp_path / ".dockerignore",
        ),
    )

    analyzer = DockerAnalyzer()
    diagnostics = analyzer.analyze(context)
    caching_errors = [d for d in diagnostics if d.id == "DOC-001"]
    assert len(caching_errors) == 0


def test_doc_002_root_user_execution(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim\n"
        "WORKDIR /app\n"
        "COPY requirements.txt .\n"
        "RUN pip install --no-cache-dir -r requirements.txt\n"
        "COPY . .\n"
        'ENTRYPOINT ["python", "app.py"]\n',
        encoding="utf-8",
    )
    (tmp_path / ".dockerignore").write_text(".venv\n", encoding="utf-8")

    context = _create_context(
        tmp_path,
        DockerConfig(
            has_dockerfile=True,
            dockerfile_path=dockerfile,
            base_image="python:3.12-slim",
            base_python_version="3.12",
            has_dockerignore=True,
            dockerignore_path=tmp_path / ".dockerignore",
        ),
    )

    analyzer = DockerAnalyzer()
    diagnostics = analyzer.analyze(context)
    root_errors = [d for d in diagnostics if d.id == "DOC-002"]
    assert len(root_errors) == 1
    assert "executes as the root user" in root_errors[0].message
    assert root_errors[0].line == 6


def test_doc_003_unpinned_base_image_latest(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:latest\n"
        "WORKDIR /app\n"
        "COPY requirements.txt .\n"
        "RUN pip install --no-cache-dir -r requirements.txt\n"
        "USER appuser\n"
        'CMD ["python", "main.py"]\n',
        encoding="utf-8",
    )
    (tmp_path / ".dockerignore").write_text(".venv\n", encoding="utf-8")

    context = _create_context(
        tmp_path,
        DockerConfig(
            has_dockerfile=True,
            dockerfile_path=dockerfile,
            base_image="python:latest",
            base_python_version=None,
            has_dockerignore=True,
            dockerignore_path=tmp_path / ".dockerignore",
        ),
    )

    analyzer = DockerAnalyzer()
    diagnostics = analyzer.analyze(context)
    unpinned_errors = [d for d in diagnostics if d.id == "DOC-003"]
    assert len(unpinned_errors) == 1
    assert "uses an unpinned tag" in unpinned_errors[0].message


def test_doc_004_missing_dockerignore(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim\n"
        "WORKDIR /app\n"
        "COPY requirements.txt .\n"
        "RUN pip install --no-cache-dir -r requirements.txt\n"
        "USER appuser\n"
        'CMD ["python", "main.py"]\n',
        encoding="utf-8",
    )

    context = _create_context(
        tmp_path,
        DockerConfig(
            has_dockerfile=True,
            dockerfile_path=dockerfile,
            base_image="python:3.12-slim",
            base_python_version="3.12",
            has_dockerignore=False,
            dockerignore_path=None,
        ),
    )

    analyzer = DockerAnalyzer()
    diagnostics = analyzer.analyze(context)
    ignore_errors = [d for d in diagnostics if d.id == "DOC-004"]
    assert len(ignore_errors) == 1
    assert "without a corresponding .dockerignore file" in ignore_errors[0].message


def test_doc_005_missing_no_cache_dir_in_pip_install(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim\n"
        "WORKDIR /app\n"
        "COPY requirements.txt .\n"
        "RUN pip install -r requirements.txt\n"
        "USER appuser\n"
        'CMD ["python", "main.py"]\n',
        encoding="utf-8",
    )
    (tmp_path / ".dockerignore").write_text(".venv\n", encoding="utf-8")

    context = _create_context(
        tmp_path,
        DockerConfig(
            has_dockerfile=True,
            dockerfile_path=dockerfile,
            base_image="python:3.12-slim",
            base_python_version="3.12",
            has_dockerignore=True,
            dockerignore_path=tmp_path / ".dockerignore",
        ),
    )

    analyzer = DockerAnalyzer()
    diagnostics = analyzer.analyze(context)
    cache_errors = [d for d in diagnostics if d.id == "DOC-005"]
    assert len(cache_errors) == 1
    assert "missing '--no-cache-dir'" in cache_errors[0].message
    assert cache_errors[0].line == 4


def test_doc_006_sensitive_file_copied(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim\n"
        "WORKDIR /app\n"
        "COPY .env .env\n"
        "COPY requirements.txt .\n"
        "RUN pip install --no-cache-dir -r requirements.txt\n"
        "USER appuser\n"
        'CMD ["python", "main.py"]\n',
        encoding="utf-8",
    )
    (tmp_path / ".dockerignore").write_text(".venv\n", encoding="utf-8")

    context = _create_context(
        tmp_path,
        DockerConfig(
            has_dockerfile=True,
            dockerfile_path=dockerfile,
            base_image="python:3.12-slim",
            base_python_version="3.12",
            has_dockerignore=True,
            dockerignore_path=tmp_path / ".dockerignore",
        ),
    )

    analyzer = DockerAnalyzer()
    diagnostics = analyzer.analyze(context)
    secret_errors = [d for d in diagnostics if d.id == "DOC-006"]
    assert len(secret_errors) == 1
    assert "Potentially sensitive file" in secret_errors[0].message
    assert secret_errors[0].line == 3


def test_multi_stage_dockerfile_handling(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "# Build stage\n"
        "FROM python:3.12-slim AS builder\n"
        "WORKDIR /build\n"
        "COPY requirements.txt .\n"
        "RUN pip install --no-cache-dir -r requirements.txt\n"
        "\n"
        "# Runner stage\n"
        "FROM python:3.12-slim AS runner\n"
        "ENV PYTHONUNBUFFERED=1\n"
        "ENV PYTHONDONTWRITEBYTECODE=1\n"
        "WORKDIR /app\n"
        "COPY --from=builder /build /app\n"
        "COPY . .\n"
        "USER appuser\n"
        'CMD ["python", "main.py"]\n',
        encoding="utf-8",
    )
    (tmp_path / ".dockerignore").write_text(".venv\n", encoding="utf-8")

    context = _create_context(
        tmp_path,
        DockerConfig(
            has_dockerfile=True,
            dockerfile_path=dockerfile,
            base_image="python:3.12-slim",
            base_python_version="3.12",
            has_dockerignore=True,
            dockerignore_path=tmp_path / ".dockerignore",
        ),
    )

    analyzer = DockerAnalyzer()
    diagnostics = analyzer.analyze(context)
    # Should be clean of DOC-001, DOC-002, DOC-003, DOC-004, DOC-005, DOC-006
    assert diagnostics == []


def test_analysis_engine_integration(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        'FROM python:latest\nCMD ["python", "app.py"]\n',
        encoding="utf-8",
    )
    context = _create_context(
        tmp_path,
        DockerConfig(
            has_dockerfile=True,
            dockerfile_path=dockerfile,
            base_image="python:latest",
            base_python_version=None,
            has_dockerignore=False,
            dockerignore_path=None,
        ),
    )

    engine = AnalysisEngine(analyzers=[DockerAnalyzer()])
    result = engine.run(context)
    rule_ids = {d.id for d in result.diagnostics}
    assert "DOC-002" in rule_ids  # root user
    assert "DOC-003" in rule_ids  # unpinned latest
    assert "DOC-004" in rule_ids  # missing .dockerignore


def test_doc_007_missing_healthcheck(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim\n"
        "ENV PYTHONUNBUFFERED=1\n"
        "ENV PYTHONDONTWRITEBYTECODE=1\n"
        "EXPOSE 8000\n"
        "USER appuser\n"
        'CMD ["uvicorn", "main:app", "--port", "8000"]\n',
        encoding="utf-8",
    )
    (tmp_path / ".dockerignore").write_text(".venv\n", encoding="utf-8")

    context = _create_context(
        tmp_path,
        DockerConfig(
            has_dockerfile=True,
            dockerfile_path=dockerfile,
            base_image="python:3.12-slim",
            base_python_version="3.12",
            has_dockerignore=True,
            dockerignore_path=tmp_path / ".dockerignore",
        ),
    )

    analyzer = DockerAnalyzer()
    diagnostics = analyzer.analyze(context)
    hc_errors = [d for d in diagnostics if d.id == "DOC-007"]
    assert len(hc_errors) == 1
    assert "lacks a HEALTHCHECK" in hc_errors[0].message


def test_doc_008_missing_pythonunbuffered(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        'FROM python:3.12-slim\nUSER appuser\nCMD ["python", "main.py"]\n',
        encoding="utf-8",
    )
    (tmp_path / ".dockerignore").write_text(".venv\n", encoding="utf-8")

    context = _create_context(
        tmp_path,
        DockerConfig(
            has_dockerfile=True,
            dockerfile_path=dockerfile,
            base_image="python:3.12-slim",
            base_python_version="3.12",
            has_dockerignore=True,
            dockerignore_path=tmp_path / ".dockerignore",
        ),
    )

    analyzer = DockerAnalyzer()
    diagnostics = analyzer.analyze(context)
    unbuf_errors = [d for d in diagnostics if d.id == "DOC-008"]
    assert len(unbuf_errors) == 1
    assert "missing 'ENV PYTHONUNBUFFERED=1'" in unbuf_errors[0].message


def test_doc_009_deprecated_maintainer(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim\n"
        "MAINTAINER Jane Doe <jane@example.com>\n"
        "USER appuser\n"
        'CMD ["python", "main.py"]\n',
        encoding="utf-8",
    )
    (tmp_path / ".dockerignore").write_text(".venv\n", encoding="utf-8")

    context = _create_context(
        tmp_path,
        DockerConfig(
            has_dockerfile=True,
            dockerfile_path=dockerfile,
            base_image="python:3.12-slim",
            base_python_version="3.12",
            has_dockerignore=True,
            dockerignore_path=tmp_path / ".dockerignore",
        ),
    )

    analyzer = DockerAnalyzer()
    diagnostics = analyzer.analyze(context)
    maintainer_errors = [d for d in diagnostics if d.id == "DOC-009"]
    assert len(maintainer_errors) == 1
    assert "Deprecated MAINTAINER" in maintainer_errors[0].message


def test_doc_010_sudo_usage(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        'FROM python:3.12-slim\nRUN sudo apt-get update\nUSER appuser\nCMD ["python", "main.py"]\n',
        encoding="utf-8",
    )
    (tmp_path / ".dockerignore").write_text(".venv\n", encoding="utf-8")

    context = _create_context(
        tmp_path,
        DockerConfig(
            has_dockerfile=True,
            dockerfile_path=dockerfile,
            base_image="python:3.12-slim",
            base_python_version="3.12",
            has_dockerignore=True,
            dockerignore_path=tmp_path / ".dockerignore",
        ),
    )

    analyzer = DockerAnalyzer()
    diagnostics = analyzer.analyze(context)
    sudo_errors = [d for d in diagnostics if d.id == "DOC-010"]
    assert len(sudo_errors) == 1
    assert "Unnecessary 'sudo'" in sudo_errors[0].message


def test_doc_011_apt_cleanup_and_recommends(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim\n"
        "RUN apt-get update && apt-get install -y curl\n"
        "USER appuser\n"
        'CMD ["python", "main.py"]\n',
        encoding="utf-8",
    )
    (tmp_path / ".dockerignore").write_text(".venv\n", encoding="utf-8")

    context = _create_context(
        tmp_path,
        DockerConfig(
            has_dockerfile=True,
            dockerfile_path=dockerfile,
            base_image="python:3.12-slim",
            base_python_version="3.12",
            has_dockerignore=True,
            dockerignore_path=tmp_path / ".dockerignore",
        ),
    )

    analyzer = DockerAnalyzer()
    diagnostics = analyzer.analyze(context)
    apt_errors = [d for d in diagnostics if d.id == "DOC-011"]
    assert len(apt_errors) == 1
    assert "apt-get install" in apt_errors[0].message


def test_doc_012_add_instruction_used(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim\n"
        "ADD requirements.txt /app/requirements.txt\n"
        "USER appuser\n"
        'CMD ["python", "main.py"]\n',
        encoding="utf-8",
    )
    (tmp_path / ".dockerignore").write_text(".venv\n", encoding="utf-8")

    context = _create_context(
        tmp_path,
        DockerConfig(
            has_dockerfile=True,
            dockerfile_path=dockerfile,
            base_image="python:3.12-slim",
            base_python_version="3.12",
            has_dockerignore=True,
            dockerignore_path=tmp_path / ".dockerignore",
        ),
    )

    analyzer = DockerAnalyzer()
    diagnostics = analyzer.analyze(context)
    add_errors = [d for d in diagnostics if d.id == "DOC-012"]
    assert len(add_errors) == 1
    assert "ADD instruction" in add_errors[0].message


def test_doc_013_missing_dont_write_bytecode(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        'FROM python:3.12-slim\nUSER appuser\nCMD ["python", "main.py"]\n',
        encoding="utf-8",
    )
    (tmp_path / ".dockerignore").write_text(".venv\n", encoding="utf-8")

    context = _create_context(
        tmp_path,
        DockerConfig(
            has_dockerfile=True,
            dockerfile_path=dockerfile,
            base_image="python:3.12-slim",
            base_python_version="3.12",
            has_dockerignore=True,
            dockerignore_path=tmp_path / ".dockerignore",
        ),
    )

    analyzer = DockerAnalyzer()
    diagnostics = analyzer.analyze(context)
    bytecode_errors = [d for d in diagnostics if d.id == "DOC-013"]
    assert len(bytecode_errors) == 1
    assert "missing 'ENV PYTHONDONTWRITEBYTECODE=1'" in bytecode_errors[0].message


def test_doc_014_web_server_missing_expose(tmp_path: Path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim\n"
        "ENV PYTHONUNBUFFERED=1\n"
        "ENV PYTHONDONTWRITEBYTECODE=1\n"
        "USER appuser\n"
        'CMD ["uvicorn", "main:app", "--port", "8000"]\n',
        encoding="utf-8",
    )
    (tmp_path / ".dockerignore").write_text(".venv\n", encoding="utf-8")

    context = _create_context(
        tmp_path,
        DockerConfig(
            has_dockerfile=True,
            dockerfile_path=dockerfile,
            base_image="python:3.12-slim",
            base_python_version="3.12",
            has_dockerignore=True,
            dockerignore_path=tmp_path / ".dockerignore",
        ),
    )

    analyzer = DockerAnalyzer()
    diagnostics = analyzer.analyze(context)
    expose_errors = [d for d in diagnostics if d.id == "DOC-014"]
    assert len(expose_errors) == 1
    assert "without an EXPOSE instruction" in expose_errors[0].message


def test_qv_docker_cli_command(tmp_path: Path):
    runner = CliRunner()
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[project]\nname = 'test-proj'\nversion = '0.1.0'\ndependencies = []\n",
        encoding="utf-8",
    )
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12-slim\n"
        "ENV PYTHONUNBUFFERED=1\n"
        "ENV PYTHONDONTWRITEBYTECODE=1\n"
        "USER appuser\n"
        'CMD ["python", "main.py"]\n',
        encoding="utf-8",
    )
    (tmp_path / ".dockerignore").write_text(".venv\n", encoding="utf-8")

    result = runner.invoke(cli, ["docker", str(tmp_path)])
    assert result.exit_code == 0
