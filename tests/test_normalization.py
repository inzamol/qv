"""Tests for dependency name normalization (AC-06)."""

from pathlib import Path

from qv.analyzers.dependencies.analyzer import DependencyAnalyzer
from qv.core.config import canonicalize_dependency_name
from qv.core.project import load_project


def test_hyphen_underscore_package_match():
    """AC-06: Equivalent package names with hyphens and underscores resolve identically."""
    assert canonicalize_dependency_name("scikit-learn") == "scikit-learn"
    assert canonicalize_dependency_name("scikit_learn") == "scikit-learn"
    assert canonicalize_dependency_name("scikit-learn>=1.0") == "scikit-learn"
    assert canonicalize_dependency_name("scikit_learn>=1.0") == "scikit-learn"
    assert canonicalize_dependency_name("my_cool_pkg") == "my-cool-pkg"
    assert canonicalize_dependency_name("my-cool-pkg") == "my-cool-pkg"


def test_case_insensitive_package_match():
    """AC-06: Package comparison is case-insensitive."""
    assert canonicalize_dependency_name("Scikit-Learn") == "scikit-learn"
    assert canonicalize_dependency_name("SCIKIT_LEARN") == "scikit-learn"
    assert canonicalize_dependency_name("AMQP") == "amqp"
    assert canonicalize_dependency_name("Pydantic") == "pydantic"
    assert canonicalize_dependency_name("HTTPX") == "httpx"


def test_requirement_specifier_match():
    """AC-06: Requirement specifiers (~=, >=, ==, <, etc.) resolve to canonical base name."""
    assert canonicalize_dependency_name("requests>=2.31.0") == "requests"
    assert canonicalize_dependency_name("requests~=2.31.0") == "requests"
    assert canonicalize_dependency_name("requests==2.31.0") == "requests"
    assert canonicalize_dependency_name("requests<3.0.0,>=2.0.0") == "requests"
    assert canonicalize_dependency_name("click!=8.0.0") == "click"


def test_requirement_with_extras_match():
    """AC-06: Requirements with extras (e.g. package[extra]>=1.0) resolve to canonical base name."""
    assert canonicalize_dependency_name("celery[redis]>=5.2.0") == "celery"
    assert canonicalize_dependency_name("pydantic[email,dotenv]~=2.0") == "pydantic"
    assert canonicalize_dependency_name("uvicorn[standard]") == "uvicorn"
    assert canonicalize_dependency_name("fastapi[all]>=0.100.0") == "fastapi"


def test_normalization_in_dependency_analyzer(tmp_path: Path):
    """AC-06 Integration: Declared package 'scikit_learn' matches import 'sklearn' without false positives."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "norm-demo"
version = "0.1.0"
dependencies = [
    "scikit_learn>=1.2.0",
    "python_dotenv[cli]~=1.0.0",
]
""",
        encoding="utf-8",
    )
    main_py = tmp_path / "main.py"
    main_py.write_text("import sklearn\nimport dotenv\n", encoding="utf-8")

    project = load_project(tmp_path)
    analyzer = DependencyAnalyzer()
    diagnostics = analyzer.analyze(project.context)

    # No missing or unused dependency diagnostics should be emitted
    assert len(diagnostics) == 0
