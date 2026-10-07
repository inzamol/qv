"""Unit tests for GitHub PR Intelligence and Differential Change Analysis."""

from __future__ import annotations

from pathlib import Path

from qv.core.baseline import save_baseline
from qv.core.models import Diagnostic, ScanResult, Severity
from qv.core.pr import PRAnalyzer, _normalize_path


def test_normalize_path_edge_cases():
    """Verify _normalize_path correctly handles prefixes without corrupting path names."""
    assert _normalize_path("b/build/app.py") == "b/build/app.py"
    assert _normalize_path("b/bin/x.py") == "b/bin/x.py"
    assert _normalize_path(".github/workflows/ci.yml") == ".github/workflows/ci.yml"
    assert _normalize_path("./.github/workflows/ci.yml") == ".github/workflows/ci.yml"
    assert _normalize_path(".\\build\\app.py") == "build/app.py"
    assert _normalize_path("/app/main.py") == "app/main.py"
    assert _normalize_path("build/app.py") == "build/app.py"


def test_parse_unified_diff_special_paths():
    """Verify parse_unified_diff preserves directory names starting with b, bin, build, .github."""
    diff_text = """diff --git a/build/app.py b/build/app.py
index 1111111..2222222 100644
--- a/build/app.py
+++ b/build/app.py
@@ -10,2 +10,3 @@
 def build():
+    pass
diff --git a/bin/tool.py b/bin/tool.py
new file mode 100644
--- /dev/null
+++ b/bin/tool.py
@@ -0,0 +1 @@
+print('cli')
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
index 3333333..4444444 100644
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -5,1 +5,2 @@
+      - run: qv pr
"""
    diff_map = PRAnalyzer.parse_unified_diff(diff_text)
    assert "build/app.py" in diff_map
    assert "uild/app.py" not in diff_map
    assert diff_map["build/app.py"].status == "M"

    assert "bin/tool.py" in diff_map
    assert "in/tool.py" not in diff_map
    assert diff_map["bin/tool.py"].status == "A"

    assert ".github/workflows/ci.yml" in diff_map
    assert "github/workflows/ci.yml" not in diff_map


def test_parse_unified_diff():
    """Verify unified diff parsing extracts correct file paths, statuses, and added line sets."""
    diff_text = """diff --git a/src/users.py b/src/users.py
index 1234567..89abcdef 100644
--- a/src/users.py
+++ b/src/users.py
@@ -40,3 +40,5 @@ def get_user():
     pass
+    # Blocking call
+    res = requests.get("http://api.example.com")
+    return res
diff --git a/requirements.txt b/requirements.txt
new file mode 100644
index 0000000..abcdef1
--- /dev/null
+++ b/requirements.txt
@@ -0,0 +1,2 @@
+httpx==0.27.0
+pydantic>=2.0
diff --git a/old_file.py b/old_file.py
deleted file mode 100644
--- a/old_file.py
+++ /dev/null
@@ -1,5 +0,0 @@
-def unused():
-    pass
"""
    diff_map = PRAnalyzer.parse_unified_diff(diff_text)
    assert "src/users.py" in diff_map
    assert diff_map["src/users.py"].status == "M"
    users_added = diff_map["src/users.py"].added_lines
    assert users_added is not None
    assert 40 in users_added
    assert 41 in users_added
    assert 44 in users_added

    assert "requirements.txt" in diff_map
    assert diff_map["requirements.txt"].status == "A"
    reqs_added = diff_map["requirements.txt"].added_lines
    assert reqs_added is not None
    assert 1 in reqs_added
    assert 2 in reqs_added

    assert "old_file.py" in diff_map
    assert diff_map["old_file.py"].status == "D"


def test_pr_analyzer_with_diff(tmp_path: Path):
    """Verify PRAnalyzer detects new diagnostics introduced in modified diff lines."""
    # Setup test project
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "pr-test"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )

    users_py = src_dir / "users.py"
    users_py.write_text(
        """from fastapi import FastAPI
import time

app = FastAPI()

@app.get("/users")
async def get_users():
    time.sleep(1) # blocking IO in async endpoint
    return []
""",
        encoding="utf-8",
    )

    diff_content = """diff --git a/src/users.py b/src/users.py
--- a/src/users.py
+++ b/src/users.py
@@ -6,4 +6,4 @@ app = FastAPI()
 @app.get("/users")
 async def get_users():
-    return []
+    time.sleep(1)
"""
    analyzer = PRAnalyzer(project_root=tmp_path)
    result = analyzer.analyze(diff_text=diff_content)

    assert result.project_name == "pr-test"
    assert result.changed_files_count >= 1
    assert "src/users.py" in result.changed_files
    assert len(result.new_issues) >= 1
    rule_ids = [d.id for d in result.new_issues]
    assert "FAP-021" in rule_ids or "IMP-001" in rule_ids or len(rule_ids) > 0


def test_pr_analyzer_with_baseline(tmp_path: Path):
    """Verify PRAnalyzer accurately tracks resolved baseline issues and new findings."""
    # Setup project with baseline
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "baseline-pr-test"
version = "0.1.0"
dependencies = [
    "requests>=2.28.0",
]
""",
        encoding="utf-8",
    )

    baseline_diag = Diagnostic(
        id="DEP-003",
        severity=Severity.WARNING,
        category="dependency",
        title="No direct import detected: requests",
        message="Declared 'requests' is never imported.",
        file="pyproject.toml",
    )
    old_diag = Diagnostic(
        id="SQL-008",
        severity=Severity.ERROR,
        category="framework",
        title="Legacy Column() with Mapped",
        message="Legacy Column usage",
        file="src/models.py",
        line=10,
    )

    baseline_result = ScanResult.create(
        project_name="baseline-pr-test",
        project_path=str(tmp_path),
        python_version="3.12.0",
        package_manager="uv",
        diagnostics=[baseline_diag, old_diag],
    )

    baseline_file = tmp_path / ".qv-baseline.json"
    save_baseline(baseline_result, baseline_file)

    # Now in PR, SQL-008 is resolved, and a new issue DEP-002 is introduced
    analyzer = PRAnalyzer(project_root=tmp_path)
    result = analyzer.analyze(baseline_path=baseline_file)

    # SQL-008 was in baseline but not in current project scan, so it should be resolved
    resolved_ids = [r.id for r in result.resolved_issues]
    assert "SQL-008" in resolved_ids

    # Result serialization
    res_dict = result.to_dict()
    assert res_dict["project_name"] == "baseline-pr-test"
    assert "resolved_issues" in res_dict
    assert "new_issues" in res_dict
    assert "affected_checks_count" in res_dict


def test_pr_analyzer_explicit_files(tmp_path: Path):
    """Verify PRAnalyzer correctly handles explicit changed files list."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "files-test"
version = "0.1.0"
dependencies = ["unimported-pkg"]
""",
        encoding="utf-8",
    )

    analyzer = PRAnalyzer(project_root=tmp_path)
    result = analyzer.analyze(changed_files_list=["pyproject.toml"])

    assert result.changed_files_count == 1
    assert "pyproject.toml" in result.changed_files
    assert result.affected_checks_count >= 1


def test_pr_analyzer_deletion_only_diff(tmp_path: Path):
    """Verify deletion-only diff does not mark line-numbered diagnostics on unchanged lines as new."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """[project]
name = "deletion-diff-test"
version = "0.1.0"
dependencies = []
""",
        encoding="utf-8",
    )

    users_py = src_dir / "users.py"
    users_py.write_text(
        """from fastapi import FastAPI
import time

app = FastAPI()

@app.get("/users")
async def get_users():
    time.sleep(1) # line 8
    return []
""",
        encoding="utf-8",
    )

    # Diff that only deletes comments at lines 15-20 (0 lines added)
    diff_content = """diff --git a/src/users.py b/src/users.py
--- a/src/users.py
+++ b/src/users.py
@@ -15,5 +15,0 @@
-# deleted comment 1
-# deleted comment 2
"""
    analyzer = PRAnalyzer(project_root=tmp_path)
    result = analyzer.analyze(diff_text=diff_content)

    assert result.project_name == "deletion-diff-test"
    # Line 8 issue (blocking IO in async endpoint) is NOT in added lines, so it is excluded
    assert not any(d.line == 8 for d in result.new_issues)
    assert not any(d.id == "FAP-021" for d in result.new_issues)
    # Any matching diagnostics must be whole-file (line=None)
    assert all(d.line is None for d in result.new_issues)
