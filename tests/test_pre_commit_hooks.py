"""Tests for pre-commit hooks configuration."""

from __future__ import annotations

from pathlib import Path


def test_pre_commit_hooks_file_exists_and_valid():
    hooks_file = Path(__file__).parent.parent / ".pre-commit-hooks.yaml"
    assert hooks_file.exists(), ".pre-commit-hooks.yaml must exist at repo root"

    content = hooks_file.read_text(encoding="utf-8")
    assert "- id: qv-scan" in content
    assert "name: qv scan" in content
    assert "entry: qv scan" in content
    assert "language: python" in content

    assert "- id: qv-fix" in content
    assert "name: qv fix" in content
    assert "entry: qv fix -y" in content
