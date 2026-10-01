# pyright: reportMissingImports=false
# ruff: noqa: F401
"""Legacy Python script using removed stdlib modules (PEP 594)."""

import distutils  # IMP-004: Removed in Python 3.12
import imp  # IMP-004: Removed in Python 3.12


def run_legacy_task():
    print("Legacy task runner")


if __name__ == "__main__":
    run_legacy_task()
