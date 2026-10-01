"""Module B importing Module A creating circular dependency cycle."""

from module_a import run_a


def helper_b():
    return f"B helper calls {run_a}"
