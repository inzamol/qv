"""Module A importing Module B."""

from module_b import helper_b


def run_a():
    return f"A using {helper_b()}"
