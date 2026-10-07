---
name: qv-development
description: >-
  Comprehensive guide and domain knowledge for developing, debugging, extending, and maintaining the QV (python-qv) codebase.
  Activate this skill whenever working on QV, adding new diagnostic rules, implementing core or framework analyzers, creating CLI commands or reporters, modifying the remediation engine, writing test fixtures, troubleshooting AST/dependency/lockfile analysis, or running test and lint suites.
---

# QV (python-qv) Development Skill

This skill provides expert knowledge and actionable runbooks for developing, debugging, extending, and testing the **QV (`python-qv`)** project.

QV is a Python static diagnostics and health-check tool that inspects Python projects to explain root causes of issues and suggest safe, automated fixes.

---

## Quick Reference Links

- [Architecture Reference](./references/architecture.md): High-level architecture, module directory map, and execution pipeline.
- [Adding Rules & Analyzers](./references/adding-rules-and-analyzers.md): Step-by-step workflow for adding rules, framework plugins, and auto-fix remediations.
- [Debugging & Testing Guide](./references/debugging-and-testing.md): Pytest commands, linting, type-checking, common pitfalls, and AST gotchas.

---

## Core System Architecture

```text
Discovery (load_project) ➔ Context (ProjectContext) ➔ Engine (AnalysisEngine)
    ├── Core Analyzers: dependencies, environment, imports, packaging, security, docker, ci
    └── Framework Analyzers: fastapi, sqlalchemy, django, celery
        ➔ Root Cause Grouping ➔ Reporters (Terminal, Doctor, HTML, SARIF, JSON, PR, Annotator)
                              └── Remediation (RemediationEngine)
```

1. **Discovery & Context**: `load_project()` scans manifests (`pyproject.toml`, `requirements.txt`, lockfiles) and builds an immutable `ProjectContext` (ASTs, module graph, dependencies).
2. **Analysis Pipeline**: `AnalysisEngine` runs core and framework analyzers. Exceptions within analyzers are safely wrapped into `ENG-001` diagnostics to prevent scan crashes.
3. **Correlation**: Symptoms are grouped into `RootCause` items to provide actionable recommendations.
4. **Reporters & Remediation**: Results are output via Rich terminal, HTML report, SARIF, JSON, or Doctor scorecard, and safe fixes are applied via `RemediationEngine` using `tomlkit`.

---

## Standard Development Workflows

### 1. Environment & Running Tests
Always use `uv` for running commands in the virtual environment:
```bash
# Run the test suite
uv run pytest

# Run a specific test file or pattern
uv run pytest tests/test_fastapi.py -v -k "test_pattern"

# Run linters and formatters
uv run ruff check .
uv run ruff format --check .

# Run type checking
uv run pyright
```

### 2. Adding a New Diagnostic Rule
When adding a diagnostic rule (e.g. `FAP-035` or `DEP-007`):
1. **Declare the rule** in `src/qv/rules/registry.py` under `RULES_CATALOG` with a `RuleDefinition` (ID, category, title, description, default_severity, remediation_hint, doc_url).
2. **Implement detection** in the relevant analyzer (`src/qv/analyzers/` or `src/qv/frameworks/`) producing a `Diagnostic` object.
3. **Add documentation** in `docs/rules.md` matching the rule slug.
4. **Add unit tests** in `tests/` covering both positive (violation detected) and negative (valid code passed) cases.

### 3. Adding a Framework Analyzer
1. Create `src/qv/frameworks/<framework>.py` inheriting from `BaseFrameworkAnalyzer`.
2. Implement `is_applicable(context)` and `analyze(context)`.
3. Register the new analyzer class in `src/qv/frameworks/__init__.py` under `AVAILABLE_FRAMEWORK_ANALYZERS`.

### 4. Adding Remediation / Auto-Fixes
1. Implement fix generator in `src/qv/remediation/engine.py`.
2. Always use `tomlkit` for modifying TOML files to preserve comments, indentation, and styling.
3. Support dry-run mode (`qv fix --dry-run`).
4. Add verification tests in `tests/test_remediation.py`.

---

## Critical Invariants & Best Practices

1. **No Fatal Analyzer Failures**: Analyzers must never let uncaught exceptions crash the entire CLI scan. The engine isolates analyzer execution and logs `ENG-001`.
2. **Immutable Context**: Analyzers must treat `ProjectContext` as read-only.
3. **Package Normalization**: Use `packaging.utils.canonicalize_name` when comparing package names to avoid mismatch bugs (e.g. `uvicorn[standard]` vs `uvicorn`, `PyYAML` vs `pyyaml`).
4. **Safe Remediations**: Only deterministic, safe fixes should be automated. Destructive changes must require explicit flags or user confirmation.
5. **Cross-Platform Compatibility**: Always account for Windows path separators and terminal UTF-8 encoding.
6. **Architecture Graph Component Boundaries**:
   - **Never use file-count thresholds** (e.g. `len(files) > 10`) to shift component classification depth. In flat layouts (e.g. `api/v1/users.py`, `services/billing/charge.py`), nested subdirectories must not override the top-level architectural layer (`api`, `services`).
   - **Only treat `clean_parts[1]` as a subpackage when `clean_parts[0]` is a verified package root** (e.g. `pkg_name`, `"qv"`, or discovered roots under `src/` or `lib/`).
   - **Do not create phantom components for package-root files**: `__init__.py`, `__main__.py`, and `version.py` at the root must not create a separate component (like `qv`) that creates artificial cycles with subpackages (`qv <-> cli`).
7. **Third-Party vs Internal Import Resolution**:
   - **Never match arbitrary dotted segments of imports to component slugs**: Resolving imports to internal components must only check the top-level segment (`top = mod_name.split(".")[0]`) or registered internal modules. Never iterate all dotted segments (`parts = mod_name.split(".")`), as external imports like `sqlalchemy.orm.Session`, `requests.api.get`, or `click.core` will match internal slugs (`orm`, `api`, `core`) and create fake cycles or layer violations.
8. **CLI Diagnostic Emission & Strict Verification**:
   - Any CLI command claiming to check specific rules (e.g. `qv architecture` checking `ARC-001` and `ARC-002`) must actually emit them as standardized `Diagnostic` instances in `ScanResult`, and must fail with exit code `1` when `--strict` is enabled.
   - Tests must assert specific diagnostic codes (`assert "ARC-001" in result.output`) and must never use fallback passes (such as `"Passed" in result.output`) that mask gaps.

