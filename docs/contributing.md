# Contributor Guide

Welcome to the `qv` project! We appreciate contributions to make Python project health diagnostics faster, more accurate, and more helpful.

---

## Development Setup

`qv` uses `uv` for fast, reproducible dependency management.

### 1. Clone & Sync

```bash
git clone https://github.com/inzamol/qv.git
cd qv

# Create venv and install all dev dependencies
uv sync --extra dev
```

### 2. Run Tests
 
```bash
uv run pytest
```

### 3. Multi-Environment Matrix Testing (Tox)

Run tests, linting, and typechecking locally across all environments before submitting a PR:

```bash
# Run all configured tox environments
uv run tox

# Or run specific test environments
uv run tox -e py312
uv run tox -e lint
uv run tox -e typecheck
```

### 4. Lint & Format

```bash
uv run ruff check .
uv run ruff format .
```

---

## Architecture Overview

```text
               CLI (click + rich)
                       │
               Project Discovery
                       │
              ProjectContext (Immutable)
                       │
        ┌──────────────┼──────────────┐
  Dependencies    Environment       Imports      Packaging
    Analyzer        Analyzer        Analyzer      Analyzer
        └──────────────┬──────────────┘
                       │
                AnalysisEngine
                       │
               Diagnostic Model
                       │
              Root Cause Correlator
                       │
         ┌─────────────┼─────────────┐
      Terminal       JSON          SARIF
      Reporter     Reporter       Reporter
```

---

## Adding a New Diagnostic Rule

1. **Rule ID**: Choose a stable, permanent ID (e.g. `DEP-007`, `IMP-005`).
2. **Catalog Entry**: Register rule metadata in `src/qv/rules/registry.py`.
3. **Analyzer Implementation**: Implement the check inside the appropriate analyzer under `src/qv/analyzers/`.
4. **Diagnostic Construction**: Emit a `Diagnostic` object with clear `title`, `message`, `evidence`, and `suggestions`.
5. **Unit Tests**: Add positive tests (detecting issue) and negative tests (false-positive prevention) in `tests/analyzers/`.
6. **Documentation**: Update `docs/rules.md`.

---

## Code Quality Standards

- Type annotations on all functions.
- Deterministic by default — zero network calls during standard analysis.
- Every diagnostic must supply verifiable evidence.
- Full test coverage for new rules.
