# Debugging & Testing Guide for QV

This guide covers debugging techniques, running tests, type checking, linting, and troubleshooting common issues in QV.

---

## 1. Development Commands

Always use `uv` to run tools and scripts in the virtual environment.

### Testing with Pytest
```bash
# Run all tests
uv run pytest

# Run a specific test file
uv run pytest tests/test_engine.py

# Run a specific test function with verbose output
uv run pytest tests/test_fastapi.py -k "test_route_validation" -vv

# Run with test coverage
uv run pytest --cov=qv --cov-report=term-missing
```

### Static Analysis & Linting
```bash
# Lint check with ruff
uv run ruff check .

# Auto-fix lint violations
uv run ruff check --fix .

# Code formatting check
uv run ruff format --check .

# Format code
uv run ruff format .

# Type checking with pyright
uv run pyright
```

### Building Documentation
```bash
# Build docs
uv run mkdocs build --strict

# Run local doc server
uv run mkdocs serve
```

---

## 2. Debugging Common Issues & Gotchas

### 1. `ENG-001` Diagnostic Emitted During Scan
- **Symptom:** `ENG-001` appears in scan results: "Analyzer <name> failed during execution".
- **Cause:** An unhandled exception occurred inside an analyzer's `analyze()` method.
- **Debugging:** Run with `--verbose` or attach a debugger in `src/qv/core/engine.py` inside the analyzer loop to inspect the traceback. Ensure AST traversal handles unexpected node types or malformed syntax trees gracefully.

### 2. Module Import Issues in Tests
- **Symptom:** `ModuleNotFoundError: No module named 'tomlkit'` (or similar) when running `pytest` directly.
- **Fix:** Always execute tests via `uv run pytest` or activate the project `.venv` first.

### 3. Windows Encoding Issues (`UnicodeEncodeError`)
- **Symptom:** Rich console or terminal output fails with character encoding errors on Windows terminal.
- **Fix:** `src/qv/cli/main.py` contains `sys.stdout.reconfigure(encoding="utf-8")`. Ensure any direct file writes or sub-processes explicitly specify `encoding="utf-8"`.

### 4. Dependency & Lockfile Parsing Bugs
- **Symptom:** Missing packages or false-positive `DEP-002`/`DEP-003` findings.
- **Checklist:**
  - Check package name normalization (e.g., `PyYAML` vs `pyyaml`, underscores vs hyphens) using `packaging.utils.canonicalize_name`.
  - Check whether package imports differ from distribution names (e.g. `pydantic` vs `pydantic_core`, `PIL` vs `Pillow`, `yaml` vs `pyyaml`, `dotenv` vs `python-dotenv`).
  - Verify if standard library modules are correctly identified via `sys.stdlib_module_names` or fallback lists for Python 3.10+.

### 5. AST Parsing Across Python Versions
- **Symptom:** Syntax error when parsing modern Python 3.11/3.12 syntax (e.g., match-case, type parameter syntax PEP 695).
- **Rule:** `ProjectContext` parses ASTs using Python's standard `ast.parse`. If parsing fails due to syntax errors in user code, QV logs a warning/diagnostic rather than failing the scan.

### 6. Safe Remediations & TOML Formatting
- **Symptom:** `pyproject.toml` loses comments or formatting when running `qv fix`.
- **Rule:** Never use standard `tomli_w` or dictionary dump for auto-fixes. Always use `tomlkit` document editing to preserve comments, indentation, and structure.
