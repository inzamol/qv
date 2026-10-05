# qv

<div align="center">

### Modern diagnostic and health analyzer for Python projects

Diagnose root causes across dependency resolvers, runtime environment drift, circular imports, and framework anti-patterns with safe, actionable fixes.

[![PyPI Version](https://img.shields.io/pypi/v/python-qv.svg?style=flat-square&color=2563eb)](https://pypi.org/project/python-qv/)
[![Python Versions](https://img.shields.io/pypi/pyversions/python-qv.svg?style=flat-square&color=2563eb)](https://pypi.org/project/python-qv/)
[![CI Status](https://img.shields.io/github/actions/workflow/status/inzamol/qv/ci.yml?branch=main&style=flat-square)](https://github.com/inzamol/qv/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-gray.svg?style=flat-square)](https://opensource.org/licenses/MIT)

[Installation](#installation) &bull; [Quick Start](#quick-start) &bull; [Interactive TUI](#interactive-tui-explorer) &bull; [Rule Categories](#rule-categories--capabilities) &bull; [CLI Commands](#cli-commands--usage) &bull; [Configuration](#configuration) &bull; [CI/CD Integration](#cicd-integration) &bull; [Documentation](https://inzamol.github.io/qv/)

</div>

---

## Why qv

Python projects rarely fail because of syntax errors. They fail because of **ecosystem friction**:
- Incompatible transitive dependency constraints that break package resolvers.
- Missing dependencies imported in source files but omitted from `pyproject.toml`.
- Docker containers pinned to older runtimes while developers work on newer Python releases.
- Silent circular imports that only crash at runtime when specific execution paths trigger.

Instead of parsing hundreds of lines of cryptic resolver logs, **`qv`** analyzes your project in milliseconds, isolates the root cause, provides concrete evidence, and outputs copy-paste remediation commands.

### Complete Project Health Scorecard (`qv doctor`)

```text
QV Project Health
────────────────────────────────────────

Dependencies       92/100   █████████░
Security           84/100   ████████░░
Packaging          96/100   ██████████
Architecture       78/100   ████████░░
Environment        91/100   █████████░
Framework          88/100   █████████░

Health Score: 87/100

3 high-priority issues
7 warnings
42 checks passed

Top problems:
  1. SQL-014  N+1 query detected
  2. DEP-002  Missing dependency: httpx
  3. ENV-003  Python version mismatch

Run `qv explain SQL-014` for details.
```

### Deep Diagnostic Evidence Scan (`qv scan`)

```text
qv
Project: payment-service
Python:  3.12.7
Package Manager: uv

1 Errors   1 Warnings   48 Checks Passed

┌────────────────── [ERROR] DEP-001 Dependency constraint conflict ───────────┐
│ celery 5.4.0 requires kombu<5.4.0,>=5.3.0, but installed is kombu 5.5.2.     │
│                                                                              │
│ Evidence:                                                                    │
│   - celery declared requirement: kombu<5.4.0,>=5.3.0                         │
│   - Installed kombu version: 5.5.2 in active environment                     │
│                                                                              │
│ Suggested fix:                                                               │
│   Upgrade celery or pin kombu to <5.4.0,>=5.3.0.                             │
│   $ uv add 'kombu<5.4.0,>=5.3.0'                                             │
└──────────────────────────────────────────────────────────────────────────────┘

Health Score: 85/100
```

---

## Installation & Execution

### 1. Ephemeral Run (Zero Installation Required)
Run `qv` instantly without installing anything into your environment:
```bash
# Run health scorecard
uvx python-qv doctor
# or
pipx run python-qv doctor

# Run detailed scan
uvx python-qv scan
# or
pipx run python-qv scan
```

### 2. Standard Project Dependency (PyPI)
Install `python-qv` as a development dependency into your active virtual environment:
```bash
# Using uv
uv add python-qv --dev

# Using pip
pip install python-qv

# Using poetry
poetry add python-qv --group dev
```

### 3. Global CLI Tool Installation
Install `qv` globally in an isolated environment as a standalone system command:
```bash
# Using uv tool
uv tool install python-qv

# Using pipx
pipx install python-qv
```

### 4. Install Latest Development Version (from GitHub)
Install the latest cutting-edge build directly from the `main` branch:
```bash
# With pip
pip install git+https://github.com/inzamol/qv.git

# With uv tool
uv tool install git+https://github.com/inzamol/qv.git
```

### 5. Install from Local Codebase Clone (Editable Mode)
For development, local testing, and contributing:
```bash
git clone https://github.com/inzamol/qv.git
cd qv

# Using uv
uv pip install -e .

# Using pip
pip install -e .
```

---

## Quick Start

### 1. Run Complete Project Health Report (`qv doctor`)
Get a complete project health report across all 6 core pillars in one command:
```bash
qv doctor
```

### 2. Run Detailed Diagnostic Scan (`qv scan`)
Run a deep diagnostic scan with full evidence panels and remediation commands:
```bash
qv scan
```

### 3. Launch the Interactive TUI Explorer
Navigate findings with keyboard controls, view AST details, and trigger 1-key remediation:
```bash
qv inspect
# or shorthand
qv ui
```

### 4. Generate a Standalone HTML Report
Export an interactive HTML dashboard with health metrics, filters, and dark/light modes:
```bash
qv scan --html report.html
```

### 5. Explain Any Rule
Get full context, common causes, and remediation advice for any diagnostic rule code:
```bash
qv explain DEP-001
```

### 6. Initialize Configuration
Add default configuration rules to `pyproject.toml` without overwriting existing settings:
```bash
qv init
```

---

## Interactive TUI Explorer

Run `qv inspect` (or `qv ui`) for a full terminal dashboard:

```text
┌────────────────────────────────────────────── qv Explorer ──────────────────────────────────────────────┐
│  qv Explorer  |  Project: payment-service  |  Health Score: 65/100                                       │
│  Python: 3.12.7  |  Package Manager: uv  |  Errors: 2  |  Warnings: 1  |  Checks Passed: 48             │
├────────────────────────── Findings (1/3) ──────────────────────────┬──────────────── Details: DEP-001 ──┤
│     Sev   Rule     Title                                           │ [ERROR] DEP-001: Constraint conflict│
│  >  ERR   DEP-001  Dependency constraint conflict                  │ celery requires kombu<5.4.0,>=5.3.0│
│     ERR   DEP-002  Missing dependency: httpx                       │ Location: pyproject.toml           │
│     WARN  IMP-003  Unused / orphan module: legacy_calc.py          │                                    │
│                                                                    │ Suggested Remediation:             │
│                                                                    │   Pin kombu to <5.4.0,>=5.3.0      │
│                                                                    │   $ uv add 'kombu<5.4.0'           │
├────────────────────────────────────────────────────────────────────┴────────────────────────────────────┤
│ [Up/k, Down/j] Navigate  |  [Enter] Expand  |  [f] Apply Fix  |  [t] Tree View  |  [q] Quit             │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

- **`Up / k` & `Down / j`**: Navigate findings list.
- **`f`**: Apply automated remediation for selected finding.
- **`t`**: Toggle between Findings view and live Dependency Tree.
- **`Enter`**: Expand and focus finding details panel.
- **`q`**: Exit dashboard.

---

## Rule Categories & Capabilities

`qv` features over 80 built-in rules across general and framework-specific analyzers:

| Category | Rule IDs | Focus Area | Default Severity |
|---|---|---|---|
| **Dependencies** | `DEP-001` - `DEP-006` | Constraint conflicts, undeclared imports, unused dependencies, Python version mismatches, security vulnerabilities | `ERROR` / `WARNING` |
| **Environment** | `ENV-001` - `ENV-003` | Active interpreter drift, Dockerfile base image mismatches, CI matrix drift | `WARNING` |
| **Architecture** | `IMP-001` - `IMP-004` | Circular import cycles, unresolved local imports, orphan modules, deprecated stdlib modules | `ERROR` / `WARNING` |
| **Packaging** | `PKG-001` - `PKG-002` | Missing PEP 621 metadata, invalid configuration syntax | `ERROR` / `WARNING` |
| **FastAPI Doctor** | `FAP-001` - `FAP-038` | Blocking I/O in async routes, missing response models, insecure CORS, untyped request bodies, Pydantic v2 migrations | `ERROR` / `WARNING` |
| **SQLAlchemy Doctor** | `SQL-001` - `SQL-030` | N+1 queries in loops, unclosed sessions, SQL injection risks, sync DB calls in async event loop, 2.0 mapped columns | `ERROR` / `WARNING` |

*Refer to the complete [Rules Catalog](docs/rules.md) for full descriptions and remediation guides.*

---

## CLI Commands & Usage

### 1. Diagnostic & Health Scanning (`qv scan`)

Perform comprehensive health scans across dependencies, runtime environment, imports, and framework code.

#### Standard Project Scan
```bash
# Scan current directory
qv scan

# Scan a specific directory or microservice
qv scan ./services/payment
```

**Terminal Output (Healthy Project):**
```text
qv
Project: python-qv
Python:  3.12.7
Package Manager: uv

0 Errors   0 Warnings   65 Checks Passed

Everything looks healthy. No diagnostic issues found.
Health Score: 100/100
```

**Terminal Output (Project with Findings):**
```text
qv
Project: payment-service
Python:  3.12.7
Package Manager: uv

2 Errors   1 Warnings   48 Checks Passed

┌────────────────── [ERROR] DEP-001 Dependency constraint conflict ───────────┐
│ celery 5.4.0 requires kombu<5.4.0,>=5.3.0, but installed is kombu 5.5.2.     │
│                                                                              │
│ Evidence:                                                                    │
│   - celery declared requirement: kombu<5.4.0,>=5.3.0                         │
│   - Installed kombu version: 5.5.2 in active environment                     │
│                                                                              │
│ Suggested fix:                                                               │
│   Upgrade celery or pin kombu to <5.4.0,>=5.3.0.                             │
│   $ uv add 'kombu<5.4.0,>=5.3.0'                                             │
└──────────────────────────────────────────────────────────────────────────────┘

┌────────────────── [ERROR] DEP-002 Missing dependency declaration ───────────┐
│ Package 'httpx' is imported in src/client.py but is not in pyproject.toml.   │
│                                                                              │
│ Suggested fix:                                                               │
│   $ uv add httpx                                                             │
└──────────────────────────────────────────────────────────────────────────────┘

┌────────────────── [WARN] DEP-002 Undeclared transitive dependency: kombu ────┐
│ Module 'kombu' is imported in src/tasks.py:3 and provided transitively        │
│ by 'celery', but is not declared directly in project dependencies.           │
│                                                                              │
│ Evidence:                                                                    │
│   - Import statement: `import kombu` in src/tasks.py:3                       │
│   - 'kombu' is currently installed as a transitive dependency via 'celery',  │
│     but is not declared directly.                                            │
│                                                                              │
│ Suggested fix:                                                               │
│   Add 'kombu' directly to project dependencies in pyproject.toml.            │
│   $ uv add kombu                                                             │
└──────────────────────────────────────────────────────────────────────────────┘

┌────────────────── [WARN] IMP-003 Unused / orphan local module ──────────────┐
│ File 'src/utils/legacy_calc.py' is never imported by any project module.     │
│                                                                              │
│ Suggested fix:                                                               │
│   Review if this module is obsolete and can be safely deleted.              │
└──────────────────────────────────────────────────────────────────────────────┘

Health Score: 60/100
```

#### Strict Mode & Severity Filtering
```bash
# Fail with exit code 1 if any warnings or errors exist
qv scan --strict

# Filter by minimum severity level (error, warning, info)
qv scan --severity error

# Shorthand flags
qv scan -E            # --errors-only: display errors only
qv scan -W            # --hide-warnings: hide warning diagnostics
```

#### Interactive HTML Dashboard Export
```bash
qv scan --html report.html
```

**Terminal Output:**
```text
HTML report successfully written to report.html

qv
Project: python-qv
Python:  3.12.7
Package Manager: uv

0 Errors   0 Warnings   65 Checks Passed
Health Score: 100/100
```

#### JSON and SARIF Export (CI / Code Scanning)
```bash
# Output SARIF format for GitHub Security Code Scanning tab
qv scan --sarif -o results.sarif

# Output machine-readable JSON for custom pipelines
qv scan --json -o findings.json

# Emit GitHub Actions workflow command annotations (::error:: and ::warning::)
qv scan --ci --github-annotations
```

#### Airgapped / Offline Mode
```bash
# Disable remote network queries (e.g. vulnerability feeds and PyPI index checks)
qv scan --offline
```

---

### 2. Interactive Terminal Dashboard (`qv inspect` / `qv ui`)

Launch a full-screen interactive TUI to inspect findings, view location traces, inspect circular import trees, and trigger fixes interactively.

```bash
# Inspect current repository
qv inspect

# Shorthand alias
qv ui

# Inspect target project in offline mode
qv inspect ./services/backend --offline
```

---

### 3. Automated Safe Remediation (`qv fix`)

Safely and automatically apply deterministic configuration and code fixes.

#### Dry-Run Mode
Preview proposed file modifications and shell commands without writing changes to disk:

```bash
qv fix --dry-run
```

**Terminal Output:**
```text
Found 2 actionable fix(es) (2 safe):

Proposed Fixes
┌─────────┬────────────────┬───────────────────────────────────────────────────┬──────────────┐
│ Rule    │ Target         │ Description                                       │ Type         │
├─────────┼────────────────┼───────────────────────────────────────────────────┼──────────────┤
│ DEP-002 │ pyproject.toml │ Add missing dependency 'httpx' to pyproject.toml  │ config_patch │
│ DEP-003 │ pyproject.toml │ Remove unused dependency 'pyyaml'                 │ config_patch │
└─────────┴────────────────┴───────────────────────────────────────────────────┴──────────────┘

Dry-run mode enabled. No changes written to disk.
```

#### Applying Fixes
```bash
# Apply all safe fixes without interactive confirmation prompts
qv fix -y

# Fix a specific rule only
qv fix --rule DEP-002 -y

# Apply fixes and execute package manager sync commands (e.g. uv sync / poetry install)
qv fix -y --sync
```

**Terminal Output:**
```text
Found 1 actionable fix(es) (1 safe):

Successfully applied 1 fix(es):
  + Add missing dependency 'httpx' to pyproject.toml
```

---

### 4. Dependency & Import Architecture Visualizer (`qv tree` / `qv graph`)

Render structured visual trees of package dependencies and internal source module import architecture.

#### Full Hierarchy Overview
```bash
qv tree
```

**Terminal Output:**
```text
Dependency Hierarchy
└── fastapi (0.115.0)
    ├── pydantic (2.9.2)
    │   └── pydantic-core (2.23.4)
    ├── starlette (0.38.6)
    │   └── anyio (4.6.0)
    └── typing-extensions (4.12.2)

Internal Module Import Architecture
└── app.main
    ├── app.api.routes
    │   └── app.core.config
    └── app.db.session
        └── app.models.user [CYCLE DETECTED]
```

#### Targeted Tree Views
```bash
# Show internal module imports and circular cycles only
qv tree --imports
qv tree -i

# Show direct and transitive package dependencies up to depth 2
qv tree --dependencies --depth 2
qv tree -d -L 2

# Export tree statistics and cycle detection as JSON
qv tree --json
```

---

### 5. Framework-Specific Analyzers (`qv framework`)

Run dedicated analyzers tailored for popular frameworks.

#### FastAPI Analyzer (`FAP-001` - `FAP-038`)
```bash
qv framework --name fastapi
```

**Terminal Output:**
```text
qv (FastAPI Doctor)
Project: my-api
Python:  3.12.7

1 Errors   1 Warnings   32 Checks Passed

┌────────────────── [ERROR] FAP-001 Blocking call in async endpoint ───────────┐
│ File 'src/api/users.py:42'                                                   │
│ Synchronous blocking call 'time.sleep()' inside 'async def get_users()'      │
│ blocks the asyncio event loop and starves concurrent requests.               │
│                                                                              │
│ Suggested fix:                                                               │
│   Use 'await asyncio.sleep()' or run in threadpool via anyio.to_thread.      │
└──────────────────────────────────────────────────────────────────────────────┘

┌────────────────── [WARN] FAP-003 Missing response model ─────────────────────┐
│ Route '@router.get("/items")' in src/api/items.py lacks a response_model.   │
│                                                                              │
│ Suggested fix:                                                               │
│   Add return type annotation: 'async def get_items() -> list[ItemResponse]:' │
└──────────────────────────────────────────────────────────────────────────────┘
```

#### SQLAlchemy Analyzer (`SQL-001` - `SQL-030`)
```bash
qv framework --name sqlalchemy
```

**Terminal Output:**
```text
qv (SQLAlchemy Doctor)
Project: my-api

1 Errors   0 Warnings   28 Checks Passed

┌────────────────── [ERROR] SQL-004 SQL Injection Risk ─────────────────────────┐
│ File 'src/db/repositories/user.py:28'                                        │
│ Raw SQL f-string interpolation detected: text(f"SELECT * FROM users WHERE id={uid}")│
│                                                                              │
│ Suggested fix:                                                               │
│   Use bound query parameters: text("SELECT * FROM users WHERE id = :uid")    │
│   session.execute(stmt, {"uid": uid})                                        │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

### 6. Subsystem-Focused Scans

Run targeted audits on specific components:

```bash
# Check dependencies only (conflicts, missing, unused, Python version compat, CVEs)
qv dependency

# Check environment drift only (Python interpreter, Docker base images, CI matrix)
qv environment

# Check AST & imports only (circular import loops, unresolvable modules, orphan files)
qv architecture
```

---

### 7. Rule Explanation & Catalog Lookup (`qv explain`)

Lookup rule definitions, remediation strategies, and documentation for any diagnostic code:

```bash
qv explain FAP-001
```

**Terminal Output:**
```text
┌────────────────── FAP-001 - Blocking call in async endpoint ─────────────────┐
│ Category: Framework                                                          │
│ Default Severity: ERROR                                                      │
│                                                                              │
│ Description:                                                                 │
│ Synchronous blocking operations (e.g. time.sleep, requests, subprocess) or    │
│ CPU-bound hashing called inside an async def FastAPI route handler block the │
│ asyncio event loop.                                                          │
│                                                                              │
│ Remediation Recommendation:                                                  │
│ Use non-blocking async alternatives (e.g. asyncio.sleep, httpx.AsyncClient)  │
│ or run blocking/CPU calls in worker threads via anyio.to_thread.run_sync.    │
│                                                                              │
│ Documentation:                                                               │
│ https://github.com/inzamol/qv/blob/main/docs/rules.md#fap-001                │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

### 8. Project Initialization (`qv init`)

Initialize or append default `[tool.qv]` settings to `pyproject.toml` without modifying other configuration tables:

```bash
qv init
```

---

### 9. Version & Info (`qv version`)

```bash
qv version
```

---

## Configuration

Configure `qv` directly in `pyproject.toml` to customize severities, ignore rules, or disable specific checks:

```toml
[tool.qv]
# Global scan settings
offline = false          # Set true to disable remote CVE/PyPI network queries
hide_warnings = false    # Set true to suppress warning-level diagnostics
errors_only = false      # Set true to report only blocking errors
min_severity = "warning" # Minimum threshold: "error", "warning", or "info"

# Method 1: Turn off specific rules or override severity ("off", "error", "warning", "info")
[tool.qv.rules]
DEP-002 = "off"          # Disable missing/transitive dependency check
IMP-003 = "off"          # Disable orphan module check
DEP-001 = "error"        # Treat dependency conflicts as blocking errors
ENV-002 = "info"         # Demote Docker runtime drift to informational notice

# Method 2: Ignore list for rules
[tool.qv.ignore]
rules = [
    "DEP-004",           # Ignore Python version compatibility mismatch
    "FAP-031",           # Ignore typing.Annotated styling rule
]

# Exclude directories and files from scanning
[tool.qv.paths]
exclude = [
    ".venv",
    "build",
    "dist",
    "legacy_scripts",
    "tests/fixtures",
]

# Set expected target Python runtime
[tool.qv.runtime]
python = "3.12"
```

*Learn more in the [Configuration Guide](docs/configuration.md).*

---

## CI/CD Integration

### Official GitHub Action

Integrate `qv` directly into `.github/workflows/ci.yml`:

```yaml
name: Health & Dependency Scan

on: [push, pull_request]

jobs:
  qv:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run qv Health Scan
        uses: inzamol/qv@v1
        with:
          strict: true
          html_report: report.html
          sarif_report: qv.sarif
          github_annotations: true
```

### GitHub Actions (Manual setup with SARIF code scanning)

```yaml
name: Health & Dependency Scan

on: [push, pull_request]

jobs:
  qv:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3

      # Run scan with PR annotations
      - name: Run qv
        run: uv run qv scan --ci --github-annotations

      # Generate SARIF report for GitHub Code Scanning
      - name: Generate SARIF report
        run: uv run qv scan --sarif -o qv.sarif
        if: always()

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: qv.sarif
        if: always()
```

### Pre-commit Hook Integration

Add `qv` to `.pre-commit-config.yaml` to detect dependency drift and circular imports prior to commits:

```yaml
repos:
  - repo: https://github.com/inzamol/qv
    rev: v0.1.0
    hooks:
      - id: qv-scan
        args: [--strict, --offline]
```

*See full details in [CI/CD & Pre-commit Integration](docs/ci_integration.md).*

---

## Design Principles

- **Diagnose first. Explain second. Fix safely.**
- **Deterministic and safe**: Auto-remediations offer exact diffs and non-destructive configuration updates.
- **Local-first and fast**: Full AST parsing, dependency graph resolution, and checks complete in under a second.
- **Package-manager agnostic**: Works with `uv`, Poetry, `pip`, PDM, and Pipenv.

---

## Documentation & Community

Full documentation is available at **[inzamol.github.io/qv](https://inzamol.github.io/qv/)**.

- [Getting Started Guide](https://inzamol.github.io/qv/getting_started/)
- [CLI Reference](https://inzamol.github.io/qv/cli_reference/)
- [Diagnostic Rules Catalog](https://inzamol.github.io/qv/rules/)
- [Configuration Guide](https://inzamol.github.io/qv/configuration/)
- [CI/CD & SARIF Integration](https://inzamol.github.io/qv/ci_integration/)
- [Contributing Guidelines](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)

---

## License

Distributed under the [MIT License](LICENSE).
