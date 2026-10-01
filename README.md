# 🔍 qv

<div align="center">

**Diagnose why your Python project is unhealthy — understand the root cause and get safe, actionable fixes.**

[![PyPI Version](https://img.shields.io/badge/pypi-v0.1.0-blue.svg)](https://pypi.org/project/python-qv/)
[![Python Versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://pypi.org/project/python-qv/)
[![CI Status](https://github.com/inzamol/qv/actions/workflows/ci.yml/badge.svg)](https://github.com/inzamol/qv/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

[Installation](#-installation) • [Quick Start](#-quick-start) • [Interactive TUI](#-interactive-tui-explorer) • [Features](#-what-it-detects) • [CLI Commands](#-cli-commands) • [CI/CD Integration](#-cicd-integration) • [Documentation](docs/getting_started.md)

</div>

---

## 💡 Why qv?

Python projects rarely fail because of Python syntax. They fail because of **ecosystem friction**:
- Incompatible transitive dependency constraints that break your resolver.
- Missing dependencies you forgot to add to `pyproject.toml`.
- Docker containers running Python 3.10 while your team develops on 3.12.
- Silent circular imports that only crash at runtime when certain modules load.

Instead of parsing hundreds of lines of cryptic resolver logs, **`qv`** scans your project in milliseconds, pinpoints the root cause, shows the exact evidence, and gives you a copy-paste command to fix it.

```text
🔍 qv
Project: payment-service
Python:  3.12.7
Package Manager: uv

🔴 1 Errors   🟡 1 Warnings   🟢 48 Checks Passed

┌────────────────── 🔴 DEP-001 Dependency constraint conflict ─────────────────┐
│ celery 5.4.0 requires kombu<5.4.0,>=5.3.0, but installed is kombu 5.5.2.     │
│                                                                              │
│ Evidence:                                                                    │
│   • celery declared requirement: kombu<5.4.0,>=5.3.0                         │
│   • Installed kombu version: 5.5.2 in active environment                     │
│                                                                              │
│ Suggested fix:                                                               │
│   Upgrade celery or pin kombu to <5.4.0,>=5.3.0.                             │
│   $ uv add 'kombu<5.4.0,>=5.3.0'                                             │
└──────────────────────────────────────────────────────────────────────────────┘

Health Score: 85/100
```

---

## 📦 Installation

Install `python-qv` into your virtual environment (provides the `qv` CLI):

```bash
# Using pip
pip install python-qv

# Using uv
uv add python-qv --dev

# Run directly without installing (via uvx or pipx)
uvx python-qv scan
# or
pipx run python-qv scan
```

---

## 🚀 Quick Start

### 1. Run a Health Scan

Run `qv scan` inside any Python repository:

```bash
qv scan
```

### 2. Launch the Interactive TUI Explorer

Explore findings interactively with keyboard navigation, live details, dependency tree view, and 1-key remediation:

```bash
qv inspect
# or
qv ui
```

### 3. Generate a Self-Contained HTML Report

Export a standalone, interactive HTML report with score meters, search filters, and dark/light modes:

```bash
qv scan --html report.html
```

### 4. Understand Any Flagged Issue

Need more context on why a rule triggered? Run `explain`:

```bash
qv explain DEP-001
```

### 5. Add Project Configuration

To add default configuration to your `pyproject.toml`:

```bash
qv init
```

---

## 🖥️ Interactive TUI Explorer

Run `qv inspect` (or `qv ui`) for a full terminal dashboard:

```text
┌────────────────────────────────────────────── qv Explorer ──────────────────────────────────────────────┐
│  🔍 qv Explorer  •  Project: all-in-one-demo  •  Health Score: 40/100                                   │
│  Python: 3.12.7  |  Package Manager: PIP  |  Errors: 3  |  Warnings: 3  |  Checks Passed: 49            │
├────────────────────────── Findings (1/6) ──────────────────────────┬──────────────── Details: DEP-001 ──┤
│     Sev   Rule     Title                                           │ [ERROR] DEP-001: Constraint conflict│
│  👉 ERR   DEP-001  Dependency constraint conflict                  │ celery requires kombu<5.4.0,>=5.3.0│
│     ERR   DEP-002  Missing dependency: httpx                       │ Location: pyproject.toml           │
│     ERR   DEP-002  Missing dependency: pydantic                    │                                    │
│     WARN  DEP-003  Unused declared dependency: requests            │ Remediation:                       │
│     WARN  DEP-003  Unused declared dependency: pyyaml              │   👉 Pin kombu to <5.4.0,>=5.3.0   │
│     ... 1 more below ...                                           │      $ pip install 'kombu<5.4.0'   │
├────────────────────────────────────────────────────────────────────┴────────────────────────────────────┤
│ [↑/k, ↓/j] Navigate  •  [Enter] Expand  •  [f] Apply Fix  •  [t] Tree View  •  [q] Quit                 │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

- **`↑ / k` & `↓ / j`**: Scroll smoothly through findings.
- **`f`**: Apply automated remediation fix for the active finding.
- **`t`**: Toggle between Findings view and live Dependency Tree.
- **`Enter`**: Expand details panel.

---

## 🔍 What It Detects

| Category | Rule ID | Description | Default Severity |
|---|---|---|---|
| **Dependencies** | `DEP-001` | Incompatible package version constraints across dependency tree | `ERROR` |
| | `DEP-002` | Third-party packages imported in code but missing from `pyproject.toml` | `ERROR` |
| | `DEP-003` | Declared dependencies that are never imported anywhere in project | `WARNING` |
| | `DEP-004` | Package requires a Python version incompatible with target runtime | `WARNING` |
| | `DEP-005` | Installed virtualenv version does not match declared manifest pin | `WARNING` |
| **Environment** | `ENV-001` | Active interpreter version differs from project `requires-python` | `WARNING` |
| | `ENV-002` | Dockerfile base image Python version differs from project runtime | `WARNING` |
| | `ENV-003` | CI matrix does not cover the Python versions declared in project | `WARNING` |
| **Architecture** | `IMP-001` | Circular import cycles across local modules | `ERROR` |
| | `IMP-002` | Unresolved relative or internal module imports | `ERROR` |
| **Packaging** | `PKG-001` | Missing PEP 621 metadata (name, version, etc.) | `WARNING` |
| | `PKG-002` | Invalid syntax or malformed keys in `pyproject.toml` | `ERROR` |
| **FastAPI Doctor** | `FAP-001`–`FAP-038` | Async blocking calls, CPU starvation in endpoints, insecure CORS, missing timeouts, lifecycle anti-patterns, Pydantic v2 migrations | `ERROR` / `WARNING` |
| **SQL & Database** | `SQL-001`–`SQL-030` | N+1 queries in loops, session leaks, SQL injection, sync DB in async loop, missing eager loading, pool starvation, 2.0 syntax | `ERROR` / `WARNING` |

👉 *See all 80+ rules and remediation steps in the [Rules Catalog](docs/rules.md).*

---

## 🛠️ CLI Commands & Examples

### 1. `qv scan` — Full Project Diagnostics
Run a comprehensive health audit scanning dependencies, runtime environment, imports, and packaging.

```bash
# Scan current repository
qv scan

# Scan a specific directory or microservice
qv scan ./services/payment

# Strict mode: fail CI if any warnings exist (exit code 1)
qv scan --strict

# Generate a self-contained interactive HTML dashboard
qv scan --html report.html

# Output SARIF format for GitHub Code Scanning / IDE integration
qv scan --sarif -o results.sarif

# Output machine-readable JSON
qv scan --json -o results.json

# Offline / Airgapped mode (skips remote package index checks)
qv scan --offline

# Emit GitHub Actions workflow command annotations (::error:: and ::warning::)
qv scan --ci --github-annotations
```

---

### 2. `qv inspect` (or `qv ui`) — Interactive Terminal Dashboard
Explore diagnostic findings, view evidence, inspect circular import trees, and apply fixes interactively with keyboard shortcuts.

```bash
# Launch interactive dashboard for current repository
qv inspect

# Inspect another project
qv inspect ../another-service

# Airgapped / offline TUI
qv inspect --offline
```

*Controls: `↑`/`k` and `↓`/`j` to navigate, `Enter` to expand details, `f` to apply fix, `t` to toggle dependency tree, `q` to quit.*

---

### 3. `qv fix` — Safe Automated Remediation
Automatically generate and apply deterministic fixes to your project manifest and configuration.

```bash
# Interactive wizard (prompts before applying each fix)
qv fix

# Preview proposed file diffs and commands without modifying disk
qv fix --dry-run

# Automatically apply all safe fixes without prompting
qv fix -y

# Fix only a specific rule (e.g. missing dependencies)
qv fix --rule DEP-002 -y

# Apply fixes and execute package manager sync commands
qv fix --sync -y
```

---

### 4. `qv tree` (or `qv graph`) — Dependency & Architecture Visualizer
Render color-coded visual trees of package dependencies and source module import graphs.

```bash
# Render complete overview (dependency tree + import architecture)
qv tree

# Visualize direct & transitive dependencies up to depth 2
qv tree --dependencies --depth 2
# or shorthand:
qv tree -d -L 2

# Visualize internal module import graph and circular import cycles
qv tree --imports
# or shorthand:
qv tree -i

# Export tree hierarchy and cycle statistics as JSON
qv tree --json > tree.json
```

---

### 5. `qv explain` — Rule Catalog & Fix Advice
Look up detailed explanations, common causes, evidence criteria, and remediation advice for any diagnostic rule.

```bash
# Explain dependency constraint conflicts
qv explain DEP-001

# Explain missing undeclared imports
qv explain DEP-002

# Explain circular import loops
qv explain IMP-001

# Explain Python/Docker environment drift
qv explain ENV-002
```

---

### 6. Subsystem-Focused Scans
Run focused audits on specific components when troubleshooting or in modular CI pipelines:

```bash
# Check dependencies only (conflicts, missing, unused, incompatible Python)
qv dependency

# Check environment drift only (interpreter version, Dockerfile, CI matrix)
qv environment

# Check AST & imports only (circular import loops, unresolvable modules)
qv architecture

# Check framework-specific issues (FastAPI, SQLAlchemy, SQLModel)
qv framework
qv framework --name fastapi
qv framework --name sqlalchemy
```

---

### 7. `qv init` — Project Configuration Setup
Initialize or update `pyproject.toml` with default `[tool.qv]` configuration rules and path exclusions without overwriting existing settings.

```bash
# Initialize [tool.qv] in pyproject.toml
qv init
```

---

### 8. `qv version` — Version Information
```bash
qv version
# or
qv --version
```

👉 *See full option matrices in the [CLI Reference](docs/cli_reference.md).*

---

## ⚙️ Configuration

Configure `qv` in your `pyproject.toml`:

```toml
[tool.qv]

# Override severity for any rule (error, warning, info, off)
[tool.qv.rules]
DEP-001 = "error"
DEP-003 = "warning"
ENV-002 = "info"

# Ignore specific rules
[tool.qv.ignore]
rules = ["DEP-004"]

# Exclude directories from scanning
[tool.qv.paths]
exclude = [
    ".venv",
    "build",
    "dist",
    "legacy_scripts",
]

# Set expected target Python version
[tool.qv.runtime]
python = "3.12"
```

👉 *Learn more in the [Configuration Guide](docs/configuration.md).*

---

## 🤖 CI/CD Integration

### Official GitHub Action

You can use the official `qv` GitHub Action directly in `.github/workflows/ci.yml`:

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

Add `qv` directly to your `.pre-commit-config.yaml` to catch dependency drift and circular imports before committing:

```yaml
repos:
  - repo: https://github.com/inzamol/qv
    rev: v0.1.0
    hooks:
      # Diagnose health before committing
      - id: qv-scan
        args: [--strict, --offline]

      # Optional: Auto-remediate safe issues on commit
      # - id: qv-fix
```

👉 *See full details in [CI/CD & Pre-commit Integration](docs/ci_integration.md).*

---

## 🎯 Design Principles

- **Diagnose first. Explain second. Fix safely.**
- **No destructive auto-mutations**: Remediations provide the exact commands/diffs for you to review and apply.
- **Local-first & Blazing fast**: Zero network calls required; scans complete in under a second.
- **Package-manager agnostic**: Works out of the box with `uv`, Poetry, `pip`, PDM, and Pipenv.

---

## 📚 Complete Documentation

- 🚀 [Getting Started Guide](docs/getting_started.md)
- 📖 [CLI Reference](docs/cli_reference.md)
- 📋 [Diagnostic Rules Catalog](docs/rules.md)
- ⚙️ [Configuration Guide](docs/configuration.md)
- 🤖 [CI/CD & SARIF Integration](docs/ci_integration.md)
- 🤝 [Contributing Guidelines](docs/contributing.md)

---

## 📄 License

Distributed under the [MIT License](LICENSE).
