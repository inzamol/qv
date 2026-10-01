# 🔍 qv

<div align="center">

**Diagnose why your Python project is unhealthy — understand the root cause and get safe, actionable fixes.**

[![PyPI Version](https://img.shields.io/pypi/v/python-qv.svg?color=blue)](https://pypi.org/project/python-qv/)
[![Python Versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://pypi.org/project/python-qv/)
[![CI Status](https://github.com/inzamol/qv/actions/workflows/ci.yml/badge.svg)](https://github.com/inzamol/qv/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

[Installation](#-installation) • [Quick Start](#-quick-start) • [Features](#-what-it-detects) • [CLI Commands](#-cli-commands) • [CI/CD Integration](#-cicd-integration) • [Documentation](docs/getting_started.md)

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

### 2. Understand Any Flagged Issue

Need more context on why a rule triggered? Run `explain`:

```bash
qv explain DEP-001
```

### 3. Add Project Configuration

To add default configuration to your `pyproject.toml`:

```bash
qv init
```

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

👉 *See full explanations and remediation steps in the [Rules Catalog](docs/rules.md).*

---

## 🛠️ CLI Commands

```bash
# Full project diagnostic scan
qv scan

# Scan another folder
qv scan ./services/billing

# Strict mode: fail CI on warnings as well as errors
qv scan --strict

# Output machine-readable formats
qv scan --json
qv scan --sarif -o results.sarif

# Run focused subsystem scans
qv dependency       # Check package constraints & imports
qv environment      # Check Python, Docker & CI version drift
qv architecture     # Check for circular imports & dead paths

# Explain a rule
qv explain DEP-002

# Check installed version
qv version
```

👉 *See detailed options in the [CLI Reference](docs/cli_reference.md).*

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

### GitHub Actions (with SARIF code scanning)

Add this step to your GitHub Actions workflow (`.github/workflows/ci.yml`):

```yaml
name: Health & Dependency Scan

on: [push, pull_request]

jobs:
  qv:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3

      # Run scan in CI mode
      - name: Run qv
        run: uv run qv scan --ci

      # Optional: Generate SARIF report for GitHub Code Scanning
      - name: Generate SARIF report
        run: uv run qv scan --sarif -o qv.sarif
        if: always()

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: qv.sarif
        if: always()
```

👉 *See full details in [CI/CD Integration](docs/ci_integration.md).*

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
