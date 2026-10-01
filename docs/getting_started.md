# Getting Started with qv

`qv` is a package-manager-agnostic diagnostic platform for Python projects. It analyzes your project configuration, environment, source code imports, and dependency tree to pinpoint health issues and suggest safe, actionable fixes.

---

## Installation

Install `python-qv` into your virtual environment or globally via pip or uv (provides the `qv` CLI):

```bash
# Using pip
pip install python-qv

# Using uv
uv add python-qv --dev

# Or run directly without installation using uvx
uvx python-qv scan
```

---

## Quick Start

### 1. Run a Health Scan

Run `qv scan` in your project root:

```bash
qv scan
```

Example output:

```text
🔍 qv
Project: my-api
Python:  3.12.7
Package Manager: uv

🔴 1 Errors   🟡 1 Warnings   🟢 48 Checks Passed

┌────────────────── 🔴 DEP-001 Dependency constraint conflict ─────────────────┐
│ celery 5.4.0 requires kombu<5.4.0,>=5.3.0, but installed is kombu 5.5.2.     │
│                                                                              │
│ Evidence:                                                                    │
│   • celery declared requirement: kombu<5.4.0,>=5.3.0                         │
│   • Installed kombu version: 5.5.2                                           │
│                                                                              │
│ Suggested fix:                                                               │
│   Upgrade celery or pin kombu to <5.4.0,>=5.3.0.                             │
│   $ uv add 'kombu<5.4.0,>=5.3.0'                                             │
└──────────────────────────────────────────────────────────────────────────────┘

Health Score: 85/100
```

---

### 2. Understand Diagnostic Rules

If a rule is flagged, you can get in-depth guidance using `explain`:

```bash
qv explain DEP-001
```

---

### 3. Initialize Configuration

To configure rule severities and paths in your `pyproject.toml`:

```bash
qv init
```

This adds a `[tool.qv]` configuration block without overwriting existing settings.

---

## Next Steps

- Explore the [CLI Reference](cli_reference.md) for all available commands and flags.
- Learn about the [Rules Catalog](rules.md) to understand detected issues.
- Read [Configuration Guide](configuration.md) to customize rules for your project.
- Integrate into [CI/CD](ci_integration.md) with SARIF and strict modes.
