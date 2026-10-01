# Getting Started with qv

`qv` is a package-manager-agnostic diagnostic platform for Python projects. It analyzes your project configuration, environment, source code imports, and dependency tree to pinpoint health issues and suggest safe, actionable fixes.

---

## 1. Installation

Install `python-qv` into your virtual environment or globally via pip or uv (provides the `qv` CLI):

=== "Using uv"
    ```bash
    uv add python-qv --dev
    ```

=== "Using pip"
    ```bash
    pip install python-qv
    ```

=== "Run directly without installing"
    ```bash
    uvx python-qv scan
    ```

---

## 2. Initialize Project Configuration (`qv init`)

Before running extensive scans or configuring custom rule thresholds, initialize standard settings in your `pyproject.toml`:

```bash
qv init
```

This creates a default `[tool.qv]` configuration block without overwriting any of your existing project settings:

```toml
[tool.qv]
[tool.qv.rules]
DEP-001 = "error"
DEP-002 = "error"
DEP-003 = "warning"
IMP-001 = "error"

[tool.qv.paths]
exclude = [".venv", "build", "dist"]
```

---

## 3. Run a Health Scan (`qv scan`)

Run `qv scan` in your project root to perform a comprehensive diagnostic audit:

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

## 4. Explore & Remediate Findings

### 4.1 Interactive TUI Dashboard (`qv inspect`)
Launch the interactive terminal dashboard to navigate findings, inspect evidence, view dependency trees, and apply fixes with keyboard shortcuts:

```bash
qv inspect
```

### 4.2 Safe Automated Remediation (`qv fix`)
Safely apply deterministic fixes (such as adding undeclared dependencies or pruning unused packages):

```bash
# Preview proposed diffs without touching disk
qv fix --dry-run

# Apply all safe fixes automatically
qv fix -y
```

---

## 5. Understand Diagnostic Rules (`qv explain`)

If a specific diagnostic rule is flagged, you can get in-depth guidance, common causes, and remediation advice:

```bash
qv explain DEP-001
```

---

## 6. Next Steps

- Explore the [CLI Commands Reference](cli_reference.md) for all commands, arguments, and flags.
- Learn about the [Rules Catalog](rules.md) to understand detected issues.
- Read the [Configuration Guide](configuration.md) to customize rules for your project.
- Integrate into [CI/CD](ci_integration.md) with SARIF and strict modes.
