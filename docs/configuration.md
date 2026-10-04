# Configuration Guide

`qv` is configured directly in your project's `pyproject.toml` file under the `[tool.qv]` table.

---

## 1. Example `pyproject.toml`

```toml
[tool.qv]

# Override individual rule severities (error, warning, info, off)
[tool.qv.rules]
DEP-001 = "error"
DEP-002 = "error"
DEP-003 = "warning"
DEP-004 = "info"
IMP-001 = "error"

# Ignore specific rules entirely
[tool.qv.ignore]
rules = ["DEP-005"]

# Customize path exclusions
[tool.qv.paths]
exclude = [
    ".venv",
    "build",
    "dist",
    "node_modules",
    "legacy_scripts",
]

# Set expected Python runtime target
[tool.qv.runtime]
python = "3.12"
```

---

## 2. Severity Overrides

You can adjust how strictly any rule is treated:

| Value | Behavior |
|---|---|
| `"error"` | Causes scan to fail and exit with non-zero code |
| `"warning"` | Displays warning; fails in `--strict` or `--ci` mode |
| `"info"` | Informational finding; does not affect health score as severely |
| `"off"` | Disables the check completely |

---

## 3. Ignore Rules and Dependencies

### 3.1 Ignore Rules Globally
To suppress specific diagnostic rule IDs that are not applicable to your workflow, list them under `[tool.qv.ignore]`:

```toml
[tool.qv.ignore]
rules = ["DEP-003", "ENV-002"]
```

### 3.2 Ignore Specific Packages (DEP-003)
To ignore specific packages from unused dependency checks (`DEP-003`) (e.g. dynamic plugins, CLI drivers, or runtime dependencies), configure `[tool.qv.dependencies]`:

```toml
[tool.qv.dependencies]
ignore = ["amqp", "psycopg2-binary", "gunicorn"]
```

Package names are automatically normalized, case-insensitive, and support version specifiers (e.g. `amqp>=1.0` or `amqp[extra]`). Ignoring a package only suppresses `DEP-003` for that package while keeping all other rules active.

---

## 4. Precedence Order

When resolving configuration, `qv` follows this precedence:

1. **CLI Flags** (`--strict`, `--json`, `--sarif`) — highest precedence.
2. **Project `pyproject.toml`** (`[tool.qv]`).
3. **Default Built-in Rules** — lowest precedence.
