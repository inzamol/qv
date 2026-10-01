# Configuration Guide

`qv` is configured directly in your project's `pyproject.toml` file under the `[tool.qv]` table.

---

## Example `pyproject.toml`

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

## Severity Overrides

You can adjust how strictly any rule is treated:

| Value | Behavior |
|---|---|
| `"error"` | Causes scan to fail and exit with non-zero code |
| `"warning"` | Displays warning; fails in `--strict` or `--ci` mode |
| `"info"` | Informational finding; does not affect health score as severely |
| `"off"` | Disables the check completely |

---

## Ignore Rules

To suppress rules that are not applicable to your workflow, list them under `[tool.qv.ignore]`:

```toml
[tool.qv.ignore]
rules = ["DEP-003", "ENV-002"]
```

---

## Precedence Order

When resolving configuration, `qv` follows this precedence:

1. **CLI Flags** (`--strict`, `--json`, `--sarif`) — highest precedence.
2. **Project `pyproject.toml`** (`[tool.qv]`).
3. **Default Built-in Rules** — lowest precedence.
