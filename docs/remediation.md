# 🛠️ Safe Automated Remediation

`qv` follows a strict design principle: **Diagnose first. Explain second. Fix safely.**

Unlike aggressive tools that rewrite code unpredictably, `qv fix` computes deterministic, reversible remediation plans. You can preview proposed diffs in advance with `--dry-run`, apply fixes interactively, or automate safe repairs in CI scripts.

---

## 🚀 Basic Usage

```bash
# Interactive wizard (prompts before applying each fix)
qv fix

# Preview proposed file diffs without touching disk
qv fix --dry-run

# Automatically apply all safe fixes without prompting
qv fix -y

# Fix only a specific rule (e.g. missing dependencies)
qv fix --rule DEP-002 -y

# Apply fixes and execute package manager sync commands
qv fix --sync -y
```

---

## 🔒 Safety Guarantees & Remediation Levels

`qv` classifies fixes into three safety categories:

| Fix Category | Example | Behavior |
|---|---|---|
| **Safe (Deterministic)** | Adding missing dependencies to `pyproject.toml` (`DEP-002`)<br>Removing unused declared dependencies (`DEP-003`)<br>Adding default `[tool.qv]` settings (`PKG-001`) | Applied automatically with `-y` or after confirmation. |
| **Command-Assisted** | Running `uv add` or `pip install` (`DEP-001`, `DEP-005`) | Proposed as shell commands. Only executed if `--sync` is explicitly passed. |
| **Manual / Complex** | Refactoring circular import cycles (`IMP-001`) | Provides architectural refactoring hints and code snippets for human review; no blind mutations. |

---

## 📋 Remediation Plan Inspection (`--dry-run`)

Running `qv fix --dry-run` displays a table of planned actions and exact file diffs:

```text
Found 2 actionable fix(es) (2 safe):

┌────────┬────────────────┬─────────────────────────────────────────────────┬──────────┐
│ Rule   │ Target         │ Description                                     │ Type     │
├────────┼────────────────┼─────────────────────────────────────────────────┼──────────┤
│ DEP-002│ pyproject.toml │ Add 'httpx' to project dependencies             │ modify   │
│ DEP-003│ pyproject.toml │ Remove unused requirement 'requests>=2.31.0'    │ modify   │
└────────┴────────────────┴─────────────────────────────────────────────────┴──────────┘

Dry-run mode enabled. No changes written to disk.
```

---

## 🔄 Package Manager Auto-Sync (`--sync`)

When dependencies are modified, running `qv fix --sync` automatically calls the detected package manager (`uv sync`, `poetry install`, `pip install`) to keep your active virtual environment in lockstep:

```bash
qv fix --sync -y
```
