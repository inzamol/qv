# 🖥️ Interactive Terminal Explorer (TUI)

`qv` provides a full-featured, interactive terminal dashboard for exploring diagnostic findings, inspecting evidence, switching between findings and live dependency trees, and applying remediation fixes with a single keystroke.

---

## 🚀 Launching the TUI

Run `qv inspect` (or its alias `qv ui`) from your project root:

```bash
# Inspect current project
qv inspect

# Inspect another directory
qv inspect ./services/payment

# Run in airgapped / offline mode
qv inspect --offline
```

---

## 🎮 Interface & Layout

The dashboard splits into two primary panes alongside an informative header and controls footer:

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

### 1. Header Pane
Displays real-time project metrics:
- **Project Name & Health Score**: Color-coded score gauge (Green $\ge 80$, Yellow $\ge 50$, Red $< 50$).
- **Environment Metadata**: Active Python interpreter, detected package manager (`uv`, `poetry`, `pip`, `pdm`, `pipenv`), count of Errors, Warnings, and Checks Passed.

### 2. Findings List Pane (Left)
- Shows all active diagnostics sorted by severity.
- Smooth scrolling with visible indicators (`▲ ... more above ...` / `▼ ... more below ...`).
- Selected item highlighted with active indicator (`👉`).

### 3. Details Pane (Right)
- **Title & Severity**: Color-coded severity badge and rule ID.
- **Location**: Exact file and line number where the issue originated.
- **Root Cause & Message**: Contextual explanation of what went wrong.
- **Evidence**: Verified facts and file references gathered during discovery.
- **Remediation**: Copy-pasteable command or code snippet.
- **Documentation**: Direct link to the rule documentation.

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Description |
|---|---|
| `↑` / `k` | Move selection to the previous finding |
| `↓` / `j` | Move selection to the next finding |
| `Enter` / `Space` | Toggle finding details expansion |
| `f` | **Apply Automated Fix** directly to project files |
| `t` | **Toggle Dependency Tree View** |
| `q` / `Esc` | Exit the interactive explorer |

---

## 🛠️ One-Key Remediation (`f`)

When a finding has a deterministic automated fix available (e.g. adding a missing dependency or removing an unused package):
1. Navigate to the finding using `↑` or `↓`.
2. Press **`f`**.
3. `qv` will safely apply the change to your `pyproject.toml` or source code.
4. The footer will display a confirmation banner:
   ```text
   ✔ Successfully applied fix for DEP-002!
   ```
5. If no automated fix exists for that specific rule, the footer displays:
   ```text
   No automated fix available for rule IMP-001
   ```
