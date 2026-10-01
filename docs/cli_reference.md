# CLI Reference

`qv` provides commands for scanning projects, explaining findings, configuring rules, and inspecting specific subsystems.

---

## 1. Global Options

```bash
qv --help
qv --version
```

---

## 2. `qv init`

Generates or updates the `[tool.qv]` configuration block in your `pyproject.toml` without overwriting existing settings.

```bash
qv init [PATH]
```

Example:

```bash
# Initialize [tool.qv] in current directory
qv init

# Initialize in a specific project path
qv init ./services/backend
```

---

## 3. `qv scan`

Runs full diagnostic analysis on the specified directory.

```bash
qv scan [PATH] [OPTIONS]
```

### 3.1 Arguments

| Argument | Description | Default |
|---|---|---|
| `PATH` | Path to the project root directory | `.` (current directory) |

### 3.2 Options

| Option | Description |
|---|---|
| `--strict` | Promotes warnings to errors (fails CI if any warnings exist) |
| `--ci` | Runs non-interactively with strict mode enabled |
| `--json` | Emits scan results as structured JSON |
| `--sarif` | Emits scan results as standard SARIF v2.1.0 format |
| `--html <FILE>` | Generates an interactive, standalone HTML dashboard |
| `--github-annotations` | Emits GitHub Actions inline PR workflow annotations |
| `--offline` | Disables remote vulnerability/CVE queries (airgapped mode) |
| `--output`, `-o <FILE>` | Writes output directly to a file |

### 3.3 Exit Codes

| Exit Code | Meaning |
|---|---|
| `0` | Clean project — no blocking errors or warnings |
| `1` | Blocking findings detected |
| `2` | Invalid configuration or unknown rule ID |
| `3` | Analysis or runtime failure |

---

## 4. `qv inspect` (alias: `qv ui`)

Launches an interactive terminal dashboard (TUI) to navigate findings, expand evidence, view dependency trees, and apply fixes interactively with keyboard shortcuts.

```bash
qv inspect [PATH] [OPTIONS]
qv ui [PATH] [OPTIONS]
```

### 4.1 Controls

| Key | Action |
|---|---|
| `↑` / `k` | Navigate to previous finding |
| `↓` / `j` | Navigate to next finding |
| `Enter` / `Space` | Toggle details expansion |
| `f` | Apply remediation fix for selected finding |
| `t` | Switch between Diagnostics and Dependency Tree view |
| `q` / `Esc` | Exit interactive explorer |

---

## 5. `qv fix`

Safely and automatically fixes detectable diagnostic health issues (e.g., adding missing dependencies to `pyproject.toml`, removing unused dependencies, initializing packaging metadata).

```bash
qv fix [PATH] [OPTIONS]
```

### 5.1 Options

| Option | Description |
|---|---|
| `--dry-run` | Shows proposed fixes and diffs without modifying any files |
| `-y`, `--yes` | Automatically applies all safe fixes without interactive confirmation |
| `--rule <RULE_ID>` | Filters remediation to a specific rule ID (e.g. `DEP-002`) |
| `--sync` | Runs suggested package manager install/sync commands |

Example:

```bash
# Preview proposed fixes
qv fix --dry-run

# Apply all safe fixes automatically
qv fix -y
```

---

## 6. `qv tree` / `qv graph`

Visualizes direct vs transitive package dependencies and internal source module import architecture (with circular import cycles highlighted).

```bash
qv tree [PATH] [OPTIONS]
```

### 6.1 Options

| Option | Description |
|---|---|
| `-d`, `--dependencies` | Visualizes direct and transitive package dependencies |
| `-i`, `--imports` | Visualizes internal Python module imports and circular cycles |
| `-L`, `--depth <N>` | Maximum depth level for the tree (default: 5) |
| `--json` | Emits dependency and import statistics as JSON |

Example:

```bash
# View full project tree (dependencies and imports)
qv tree

# View only internal module import hierarchy and circular loops
qv tree --imports

# View dependency tree up to 2 levels deep
qv tree -d -L 2
```

---

## 7. `qv explain`

Displays detailed explanations, evidence requirements, and remediation instructions for a rule.

```bash
qv explain <RULE_ID>
```

Example:

```bash
qv explain DEP-002
```

---

## 8. Targeted Subsystem Commands

Run focused checks on specific areas without executing the full scan:

### 8.1 `qv dependency`
Scans for dependency conflicts, missing imports, unused packages, and version mismatches.

```bash
qv dependency [PATH]
```

### 8.2 `qv environment`
Checks for Python runtime drift between local environment, Dockerfiles, and CI matrices.

```bash
qv environment [PATH]
```

### 8.3 `qv architecture`
Scans source code for circular imports and unresolved internal modules.

```bash
qv architecture [PATH]
```
