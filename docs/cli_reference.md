# CLI Reference

`qv` provides commands for scanning projects, explaining findings, configuring rules, and inspecting specific subsystems.

---

## Global Options

```bash
qv --help
qv --version
```

---

## `qv scan`

Runs full diagnostic analysis on the specified directory.

```bash
qv scan [PATH] [OPTIONS]
```

### Arguments

| Argument | Description | Default |
|---|---|---|
| `PATH` | Path to the project root directory | `.` (current directory) |

### Options

| Option | Description |
|---|---|
| `--strict` | Promotes warnings to errors (fails CI if any warnings exist) |
| `--ci` | Runs non-interactively with strict mode enabled |
| `--json` | Emits scan results as structured JSON |
| `--sarif` | Emits scan results as standard SARIF v2.1.0 format |
| `--output`, `-o <FILE>` | Writes output directly to a file |

### Exit Codes

| Exit Code | Meaning |
|---|---|
| `0` | Clean project — no blocking errors or warnings |
| `1` | Blocking findings detected |
| `2` | Invalid configuration or unknown rule ID |
| `3` | Analysis or runtime failure |

---

## `qv fix`

Safely and automatically fixes detectable diagnostic health issues (e.g., adding missing dependencies to `pyproject.toml`, removing unused dependencies, initializing packaging metadata).

```bash
qv fix [PATH] [OPTIONS]
```

### Options

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

## `qv tree` / `qv graph`

Visualizes direct vs transitive package dependencies and internal source module import architecture (with circular import cycles highlighted).

```bash
qv tree [PATH] [OPTIONS]
```

### Options

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

## `qv explain`

Displays detailed explanations, evidence requirements, and remediation instructions for a rule.

```bash
qv explain <RULE_ID>
```

Example:

```bash
qv explain DEP-002
```

---

## `qv init`

Generates or updates the `[tool.qv]` configuration block in your `pyproject.toml`.

```bash
qv init [PATH]
```

---

## Targeted Subsystem Commands

Run focused checks on specific areas without executing the full scan:

### `qv dependency`
Scans for dependency conflicts, missing imports, unused packages, and version mismatches.

```bash
qv dependency [PATH]
```

### `qv environment`
Checks for Python runtime drift between local environment, Dockerfiles, and CI matrices.

```bash
qv environment [PATH]
```

### `qv architecture`
Scans source code for circular imports and unresolved internal modules.

```bash
qv architecture [PATH]
```
