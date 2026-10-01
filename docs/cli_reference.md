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
