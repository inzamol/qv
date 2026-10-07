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

## 3. `qv doctor`

One command that provides a complete, high-level project health scorecard across all 6 core pillars (Dependencies, Security, Packaging, Architecture, Environment, Framework) with progress bars and top priority problems.

```bash
qv doctor [PATH] [OPTIONS]
```

Example:

```text
QV Project Health
────────────────────────────────────────

Dependencies      92/100   █████████░
Security           84/100   ████████░░
Packaging          96/100   ██████████
Architecture       78/100   ████████░░
Environment        91/100   █████████░
Framework          88/100   █████████░

Health Score: 87/100

3 high-priority issues
7 warnings
42 checks passed

Top problems:
  1. SQL-014  N+1 query detected
  2. DEP-002  Missing dependency: httpx
  3. ENV-003  Python version mismatch

Run `qv explain SQL-014` for details.
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
| `--baseline <FILE>` | Filter findings against an established baseline file (ignores pre-existing issues) |
| `--json` | Emits doctor health scorecard as structured JSON |
| `--sarif` | Emits scan results as standard SARIF v2.1.0 format |
| `--top <N>` | Number of top problems to highlight (default: 3) |
| `--format`, `-f <FORMAT>` | Specify output format (`terminal`, `json`, `sarif`, `html`, `text`) |
| `--html <FILE>` | Generates an interactive, standalone HTML dashboard |
| `--github-annotations` | Emits GitHub Actions inline PR workflow annotations |
| `--offline` | Disables remote vulnerability/CVE queries (airgapped mode) |
| `--output`, `-o <FILE>` | Writes output directly to a file |

---

## 4. `qv scan`

Runs full diagnostic analysis on the specified directory.

```bash
qv scan [PATH] [OPTIONS]
```

### 4.1 Arguments

| Argument | Description | Default |
|---|---|---|
| `PATH` | Path to the project root directory | `.` (current directory) |

### 4.2 Options

| Option | Description |
|---|---|
| `--strict` | Promotes warnings to errors (fails CI if any warnings exist) |
| `--ci` | Runs non-interactively with strict mode enabled |
| `--baseline <FILE>` | Filter findings against an established baseline file (ignores pre-existing issues) |
| `--json` | Emits scan results as structured JSON |
| `--sarif` | Emits scan results as standard SARIF v2.1.0 format |
| `--format`, `-f <FORMAT>` | Specify output format (`json`, `sarif`, `html`, `terminal`, `text`) |
| `--html <FILE>` | Generates an interactive, standalone HTML dashboard |
| `--github-annotations` | Emits GitHub Actions inline PR workflow annotations |
| `--offline` | Disables remote vulnerability/CVE queries (airgapped mode) |
| `--hide-warnings`, `-W` | Suppresses warning diagnostics from terminal output |
| `--errors-only`, `-E` | Only shows blocking error diagnostics (hides warnings and info) |
| `--severity <LEVEL>` | Filter findings by minimum severity (`error`, `warning`, `info`) |
| `--output`, `-o <FILE>` | Writes output directly to a file |

### 4.3 Exit Codes

| Exit Code | Meaning |
|---|---|
| `0` | Clean project — no blocking errors or warnings |
| `1` | Blocking findings detected |
| `2` | Invalid configuration or unknown rule ID |
| `3` | Analysis or runtime failure |

---

## 5. `qv inspect` (alias: `qv ui`)

Launches an interactive terminal dashboard (TUI) to navigate findings, expand evidence, view dependency trees, and apply fixes interactively with keyboard shortcuts.

```bash
qv inspect [PATH] [OPTIONS]
qv ui [PATH] [OPTIONS]
```

### 5.1 Controls

| Key | Action |
|---|---|
| `↑` / `k` | Navigate to previous finding |
| `↓` / `j` | Navigate to next finding |
| `Enter` / `Space` | Toggle details expansion |
| `f` | Apply remediation fix for selected finding |
| `t` | Switch between Diagnostics and Dependency Tree view |
| `q` / `Esc` | Exit interactive explorer |

---

## 6. `qv fix`

Safely and deterministically fixes detectable diagnostic health issues (e.g., adding missing dependencies to `pyproject.toml`, creating default configuration schemas, and initializing packaging metadata). Note that unused dependency removals (`DEP-003`) are marked for manual review to prevent accidental deletion of runtime plugins.

```bash
qv fix [PATH] [OPTIONS]
```

### 6.1 Options

| Option | Description |
|---|---|
| `--dry-run` | Shows proposed fixes and diffs without modifying any files |
| `--diff` | Shows unified color diff of proposed file modifications before applying |
| `-i`, `--interactive` | Prompts for interactive confirmation before applying each fix |
| `-y`, `--yes` | Automatically applies all safe fixes without interactive confirmation |
| `--rule <RULE_ID>` | Filters remediation to a specific rule ID (e.g. `DEP-002`) |
| `--sync` | Runs suggested package manager install/sync commands |

Example:

```bash
# Preview proposed unified diffs
qv fix --diff

# Apply fixes with interactive confirmation per finding
qv fix -i

# Preview proposed fixes in dry-run mode
qv fix --dry-run

# Apply all safe fixes automatically
qv fix -y
```

---

## 7. `qv baseline`

Manages baseline snapshots (`.qv-baseline.json`) of known diagnostic issues to enable differential scanning in legacy codebases without failing CI on pre-existing debt.

```bash
qv baseline record [PATH] [OPTIONS]
qv baseline verify [PATH] [OPTIONS]
```

### 7.1 Subcommands

#### `qv baseline record`
Records current diagnostic findings into a baseline JSON file:
```bash
# Record baseline to default .qv-baseline.json
qv baseline record

# Record baseline to a custom file
qv baseline record -o custom-baseline.json
```

#### `qv baseline verify`
Verifies that no new diagnostic issues have been introduced beyond the baseline:
```bash
# Verify against default .qv-baseline.json
qv baseline verify

# Verify in strict mode against a specific baseline file
qv baseline verify -b custom-baseline.json --strict
```

---

## 8. `qv tree` / `qv graph`

Visualizes direct vs transitive package dependencies and internal source module import architecture (with circular import cycles highlighted).

```bash
qv tree [PATH] [OPTIONS]
```

### 8.1 Options

| Option | Description |
|---|---|
| `-d`, `--dependencies` | Visualizes direct and transitive package dependencies |
| `-i`, `--imports` | Visualizes internal Python module imports and circular cycles |
| `-r`, `--risk` | Annotates dependency tree with functional classifications, AST imports, and risk scores |
| `-L`, `--depth <N>` | Maximum depth level for the tree (default: 5) |
| `--json` | Emits dependency and import statistics as JSON |

Example:

```bash
# View full project tree (dependencies and imports)
qv tree

# View dependency risk and usage graph
qv tree --risk

# View only internal module import hierarchy and circular loops
qv tree --imports

# View dependency tree up to 2 levels deep
qv tree -d -L 2
```

---

## 9. `qv explain`

Displays detailed explanations, evidence requirements, and remediation instructions for a rule.

```bash
qv explain <RULE_ID>
```

Example:

```bash
qv explain DEP-002
qv explain CI-001
qv explain DJG-004
```

---

## 10. Targeted Subsystem Commands

Run focused checks on specific areas without executing the full scan:

### 10.1 `qv dependency`
Scans for dependency conflicts, missing imports, unused packages, and version mismatches, or renders an annotated Dependency Risk Graph.

```bash
qv dependency [PATH] [OPTIONS]
```

Options:
- `-g, --graph`: Render annotated dependency risk and functional usage graph.
- `-r, --risk [all|critical|high|medium|low|healthy]`: Filter dependency graph by risk level.
- `-L, --depth <N>`: Maximum depth level for the tree (default: 5).
- `--no-annotate`: Render compact dependency graph without multi-line annotation details.
- `--json`: Output scan results or dependency risk graph as structured JSON.

Example:
```bash
# Run dependency diagnostic checks
qv dependency

# Render annotated dependency risk graph
qv dependency --graph

# Filter dependency graph for critical/high risks only
qv dependency --graph --risk high
```

### 10.2 `qv environment`
Checks for Python runtime drift between local environment, Dockerfiles, and CI matrices.

```bash
qv environment [PATH]
```

### 10.3 `qv architecture`
Scans source code for circular imports and unresolved internal modules.

```bash
qv architecture [PATH]
```

### 10.4 `qv docker`
Audits Dockerfiles and docker-compose configurations for security best practices, root user risks, unpinned base images, sensitive file leaks, and cache optimization (`DOC-001` - `DOC-014`).

```bash
qv docker [PATH]
```

### 10.5 `qv ci`
Audits Continuous Integration workflows (`.github/workflows/*.yml`) for matrix mismatches, unpinned dependencies, outdated GitHub Actions, missing test/lint quality gates, hardcoded secrets, and missing concurrency cancellation (`CI-001` - `CI-006`).

```bash
qv ci [PATH]
```

### 10.6 `qv framework` (alias: `qv frameworks`)
Runs framework-specific diagnostic rules for FastAPI, SQLAlchemy, Django, and Celery.

```bash
qv framework [PATH] [OPTIONS]
```

Options:
- `-n, --name [fastapi|sqlalchemy|django|celery|sql|all]`: Filter analysis to a specific framework (default: all detected frameworks).
- `--json`: Output framework scan results as structured JSON.
- `--sarif`: Output framework scan results in SARIF v2.1.0 format.

Example:
```bash
# Scan current project for all framework issues
qv framework

# Scan specifically for FastAPI issues
qv framework --name fastapi

# Scan specifically for Django issues
qv framework --name django

```

---

## 11. `qv pr` (alias: `qv pr-analysis`)

GitHub Pull Request Intelligence engine that analyzes only the changed code in a PR, reporting newly introduced issues versus resolved issues, emitting inline GitHub Actions workflow annotations, and generating PR markdown summaries.

```bash
qv pr [PATH] [OPTIONS]
```

Example Output:
```text
QV Pull Request Analysis

Changed files: 8
Affected checks: 17

New issues
──────────
FAP-021  users.py:42
Async endpoint performs blocking I/O

DEP-002  requirements.txt
Missing declaration for httpx

Resolved
────────
SQL-008
```

### 11.1 Options

| Option | Description |
|---|---|
| `-b, --base <REF>` | Base git branch or ref (default: auto-detected from `GITHUB_BASE_REF` or git history) |
| `--head <REF>` | Head git commit or ref (default: `HEAD`) |
| `--strict` | Promotes warnings to errors (fails CI on warnings) |
| `--ci` | Runs non-interactively with step summary & inline annotations |
| `--github-annotations` | Emits GitHub Actions inline workflow command annotations (`::error` and `::warning`) |
| `--comment` | Outputs formatted Markdown suitable for GitHub PR comments |
| `--json` | Emits PR analysis results as structured JSON |
| `--sarif` | Emits new PR findings in standard SARIF v2.1.0 format |
| `--baseline <FILE>` | Compare against an established baseline snapshot file |
| `--files <LIST>` | Comma-separated list of changed files (e.g. `users.py,requirements.txt`) |
| `--diff <FILE>` | Path to a unified diff patch file |
| `-o, --output <FILE>` | Writes report directly to a file |


