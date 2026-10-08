# CI/CD Integration

`qv` is designed to seamlessly run in Continuous Integration workflows and upload code scanning alerts.

---

## 1. Official GitHub Action (`inzamol/qv`)

Use the official composite GitHub Action to run `qv` with automated PR annotations, SARIF reports, and step summaries:

```yaml
name: Python Project Health Check

on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  qv-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run qv Health Scan
        uses: inzamol/qv@v1
        with:
          format: sarif
          output: qv-results.sarif
          fail-on: error

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: qv-results.sarif
          category: qv
```

### 1.1 Action Inputs & Configuration

| Input | Description | Default |
|---|---|---|
| `path` | Path to the Python project directory to analyze | `.` |
| `version` | Version of `python-qv` to use (`latest`, specific version like `1.0.0`, or `local`) | `latest` |
| `python-version` | Python version used to run qv (`3.10`, `3.11`, `3.12`, `3.13`) | `3.12` |
| `format` | Output report format (`sarif`, `terminal`, `json`, `html`, `text`) | `sarif` |
| `output` | Output file path for generated report | `qv-results.sarif` |
| `fail-on` | Finding severity causing workflow failure (`error`, `warning`, `none`) | `error` |
| `github-annotations` | Emit GitHub Actions inline annotations (`::error`, `::warning`) | `true` |
| `offline` | Disable remote vulnerability queries (airgapped mode) | `false` |
| `baseline` | Path to baseline snapshot to ignore existing findings | `""` |
| `args` | Additional CLI arguments to pass to `qv scan` | `""` |

### 1.2 Action Outputs

| Output | Description |
|---|---|
| `sarif-file` | Path to the generated SARIF file |
| `findings` | Total number of diagnostic findings detected (populated for `sarif` or `json` formats) |
| `errors` | Total number of error findings detected (populated for `sarif` or `json` formats) |
| `warnings` | Total number of warning findings detected (populated for `sarif` or `json` formats) |
| `exit-code` | Exit code returned by `qv` |

---

## 2. Custom CI Configuration

### 2.1 Basic CI Check

Add a step to your `.github/workflows/ci.yml`:

```yaml
name: CI

on: [push, pull_request]

jobs:
  qv:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
        with:
          version: "latest"
      - run: uv run qv scan --ci --github-annotations
```

---

### 2.2 GitHub PR Intelligence (Changed Code & Annotations)

Run PR intelligence on pull requests to analyze only modified lines/files, emit inline workflow command annotations (`::error` and `::warning`), report resolved issues, and generate a step summary:

```yaml
name: PR Intelligence

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  qv-pr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Fetch git history for base ref comparison
      - uses: astral-sh/setup-uv@v3
        with:
          version: "latest"

      # Analyzes changed code, emits GitHub annotations, and generates step summary
      - name: Run QV PR Intelligence
        run: uv run qv pr --ci --github-annotations
```

---

### 2.3 Baseline & Differential Scanning (Prevent New Regressions)

For large existing codebases with pre-existing warnings or technical debt, use baseline snapshots so CI only fails on **new** diagnostic issues introduced in pull requests:

```yaml
name: CI (Baseline Verification)

on: [push, pull_request]

jobs:
  qv-baseline:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3

      # Verify that no new issues exist beyond .qv-baseline.json
      - name: Verify QV Baseline
        run: uv run qv baseline verify --strict
```

Or pass `--baseline` to standard scans:
```bash
uv run qv scan --ci --baseline .qv-baseline.json
```

---

### 2.3 CI/CD Workflow & Dockerfile Auditing

Add targeted health audits to ensure your CI workflows and Docker environments conform to production security best practices:

```yaml
      # Audit GitHub Actions workflow definitions
      - name: Audit CI Workflows
        run: uv run qv ci

      # Audit Dockerfiles and docker-compose configurations
      - name: Audit Docker Assets
        run: uv run qv docker
```

---

### 2.4 GitHub Code Scanning with SARIF

`qv` supports emitting findings in **SARIF v2.1.0** format for GitHub Advanced Security and Code Scanning:

```yaml
name: Security & Health Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  qv-sarif:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3

      - name: Run qv SARIF scan
        run: uv run qv scan --sarif --output results.sarif
        continue-on-error: true

      - name: Upload SARIF report
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: results.sarif
```

---

## 3. Pre-commit Integration

`qv` provides native pre-commit hooks via `.pre-commit-hooks.yaml`.

Add this to your project's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/inzamol/qv
    rev: v0.1.0
    hooks:
      # Block commits if diagnostic errors or warnings are detected
      - id: qv-scan
        args: [--strict, --offline]

      # Optional: Automatically remediate safe issues on commit
      # - id: qv-fix
```

### 3.1 Available Hooks

| Hook ID | Description | Default Command |
|---|---|---|
| `qv-scan` | Runs diagnostic health scan on the project | `qv scan` |
| `qv-fix` | Automatically fixes safe issues (`DEP-002`, `ENV-002`, `PKG-001`) | `qv fix -y` |

---

## 4. Exit Codes for CI Pipelines

- `0`: Success — no blocking findings.
- `1`: Failure — errors found (or warnings in `--strict` / `--ci` mode).
- `2`: Configuration error.
- `3`: Runtime / Analysis failure.
