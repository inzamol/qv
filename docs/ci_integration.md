# CI/CD Integration

`qv` is designed to seamlessly run in Continuous Integration workflows and upload code scanning alerts.

---

## 1. Official GitHub Action (`inzamol/qv`)

Use the official composite GitHub Action to run `qv` with automated PR annotations and step summaries:

```yaml
name: Python Project Health Check

on: [push, pull_request]

jobs:
  qv-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run qv Health Scan
        uses: inzamol/qv@v0.1.0
        with:
          strict: false
          sarif: true
          html-report: true
```

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

### 2.2 Baseline & Differential Scanning (Prevent New Regressions)

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
        uses: github/codeql-action/upload-sarif@v3
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
