# CI/CD Integration

`qv` is designed to seamlessly run in Continuous Integration workflows and upload code scanning alerts.

---

## GitHub Actions

### Basic CI Check

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
      - run: uv run qv scan --ci
```

---

### GitHub Code Scanning with SARIF

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

## Exit Codes for CI Pipelines

- `0`: Success — no blocking findings.
- `1`: Failure — errors found (or warnings in `--strict` / `--ci` mode).
- `2`: Configuration error.
- `3`: Runtime / Analysis failure.
