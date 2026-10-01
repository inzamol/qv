# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-10-01

Initial public release of `qv` — the proactive health diagnostics and remediation platform for Python projects.

### Added
- **Diagnostic Engine & Analyzers**:
  - `DEP-001`: Dependency version constraint conflict detection.
  - `DEP-002`: Missing undeclared package imports.
  - `DEP-003`: Unused declared dependencies.
  - `DEP-004`: Python target runtime incompatibility.
  - `DEP-005`: Virtualenv vs declared pin drift.
  - `DEP-006`: Known vulnerability/CVE reporting.
  - `ENV-001`: Python interpreter version drift.
  - `ENV-002`: Dockerfile base image Python version drift.
  - `ENV-003`: CI matrix coverage drift.
  - `IMP-001`: Circular import cycle detection with Tarjan's SCC algorithm.
  - `IMP-002`: Unresolvable internal module imports.
  - `IMP-003`: Orphan / dead internal modules.
  - `IMP-004`: Deprecated / removed standard library modules (PEP 594).
  - `PKG-001`: Missing PEP 621 packaging metadata.
  - `PKG-002`: Invalid `pyproject.toml` syntax.
- **Reporting & Visualizers**:
  - Interactive Terminal Explorer (TUI) with keyboard navigation (`qv inspect`, `qv ui`).
  - Self-contained, single-file interactive HTML report generator (`qv scan --html`).
  - Standard SARIF v2.1.0 report exporter (`qv scan --sarif`).
  - Machine-readable JSON reporter (`qv scan --json`).
  - Color-coded Rich terminal reporter with circular health score gauge.
  - Dependency and import architecture visualizers (`qv tree`, `qv graph`).
- **Remediation**:
  - Safe automated fix engine (`qv fix`) with dry-run previews, interactive confirmations, and package manager sync.
- **Ecosystem & CI/CD**:
  - Native pre-commit hooks (`qv-scan`, `qv-fix`).
  - Official GitHub Action (`action.yml`) with automated PR annotations and Step Summary markdown.
  - Automated PyPI publishing workflow with SLSA build provenance attestations.
  - Comprehensive documentation site built with MkDocs Material and configured for ReadTheDocs.
