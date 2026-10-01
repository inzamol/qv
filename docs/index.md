# 🔍 qv Documentation

**Diagnose why your Python project is unhealthy — understand the root cause and get safe, actionable fixes.**

`qv` is a fast, offline-first health analyzer for Python projects. It analyzes your dependency graph, active environment, source module imports, and packaging metadata to uncover issues like constraint conflicts, undeclared imports, circular import cycles, and Docker/CI runtime drift.

---

## ⚡ Key Capabilities

- **Diagnose in Milliseconds**: Sub-second execution with zero external network calls required.
- **Root Cause & Evidence**: Every finding shows the exact conflict chain, source line, and manifest declaration.
- **Safe Remediation**: Get copy-pasteable CLI commands or preview and apply fixes automatically with `qv fix`.
- **Interactive TUI Dashboard**: Full terminal UI (`qv inspect`) with keyboard navigation and live tree exploration.
- **Rich Output Formats**: Human-readable terminal output, standalone interactive HTML reports (`qv scan --html`), SARIF v2.1.0, and machine-readable JSON.
- **Ecosystem Agnostic**: Works out-of-the-box with `uv`, `poetry`, `pip`, `pdm`, and `pipenv`.

---

## 🚀 Quick Navigation

<div class="grid cards" markdown>

-   :material-rocket-launch:{ .lg .middle } __[Getting Started](getting_started.md)__

    ---

    Install `qv` via pip or uv and run your first diagnostic scan in seconds.

-   :material-console:{ .lg .middle } __[CLI Reference](cli_reference.md)__

    ---

    Explore all CLI commands, arguments, reporting flags, and interactive options.

-   :material-format-list-checks:{ .lg .middle } __[Rules Catalog](rules.md)__

    ---

    Browse all diagnostic rules across Dependencies, Environment, Architecture, and Packaging.

-   :material-cog:{ .lg .middle } __[Configuration Guide](configuration.md)__

    ---

    Customize rule severities, ignore specific rules, and exclude path patterns in `pyproject.toml`.

-   :material-github:{ .lg .middle } __[CI/CD & GitHub Actions](ci_integration.md)__

    ---

    Set up the official GitHub Action, SARIF code scanning, and pre-commit hooks.

-   :material-handshake:{ .lg .middle } __[Contributing Guide](contributing.md)__

    ---

    Set up your development environment, run test matrices with Tox, and author new rules.

</div>
