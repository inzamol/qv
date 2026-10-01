# Diagnostic Rules Catalog

`qv` rule IDs are stable public identifiers. This catalog lists all supported diagnostic checks, their default severities, and remediation strategies.

---

## 📦 Dependency Rules

### `DEP-001` — Dependency Constraint Conflict
- **Default Severity:** `ERROR`
- **Description:** Two or more declared or transitive dependencies have incompatible version constraints.
- **Remediation:** Upgrade the conflicting package or loosen the version pin to satisfy all requirements.

### `DEP-002` — Missing Dependency Declaration
- **Default Severity:** `ERROR`
- **Description:** A third-party package is imported in project source code but is not declared in `pyproject.toml` or requirements files.
- **Remediation:** Add the missing package to your project dependencies (`uv add <package>` or `pip install <package>`).

### `DEP-003` — Unused Declared Dependency
- **Default Severity:** `WARNING`
- **Description:** A package is declared as a direct dependency, but no import statements were detected across project source files.
- **Remediation:** Verify if this dependency is required at runtime or remove it to keep dependencies lean.

### `DEP-004` — Python Compatibility Mismatch
- **Default Severity:** `WARNING`
- **Description:** A package requires a Python version incompatible with the target project runtime.
- **Remediation:** Upgrade your target Python version or install a version of the package compatible with your environment.

### `DEP-005` — Installed/Declaration Mismatch
- **Default Severity:** `WARNING`
- **Description:** The package version installed in the virtualenv does not satisfy the constraint declared in your project manifest.
- **Remediation:** Synchronize your virtual environment using `uv sync`, `poetry install`, or `pip install -r requirements.txt`.

### `DEP-006` — Vulnerable Transitive Dependency
- **Default Severity:** `ERROR`
- **Description:** A security vulnerability has been identified in a direct or transitive dependency.
- **Remediation:** Update the vulnerable dependency or apply security patches.

---

## 🌐 Environment & Drift Rules

### `ENV-001` — Python Version Drift
- **Default Severity:** `WARNING`
- **Description:** The active Python interpreter version differs from the project's target runtime specification.
- **Remediation:** Rebuild your virtual environment using the configured target Python version.

### `ENV-002` — Docker Runtime Drift
- **Default Severity:** `WARNING`
- **Description:** The Python version specified in `Dockerfile` or `compose.yml` differs from the project's target runtime.
- **Remediation:** Update the base image tag in `Dockerfile` (e.g. `FROM python:3.12-slim`).

### `ENV-003` — CI Runtime Drift
- **Default Severity:** `WARNING`
- **Description:** CI workflow matrix does not test the Python versions declared in project support.
- **Remediation:** Align your CI test matrix with `pyproject.toml` supported versions.

---

## 🔄 Import & Architecture Rules

### `IMP-001` — Circular Import Detected
- **Default Severity:** `ERROR`
- **Description:** An import cycle exists between two or more local modules, risking runtime `ImportError` or partially initialized modules.
- **Remediation:** Break the cycle by refactoring shared logic into a separate module or using deferred imports inside functions.

### `IMP-002` — Unresolved Local Import
- **Default Severity:** `ERROR`
- **Description:** A local module imported in source code could not be resolved on the project's Python path.
- **Remediation:** Check the module name and ensure source directories are on the Python path or package root.

---

## 📄 Packaging Rules

### `PKG-001` — Missing Package Metadata
- **Default Severity:** `WARNING`
- **Description:** Essential packaging metadata (such as project name, version, or description) is missing from `pyproject.toml`.
- **Remediation:** Provide standard PEP 621 fields under the `[project]` table.

### `PKG-002` — Invalid Project Configuration
- **Default Severity:** `ERROR`
- **Description:** `pyproject.toml` contains syntax errors or invalid configuration tables.
- **Remediation:** Fix TOML syntax and ensure configuration follows PEP 621 specifications.
