# 🧪 qv Test Scenarios & Examples

This directory contains standalone example projects demonstrating all diagnostic rules detected and fixed by **`qv`**.

---

## 📁 Scenario Index

| Folder | Rule Triggered | Category | Description | Fixable with `qv fix` |
|---|---|---|---|:---:|
| **[`missing_dependencies/`](./missing_dependencies)** | `DEP-002` | Dependency | Code imports `httpx` and `pydantic`, but they are not declared in `pyproject.toml`. | ✅ Yes |
| **[`unused_dependencies/`](./unused_dependencies)** | `DEP-003` | Dependency | `requests` and `pyyaml` are declared in `pyproject.toml`, but never imported in source code. | ⚠️ Review Required |
| **[`circular_imports/`](./circular_imports)** | `IMP-001` | Architecture | `module_a.py` and `module_b.py` import each other, forming a circular dependency cycle. | ℹ️ Architectural |
| **[`unresolved_imports/`](./unresolved_imports)** | `IMP-002` | Architecture | Code imports `from app.auth.missing_token import verify_token`, which does not exist. | ℹ️ Code Edit |
| **[`missing_metadata/`](./missing_metadata)** | `PKG-001` | Packaging | Bare `pyproject.toml` missing the required PEP 621 `[project]` metadata table. | ✅ Yes |
| **[`environment_drift/`](./environment_drift)** | `ENV-002`, `ENV-003` | Environment | Target Python is `>=3.12`, but Dockerfile uses `3.10` and CI matrix runs `3.9`. | ℹ️ Docker/CI Config |
| **[`dead_modules/`](./dead_modules)** | `IMP-003` | Architecture | `unused_legacy_module.py` exists in source code but is never imported anywhere. | ℹ️ Dead Code Removal |
| **[`deprecated_stdlib/`](./deprecated_stdlib)** | `IMP-004` | Compatibility | Code imports removed stdlib modules (`imp`, `distutils`, `cgi`, `pipes` in Python 3.12/3.13). | ℹ️ Modernization |
| **[`vulnerable_dependencies/`](./vulnerable_dependencies)** | `DEP-006` | Security | Project pins `jinja2==2.11.2` with known critical security vulnerabilities & CVEs. | ℹ️ Security Upgrade |
| **[`all_in_one_unhealthy/`](./all_in_one_unhealthy)** | Multiple | All | Realistic messy project containing missing deps, unused deps, circular imports, and container drift. | ✅ Yes |

---

## 🚀 How to Run Tests

### 1. Test Missing Dependencies (`DEP-002`)
```bash
# Scan and see the missing packages (httpx, pydantic)
qv scan examples/missing_dependencies

# Preview the fix diff
qv fix examples/missing_dependencies --dry-run

# Automatically add missing packages to pyproject.toml
qv fix examples/missing_dependencies -y
```

### 2. Test Unused Dependencies (`DEP-003`)
```bash
# Scan and see unimported declared packages (requests, pyyaml)
qv scan examples/unused_dependencies

# Review and prune unimported packages interactively
qv fix examples/unused_dependencies
```

### 3. Test Circular Import Cycle (`IMP-001`)
```bash
# Scan and view the circular import chain
qv scan examples/circular_imports
```

### 4. Test Unresolved Local Import (`IMP-002`)
```bash
# Scan and pinpoint non-existent module import
qv scan examples/unresolved_imports
```

### 5. Test Missing Packaging Metadata (`PKG-001`)
```bash
# Scan bare project
qv scan examples/missing_metadata

# Automatically initialize [project] table in pyproject.toml
qv fix examples/missing_metadata -y
```

### 6. Test Environment & Container Drift (`ENV-002`, `ENV-003`)
```bash
# Scan and detect Docker base image and CI matrix drift
qv scan examples/environment_drift
```

### 7. Test Dead / Orphan Local Modules (`IMP-003`)
```bash
# Scan and detect dead unused source modules
qv scan examples/dead_modules
```

### 8. Test Deprecated/Removed Python 3.11-3.13 Stdlib Modules (`IMP-004`)
```bash
# Scan and detect PEP 594 removed stdlib modules (imp, distutils, cgi, pipes)
qv scan examples/deprecated_stdlib
```

### 9. Test Vulnerable Dependencies & CVEs (`DEP-006`)
```bash
# Scan and query live OSV.dev advisory database for CVEs
qv scan examples/vulnerable_dependencies

# Scan in offline airgapped mode
qv scan examples/vulnerable_dependencies --offline
```

### 10. Test All-in-One Unhealthy Project
```bash
# Full health report across all subsystems
qv scan examples/all_in_one_unhealthy

# Run interactive fix wizard
qv fix examples/all_in_one_unhealthy --dry-run
```
