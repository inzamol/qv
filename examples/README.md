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
| **[`docker_issues/`](./docker_issues)** | `DOC-001` - `DOC-014` | Docker | Dockerfile with caching anti-patterns, root execution, unpinned base image, and sensitive copies. | ℹ️ Container Config |
| **[`ci_issues/`](./ci_issues)** | `CI-001` - `CI-006` | CI/CD | GitHub Actions workflow with matrix drift, unpinned actions/deps, missing quality gates, and secrets. | ℹ️ Workflow Config |
| **[`django_issues/`](./django_issues)** | `DJG-001` - `DJG-006` | Django | Django project with DEBUG=True, hardcoded SECRET_KEY, wildcard hosts, N+1 queries, missing on_delete. | ℹ️ Framework Config |
| **[`celery_issues/`](./celery_issues)** | `CEL-001` - `CEL-004` | Celery | Celery tasks with insecure pickle serializer, missing timeouts, unbounded retries, blocking sleep. | ℹ️ Framework Config |
| **[`baseline_scanning/`](./baseline_scanning)** | `DEP-002` (Basellined) | Baseline | Pre-recorded baseline filtering out legacy findings during CI scans. | ℹ️ Differential Scan |
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

### 2. Test CI/CD Workflow Issues (`CI-001` - `CI-006`)
```bash
# Audit CI workflow definitions
qv ci examples/ci_issues
```

### 3. Test Django Framework Anti-Patterns (`DJG-001` - `DJG-006`)
```bash
# Scan Django settings, models, views, and middleware
qv framework --name django examples/django_issues
```

### 4. Test Celery Background Task Anti-Patterns (`CEL-001` - `CEL-004`)
```bash
# Scan Celery task definitions and app configurations
qv framework --name celery examples/celery_issues
```

### 5. Test Baseline & Differential Scanning
```bash
# Scan without baseline (reports 2 diagnostics)
qv scan examples/baseline_scanning

# Scan with baseline filter (0 diagnostics reported)
qv scan examples/baseline_scanning --baseline examples/baseline_scanning/.qv-baseline.json
```

### 6. Test Docker Container Issues (`DOC-001` - `DOC-014`)
```bash
qv docker examples/docker_issues
```

### 7. Test Circular Import Cycle (`IMP-001`)
```bash
# Scan and view the circular import chain
qv scan examples/circular_imports
```

### 8. Test Unresolved Local Import (`IMP-002`)
```bash
# Scan and pinpoint non-existent module import
qv scan examples/unresolved_imports
```

### 9. Test Missing Packaging Metadata (`PKG-001`)
```bash
# Scan bare project
qv scan examples/missing_metadata

# Automatically initialize [project] table in pyproject.toml
qv fix examples/missing_metadata -y
```

### 10. Test Vulnerable Dependencies & CVEs (`DEP-006`)
```bash
# Scan and query live OSV.dev advisory database for CVEs
qv scan examples/vulnerable_dependencies

# Scan in offline airgapped mode
qv scan examples/vulnerable_dependencies --offline
```

### 11. Test All-in-One Unhealthy Project
```bash
# Full health report across all subsystems
qv scan examples/all_in_one_unhealthy

# Run interactive fix wizard
qv fix examples/all_in_one_unhealthy --dry-run
```
