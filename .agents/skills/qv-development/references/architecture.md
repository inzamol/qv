# QV (python-qv) Architecture Reference

This reference details the internal architecture, lifecycle, and component interactions of the QV project.

---

## 1. High-Level Architecture Pipeline

```text
                           CLI Entry Point (qv / python-qv)
                                         |
                                  Project Discovery
                    (pyproject.toml, requirements, lockfiles, AST)
                                         |
                                  Project Context
                                         |
           +-----------------------------+-----------------------------+
           |                             |                             |
      Core Analyzers            Framework Plugins             Security Engine
   ├── Dependency Analyzer     ├── FastAPI Analyzer          └── OSV Vulnerability
   ├── Environment Analyzer    ├── SQLAlchemy Analyzer            Scanner
   ├── Import Analyzer         ├── Django Analyzer
   ├── Packaging Analyzer      └── Celery Analyzer
   ├── Docker Analyzer
   └── CI Analyzer
                                         |
                                 Diagnostic Engine
                            (Correlation & Root Causes)
                                         |
           +-----------------------------+-----------------------------+
           |                             |                             |
     Reporters                     Remediation                     Visualizers
   ├── Terminal Reporter       └── Remediation Engine        ├── Tree Visualizer
   ├── Doctor Scorecard            (Auto-fixes for           ├── Risk Graph Visualizer
   ├── HTML Reporter               pyproject/reqs)           └── Rich TUI Explorer
   ├── SARIF Reporter
   ├── JSON Reporter
   ├── PR Reporter
   └── GitHub Annotator
```

---

## 2. Source Code Layout (`src/qv/`)

- `analyzers/`
  - `dependencies/`: `DEP-001..006` (version conflicts, missing requirements, unused direct dependencies, python compatibility, lockfile mismatches).
  - `environment/`: `ENV-001..003` (Python runtime mismatch, venv drift, package manager inconsistencies).
  - `imports/`: `IMP-001..004` (circular imports, unresolved imports, dead modules).
  - `packaging/`: `PKG-001..002` (pyproject.toml/setup.cfg consistency, build backend issues).
  - `security/`: `SEC-001` (OSV.dev vulnerability scanner, lockfile parsers).
  - `docker/`: `DOC-001..005` (Dockerfile syntax, root user warnings, pinned base images, caching best practices).
  - `ci/`: `CI-001..004` (GitHub Actions workflow configurations, action pinning, cache optimization).
- `cli/`
  - `main.py`: Click CLI entry point, argument parsing, error boundaries (`_handle_cli_errors`), subcommands (`scan`, `doctor`, `fix`, `tree`, `graph`/`risk`, `pr`/`diff`, `rules`, `tui`).
- `core/`
  - `analyzer.py`: Base `Analyzer` typing protocol (`id`, `name`, `description`, `rules`, `analyze(context)`).
  - `config.py`: Configuration models, TOML parsing (`pyproject.toml` `[tool.qv]`), severity overrides, ignore rules, exclude paths.
  - `context.py`: `ProjectContext` immutable snapshot containing manifest data, dependency graph, AST trees, runtime configs, and discovered files.
  - `engine.py`: `AnalysisEngine` executing analyzers concurrently/sequentially, catching exceptions per analyzer (wrapped into `ENG-001`), computing root causes, and producing `ScanResult`.
  - `models.py`: Data models (`Diagnostic`, `Evidence`, `Suggestion`, `RootCause`, `ScanSummary`, `ScanResult`, `Severity`).
  - `project.py`: `load_project` discovery loader reading filesystem, package manager lockfiles, and source files.
  - `baseline.py`: Baseline fingerprinting, loading, and filtering to suppress existing legacy diagnostics.
  - `pr.py`: `PRAnalyzer` inspecting changed files in git diffs / pull requests.
- `frameworks/`
  - `base.py`: `BaseFrameworkAnalyzer` with AST visitor utilities for framework detection.
  - `fastapi.py`: `FAP-001..034` (FastAPI route definitions, dependency injection, async def, status codes, pydantic response models).
  - `sqlalchemy.py`: `SQL-001..030` (session management, N+1 query patterns, eager loading, declarative models).
  - `django.py`: `DJG-001..015` (settings, model relationships, viewsets, querysets).
  - `celery.py`: `CEL-001..010` (task signatures, broker timeouts, retry policies).
- `remediation/`
  - `engine.py`: `RemediationEngine` generating and applying deterministic safe fixes to `pyproject.toml` and `requirements.txt` using `tomlkit` (preserving comments and formatting).
  - `models.py`: `FixAction`, `FixPlan`, `FixResult`.
- `reporters/`
  - `base.py`: `Reporter` protocol.
  - `terminal.py`: Rich console reporter with formatted tables, color-coded severities, and remediation snippets.
  - `doctor_reporter.py`: Health scorecard with category grades (A-F) and checklist items.
  - `html_reporter.py`: Self-contained interactive single-file HTML report with charts and search/filter.
  - `sarif.py`: OASIS SARIF v2.1.0 JSON format for GitHub Code Scanning and IDEs.
  - `json_reporter.py`: Machine-readable JSON output for automated integrations.
  - `github_annotator.py`: Emits GitHub Actions workflow commands (`::error::`, `::warning::`) and job summaries.
  - `pr_reporter.py`: Pull request summary Markdown output.
- `rules/`
  - `registry.py`: Central source of truth (`RULES_CATALOG`, `RuleDefinition`, `get_rule_definition`) with canonical rule IDs, categories, descriptions, and documentation links.
- `tui/`
  - `app.py`: Textual/Rich interactive terminal user interface.
- `visualizers/`
  - `architecture.py`: Architecture map, layer classification, circular component dependencies (`ARC-002`), layer violations (`ARC-001`), diagnostic conversion (`to_diagnostics()`), and multi-format exports (ASCII, Mermaid, DOT, JSON).
  - `tree.py`: ASCII / Rich tree visualizer for direct & transitive dependencies.
  - `risk_graph.py`: Blast radius and dependency risk visualization.

---

## 3. Core Analysis Lifecycle

1. **Discovery (`load_project(path)`):**
   - Detects package manager (`uv`, `poetry`, `pipenv`, `flit`, `hatch`, `setuptools`).
   - Parses manifest files (`pyproject.toml`, `requirements.txt`, `Pipfile`, `setup.py`, `setup.cfg`).
   - Parses lockfiles (`uv.lock`, `poetry.lock`, `Pipfile.lock`).
   - Scans and parses Python ASTs across all non-excluded source files.
   - Discovers configuration in `pyproject.toml` under `[tool.qv]`.

2. **Context Creation (`ProjectContext`):**
   - Assembles dependencies, installed packages in active venv, AST trees, module graph, and settings into an immutable context object.

3. **Execution Pipeline (`AnalysisEngine.run(context)`):**
   - Iterates through registered core analyzers and framework analyzers.
   - Analyzer errors are isolated: an unhandled exception in an analyzer generates an `ENG-001` diagnostic without crashing other analyzers or the whole scan.
   - Applies rule severity overrides and filters disabled rules based on configuration.

4. **Root Cause Analysis & Correlation:**
   - Correlates dependent diagnostics into `RootCause` instances to highlight the root defect rather than cascading symptoms.

5. **Reporting & Remediation:**
   - Feeds `ScanResult` into selected reporter (Terminal, HTML, SARIF, JSON, Doctor, etc.).
   - If `qv fix` is invoked, `RemediationEngine` generates and applies non-destructive patches.

---

## 4. Architecture Graph & Diagnostic Pipeline (`qv architecture`)

1. **Layer & Component Discovery (`ArchitectureGraph`):**
   - Discovers components by mapping file paths into architectural folders (e.g. `api`, `services`, `repositories`, `database`, `utils`).
   - Slices subpackages only when the first path component is a recognized package root (`clean_parts[0] in known_roots`). For flat layouts, uses `clean_parts[0]`.
   - Resolves target modules to components strictly by matching top-level segments (`mod_name.split(".")[0]`) or registered internal module paths to avoid converting third-party imports into internal edges.
2. **Cycle & Layer Violation Detection:**
   - Uses DFS on component adjacency graph to detect cycles (`ARC-002`, `Severity.ERROR`).
   - Checks layer directionality and skipping rules (e.g. `API` bypassing `Services`/`Repository` to directly import `Database`, or lower layers importing higher layers) (`ARC-001`, `Severity.WARNING`).
3. **Diagnostic Conversion (`graph.to_diagnostics()`):**
   - Converts `ArchitectureViolation` instances into standardized `Diagnostic` models with `file`, `line`, `evidence`, `suggestions`, and documentation links.
   - `architecture_scan_cmd` merges these into `ScanResult` so that standard reporters, `--json`, `--sarif`, and `--strict` exit code checks behave consistently.

