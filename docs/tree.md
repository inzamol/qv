# Dependency & Architecture Tree

`qv` provides visual representations of both your package dependency tree and your internal source module import architecture.

---

## 1. Basic Usage

```bash
# Render full project view (dependencies + import graph)
qv tree

# Alias for qv tree
qv graph
```

---

## 2. Visualizing Package Dependencies

To focus exclusively on direct and transitive package dependencies:

```bash
qv tree --dependencies
# or shorthand:
qv tree -d
```

### 2.1 Limiting Tree Depth

Limit the hierarchy depth using `--depth` / `-L`:

```bash
qv tree -d -L 2
```

Example output:

```text
Dependency Hierarchy

fastapi (0.110.0) [direct]
├── starlette (0.36.3) [transitive]
│   └── anyio (4.3.0) [transitive]
│       └── idna (3.6) [transitive]
└── pydantic (2.6.4) [direct]
    ├── annotated-types (0.6.0) [transitive]
    └── pydantic-core (2.16.3) [transitive]
```

---

## 3. Visualizing Internal Module Imports & Circular Loops

To inspect internal Python module imports and pinpoint circular dependency cycles:

```bash
qv tree --imports
# or shorthand:
qv tree -i
```

Example output:

```text
Internal Module Import Architecture

services.payment
├── models.transaction
└── core.config

services.auth
├── utils.security
└── [🔴 CIRCULAR CYCLE] services.payment -> services.auth
```

---

## 4. JSON Export for Tooling

To emit the tree hierarchy, package statistics, and detected cycles as structured JSON for CI ingestion or custom dashboards:

```bash
qv tree --json > graph.json
```
