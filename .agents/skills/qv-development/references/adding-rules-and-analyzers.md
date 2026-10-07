# Guide: Adding Rules & Analyzers in QV

This guide outlines step-by-step instructions for adding a new diagnostic rule, core analyzer, framework analyzer, or auto-fix remediation to QV.

---

## 1. Adding a New Diagnostic Rule

### Step 1: Define Rule in `src/qv/rules/registry.py`

Every diagnostic rule must be declared in `RULES_CATALOG`:

```python
# src/qv/rules/registry.py

"FAP-035": RuleDefinition(
    id="FAP-035",
    category="fastapi",
    title="Deprecated background task usage",
    description="FastAPI BackgroundTasks should be passed as a route parameter rather than instantiated manually inside endpoints.",
    default_severity=Severity.WARNING,
    remediation_hint="Add `background_tasks: BackgroundTasks` directly to the route handler signature.",
    doc_url=make_doc_url("fap-035-deprecated-background-task-usage"),
),
```

### Step 2: Implement Detection Logic

Depending on rule category:
- **Core Analyzer** (e.g. `src/qv/analyzers/dependencies/`, `src/qv/analyzers/imports/`):
  Parse context (AST, lockfile, manifest) and append `Diagnostic` objects.
- **Framework Analyzer** (e.g. `src/qv/frameworks/fastapi.py`, `src/qv/frameworks/sqlalchemy.py`):
  Use AST visitors (`ast.NodeVisitor` or custom AST walkers) to find anti-patterns.

Constructing a `Diagnostic`:
```python
from qv.core.models import Diagnostic, Evidence, Severity, Suggestion
from qv.rules.registry import get_rule_definition

rule_def = get_rule_definition("FAP-035")

diagnostic = Diagnostic(
    id="FAP-035",
    severity=rule_def.default_severity if rule_def else Severity.WARNING,
    category="fastapi",
    title="Deprecated background task usage",
    message="Manual BackgroundTasks instantiation detected in endpoint 'send_notification'.",
    file=str(file_path),
    line=node.lineno,
    column=node.col_offset,
    evidence=[
        Evidence(
            fact="`BackgroundTasks()` instantiated inside handler body",
            source=str(file_path),
            details={"function": "send_notification", "line": node.lineno},
        )
    ],
    suggestions=[
        Suggestion(
            description="Declare `background_tasks: BackgroundTasks` as a function parameter instead.",
            is_safe=True,
        )
    ],
    doc_url=rule_def.doc_url if rule_def else None,
)
```

### Step 3: Document the Rule in `docs/rules.md`

Add a corresponding documentation section and anchor for the new rule in `docs/rules.md` matching the rule ID and slug.

### Step 4: Write Tests

Create or update test cases in `tests/test_<analyzer>.py`:
- Test positive match (anti-pattern triggers the rule).
- Test negative match (clean code does not trigger false positive).
- Verify rule metadata exists in `tests/test_rules.py`.

---

## 2. Adding a New Framework Analyzer

### Step 1: Create Framework Module

Create `src/qv/frameworks/<name>.py` extending `BaseFrameworkAnalyzer` (or implementing the `Analyzer` protocol):

```python
# src/qv/frameworks/flask.py

from __future__ import annotations
import ast
from pathlib import Path
from qv.core.analyzer import Analyzer
from qv.core.context import ProjectContext
from qv.core.models import Diagnostic
from qv.frameworks.base import BaseFrameworkAnalyzer


class FlaskAnalyzer(BaseFrameworkAnalyzer):
    id: str = "flask"
    name: str = "Flask Analyzer"
    description: str = "Analyzes Flask routes, application factories, and blueprint configurations."
    rules: tuple[str, ...] = ("FLK-001", "FLK-002")

    def is_applicable(self, context: ProjectContext) -> bool:
        """Check if Flask is present in dependencies or imports."""
        return "flask" in context.declared_dependencies or "flask" in context.all_imports

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        if not self.is_applicable(context):
            return []

        diagnostics: list[Diagnostic] = []
        for file_path, tree in context.ast_trees.items():
            # Run AST visitors or inspections
            ...
        return diagnostics
```

### Step 2: Register in `src/qv/frameworks/__init__.py`

```python
from qv.frameworks.flask import FlaskAnalyzer

AVAILABLE_FRAMEWORK_ANALYZERS = [
    FastAPIAnalyzer,
    SQLAlchemyAnalyzer,
    DjangoAnalyzer,
    CeleryAnalyzer,
    FlaskAnalyzer,
]
```

---

## 3. Adding Auto-Fix Remediations (`RemediationEngine`)

If a rule has a safe, deterministic fix:

1. Define a `FixAction` in `src/qv/remediation/engine.py`.
2. Use `tomlkit` for modifying TOML files (`pyproject.toml`) so formatting, spacing, and comments are preserved.
3. For `requirements.txt`, perform non-destructive updates.
4. Add dry-run (`qv fix --dry-run`) and apply tests in `tests/test_remediation.py`.
