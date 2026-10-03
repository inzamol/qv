"""Models for automated remediation engine."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class FixActionType(str, Enum):
    """Type of remediation action."""

    ADD_DEPENDENCY = "add_dependency"
    REMOVE_DEPENDENCY = "remove_dependency"
    PIN_DEPENDENCY = "pin_dependency"
    UPDATE_CONFIG = "update_config"
    UPDATE_METADATA = "update_metadata"
    EXECUTE_COMMAND = "execute_command"


class FixAction(BaseModel):
    """Individual atomic fix action to resolve a diagnostic finding."""

    id: str
    rule_id: str
    action_type: FixActionType
    description: str
    target_file: str | None = None
    diff: str | None = None
    command: str | None = None
    executable: str | None = None
    args: list[str] = Field(default_factory=list)
    is_safe: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class FixPlan(BaseModel):
    """Collection of fix actions planned for a project."""

    project_path: str
    actions: list[FixAction] = Field(default_factory=list)

    @property
    def total_fixes(self) -> int:
        return len(self.actions)

    @property
    def safe_fixes_count(self) -> int:
        return sum(1 for a in self.actions if a.is_safe)


class FixResult(BaseModel):
    """Summary of fixes applied to a project."""

    project_path: str
    applied: list[FixAction] = Field(default_factory=list)
    skipped: list[FixAction] = Field(default_factory=list)
    failed: list[tuple[FixAction, str]] = Field(default_factory=list)
    dry_run: bool = False

    @property
    def success(self) -> bool:
        return len(self.failed) == 0
