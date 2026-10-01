"""Core remediation engine implementing automated and safe fixes."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from qv.core.models import ScanResult
from qv.remediation.models import FixAction, FixActionType, FixPlan, FixResult

if sys.version_info >= (3, 11):
    pass
else:
    pass


class RemediationEngine:
    """Plans and applies automated fixes for diagnostic findings."""

    def __init__(self, project_root: Path) -> None:
        self.root = project_root.resolve()

    def plan_fixes(
        self,
        scan_result: ScanResult,
        rule_filter: str | None = None,
    ) -> FixPlan:
        """Analyze diagnostic findings and produce a structured FixPlan."""
        actions: list[FixAction] = []
        pyproject_path = self.root / "pyproject.toml"
        requirements_path = self.root / "requirements.txt"

        for idx, diag in enumerate(scan_result.diagnostics, 1):
            if rule_filter and diag.id.upper() != rule_filter.upper():
                continue

            # Handle DEP-002: Missing dependency declaration
            if diag.id == "DEP-002":
                pkg = diag.metadata.get("missing_package")
                if not pkg and diag.affected_packages:
                    pkg = diag.affected_packages[0]

                if pkg:
                    target_file = (
                        "pyproject.toml"
                        if pyproject_path.exists()
                        else "requirements.txt"
                        if requirements_path.exists()
                        else "pyproject.toml"
                    )
                    actions.append(
                        FixAction(
                            id=f"fix-dep-002-{idx}-{pkg}",
                            rule_id="DEP-002",
                            action_type=FixActionType.ADD_DEPENDENCY,
                            description=f"Add missing dependency '{pkg}' to {target_file}",
                            target_file=target_file,
                            diff=f"+ {pkg}",
                            metadata={"package": pkg},
                            is_safe=True,
                        )
                    )

            # Handle DEP-003: Unused declared dependency
            elif diag.id == "DEP-003":
                pkg = diag.metadata.get("unused_package")
                if not pkg and diag.affected_packages:
                    pkg = diag.affected_packages[0]

                if pkg:
                    target_file = (
                        "pyproject.toml"
                        if pyproject_path.exists()
                        else "requirements.txt"
                        if requirements_path.exists()
                        else "pyproject.toml"
                    )
                    actions.append(
                        FixAction(
                            id=f"fix-dep-003-{idx}-{pkg}",
                            rule_id="DEP-003",
                            action_type=FixActionType.REMOVE_DEPENDENCY,
                            description=f"Remove unused dependency '{pkg}' from {target_file}",
                            target_file=target_file,
                            diff=f"- {pkg}",
                            metadata={"package": pkg},
                            is_safe=True,
                        )
                    )

            # Handle PKG-001: Missing package metadata
            elif diag.id == "PKG-001":
                proj_name = self.root.name.lower().replace(" ", "-").replace("_", "-")
                actions.append(
                    FixAction(
                        id=f"fix-pkg-001-{idx}",
                        rule_id="PKG-001",
                        action_type=FixActionType.UPDATE_METADATA,
                        description=f"Initialize standard [project] metadata with name '{proj_name}'",
                        target_file="pyproject.toml",
                        diff=f'+ [project]\n+ name = "{proj_name}"\n+ version = "0.1.0"\n+ dependencies = []',
                        metadata={"project_name": proj_name},
                        is_safe=True,
                    )
                )

            # Handle command suggestions (e.g. DEP-001, DEP-005)
            elif diag.suggestions:
                for s_idx, sugg in enumerate(diag.suggestions):
                    if sugg.command:
                        actions.append(
                            FixAction(
                                id=f"fix-cmd-{diag.id}-{idx}-{s_idx}",
                                rule_id=diag.id,
                                action_type=FixActionType.EXECUTE_COMMAND,
                                description=sugg.description,
                                command=sugg.command,
                                is_safe=sugg.is_safe,
                            )
                        )

        return FixPlan(project_path=str(self.root), actions=actions)

    def apply_plan(
        self,
        plan: FixPlan,
        dry_run: bool = False,
        execute_commands: bool = False,
    ) -> FixResult:
        """Apply the fixes in the plan to project files."""
        result = FixResult(project_path=plan.project_path, dry_run=dry_run)

        for action in plan.actions:
            if dry_run:
                result.applied.append(action)
                continue

            try:
                if action.action_type == FixActionType.ADD_DEPENDENCY:
                    pkg = action.metadata.get("package")
                    if pkg and action.target_file == "pyproject.toml":
                        self._add_dependency_to_pyproject(pkg)
                        result.applied.append(action)
                    elif pkg and action.target_file == "requirements.txt":
                        self._add_dependency_to_requirements(pkg)
                        result.applied.append(action)
                    else:
                        result.skipped.append(action)

                elif action.action_type == FixActionType.REMOVE_DEPENDENCY:
                    pkg = action.metadata.get("package")
                    if pkg and action.target_file == "pyproject.toml":
                        self._remove_dependency_from_pyproject(pkg)
                        result.applied.append(action)
                    elif pkg and action.target_file == "requirements.txt":
                        self._remove_dependency_from_requirements(pkg)
                        result.applied.append(action)
                    else:
                        result.skipped.append(action)

                elif action.action_type == FixActionType.UPDATE_METADATA:
                    proj_name = action.metadata.get("project_name", self.root.name)
                    self._initialize_pyproject_metadata(proj_name)
                    result.applied.append(action)

                elif action.action_type == FixActionType.EXECUTE_COMMAND:
                    if execute_commands and action.command:
                        self._execute_command(action.command)
                        result.applied.append(action)
                    else:
                        result.skipped.append(action)
                else:
                    result.skipped.append(action)

            except Exception as e:
                result.failed.append((action, str(e)))

        return result

    def _add_dependency_to_pyproject(self, package: str) -> None:
        """Add a dependency to pyproject.toml [project.dependencies]."""
        pyproject_file = self.root / "pyproject.toml"

        if not pyproject_file.exists():
            content = f'[project]\nname = "{self.root.name}"\nversion = "0.1.0"\ndependencies = [\n    "{package}",\n]\n'
            pyproject_file.write_text(content, encoding="utf-8")
            return

        content = pyproject_file.read_text(encoding="utf-8")

        # Check if dependencies array exists
        dep_match = re.search(r"dependencies\s*=\s*\[(.*?)\]", content, re.DOTALL)
        if dep_match:
            raw_deps = dep_match.group(1)
            # Extract existing dependency strings
            existing_items = re.findall(r'["\']([^"\']+)["\']', raw_deps)

            # Check if package is already declared (e.g. click or click>=8.0)
            pkg_names = [re.split(r"[><=~!^ ]", item)[0].strip() for item in existing_items]
            if package not in pkg_names:
                existing_items.append(package)

            formatted_deps = "\n".join(f'    "{item}",' for item in existing_items)
            new_dep_block = f"dependencies = [\n{formatted_deps}\n]"
            updated = content[: dep_match.start()] + new_dep_block + content[dep_match.end() :]
            pyproject_file.write_text(updated, encoding="utf-8")
        elif "[project]" in content:
            # Insert dependencies array under [project]
            pattern = r"(\[project\][^\[]*)"
            updated = re.sub(
                pattern,
                r'\1dependencies = [\n    "' + package + r'",\n]\n',
                content,
                count=1,
            )
            pyproject_file.write_text(updated, encoding="utf-8")
        else:
            # Append [project] section
            updated = (
                content.rstrip()
                + f'\n\n[project]\nname = "{self.root.name}"\nversion = "0.1.0"\ndependencies = [\n    "{package}",\n]\n'
            )
            pyproject_file.write_text(updated, encoding="utf-8")

    def _remove_dependency_from_pyproject(self, package: str) -> None:
        """Remove a dependency from pyproject.toml [project.dependencies]."""
        pyproject_file = self.root / "pyproject.toml"
        if not pyproject_file.exists():
            return

        content = pyproject_file.read_text(encoding="utf-8")
        dep_match = re.search(r"dependencies\s*=\s*\[(.*?)\]", content, re.DOTALL)
        if dep_match:
            raw_deps = dep_match.group(1)
            existing_items = re.findall(r'["\']([^"\']+)["\']', raw_deps)
            filtered_items = [
                item
                for item in existing_items
                if re.split(r"[><=~!^ ]", item)[0].strip() != package
            ]
            if filtered_items:
                formatted_deps = "\n".join(f'    "{item}",' for item in filtered_items)
                new_dep_block = f"dependencies = [\n{formatted_deps}\n]"
            else:
                new_dep_block = "dependencies = []"
            updated = content[: dep_match.start()] + new_dep_block + content[dep_match.end() :]
            pyproject_file.write_text(updated, encoding="utf-8")

    def _add_dependency_to_requirements(self, package: str) -> None:
        """Add a dependency to requirements.txt."""
        req_file = self.root / "requirements.txt"
        if not req_file.exists():
            req_file.write_text(f"{package}\n", encoding="utf-8")
            return

        content = req_file.read_text(encoding="utf-8")
        lines = [line.strip() for line in content.splitlines()]
        if package not in lines:
            updated = content.rstrip() + f"\n{package}\n"
            req_file.write_text(updated, encoding="utf-8")

    def _remove_dependency_from_requirements(self, package: str) -> None:
        """Remove a dependency from requirements.txt."""
        req_file = self.root / "requirements.txt"
        if not req_file.exists():
            return

        lines = req_file.read_text(encoding="utf-8").splitlines()
        filtered = [line for line in lines if not line.strip().startswith(package)]
        req_file.write_text("\n".join(filtered) + "\n" if filtered else "", encoding="utf-8")

    def _initialize_pyproject_metadata(self, project_name: str) -> None:
        """Initialize standard PEP 621 metadata in pyproject.toml."""
        pyproject_file = self.root / "pyproject.toml"
        default_section = f"""[project]
name = "{project_name}"
version = "0.1.0"
description = "Add project description here"
readme = "README.md"
requires-python = ">=3.10"
dependencies = []
"""
        if not pyproject_file.exists():
            pyproject_file.write_text(default_section, encoding="utf-8")
            return

        content = pyproject_file.read_text(encoding="utf-8")
        if "[project]" not in content:
            updated = default_section + "\n" + content
            pyproject_file.write_text(updated, encoding="utf-8")

    def _execute_command(self, command: str) -> None:
        """Safely execute a suggested remediation shell command in project root."""
        subprocess.run(
            command,
            shell=True,
            cwd=self.root,
            check=True,
            capture_output=True,
        )
