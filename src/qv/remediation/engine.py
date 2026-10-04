"""Core remediation engine implementing automated and safe fixes."""

from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path

import tomlkit
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from qv.core.models import ScanResult
from qv.remediation.models import FixAction, FixActionType, FixPlan, FixResult


def _get_canonical_package_name(spec: str) -> str | None:
    """Extract canonical package name from requirement specification string or requirements.txt line.

    Returns None if the spec is a comment, flag, option, or non-package line.
    """
    clean_spec = spec.strip()
    if not clean_spec or clean_spec.startswith("#"):
        return None

    # Ignore pip options / flags (e.g. -r, -c, -f, --index-url, etc.) unless editable with egg
    if clean_spec.startswith("-"):
        if clean_spec.startswith("-e ") or clean_spec.startswith("--editable "):
            egg_match = re.search(r"#egg=([\w\-_.]+)", clean_spec)
            if egg_match:
                return canonicalize_name(egg_match.group(1))
        return None

    # Strip inline comments
    clean_no_comment = re.sub(r"\s+#.*$", "", clean_spec).strip()
    # Strip pip line options (e.g. --hash=sha256:...)
    clean_no_opts = re.sub(r"\s+--\S+.*$", "", clean_no_comment).strip()

    if not clean_no_opts:
        return None

    try:
        return canonicalize_name(Requirement(clean_no_opts).name)
    except Exception:
        match = re.match(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)", clean_no_opts)
        if match:
            return canonicalize_name(match.group(1))
        return None


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

            # Handle DEP-003: No direct import detected
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
                    if diag.file:
                        try:
                            diag_path = Path(diag.file)
                            if diag_path.is_absolute() and diag_path.is_relative_to(self.root):
                                rel = str(diag_path.relative_to(self.root)).replace("\\", "/")
                                if rel.endswith((".toml", ".txt", ".in")):
                                    target_file = rel
                            elif not diag_path.is_absolute() and (self.root / diag_path).exists():
                                rel = str(diag_path).replace("\\", "/")
                                if rel.endswith((".toml", ".txt", ".in")):
                                    target_file = rel
                        except Exception:
                            pass
                    actions.append(
                        FixAction(
                            id=f"fix-dep-003-{idx}-{pkg}",
                            rule_id="DEP-003",
                            action_type=FixActionType.REMOVE_DEPENDENCY,
                            description=f"Remove unimported dependency '{pkg}' from {target_file}",
                            target_file=target_file,
                            diff=f"- {pkg}",
                            metadata={"package": pkg},
                            is_safe=False,
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
                    if sugg.executable or sugg.command:
                        executable = sugg.executable
                        args = list(sugg.args) if sugg.args else []
                        if not executable and sugg.command:
                            parsed = shlex.split(sugg.command)
                            if parsed:
                                executable = parsed[0]
                                args = parsed[1:]

                        if executable:
                            actions.append(
                                FixAction(
                                    id=f"fix-cmd-{diag.id}-{idx}-{s_idx}",
                                    rule_id=diag.id,
                                    action_type=FixActionType.EXECUTE_COMMAND,
                                    description=sugg.description,
                                    executable=executable,
                                    args=args,
                                    command=sugg.command or f"{executable} {' '.join(args)}",
                                    is_safe=sugg.is_safe,
                                )
                            )

        return FixPlan(project_path=str(self.root), actions=actions)

    def apply_plan(
        self,
        plan: FixPlan,
        dry_run: bool = False,
        execute_commands: bool = False,
        only_safe: bool = False,
    ) -> FixResult:
        """Apply the fixes in the plan to project files."""
        result = FixResult(project_path=plan.project_path, dry_run=dry_run)

        for action in plan.actions:
            if only_safe and not action.is_safe:
                result.skipped.append(action)
                continue

            if dry_run:
                result.applied.append(action)
                continue

            try:
                if action.action_type == FixActionType.ADD_DEPENDENCY:
                    pkg = action.metadata.get("package")
                    if pkg and action.target_file == "pyproject.toml":
                        self._add_dependency_to_pyproject(pkg)
                        result.applied.append(action)
                    elif pkg and action.target_file:
                        self._add_dependency_to_requirements(pkg, target_file=action.target_file)
                        result.applied.append(action)
                    else:
                        result.skipped.append(action)

                elif action.action_type == FixActionType.REMOVE_DEPENDENCY:
                    pkg = action.metadata.get("package")
                    if pkg and action.target_file == "pyproject.toml":
                        self._remove_dependency_from_pyproject(pkg)
                        result.applied.append(action)
                    elif pkg and action.target_file:
                        self._remove_dependency_from_requirements(
                            pkg, target_file=action.target_file
                        )
                        result.applied.append(action)
                    else:
                        result.skipped.append(action)

                elif action.action_type == FixActionType.UPDATE_METADATA:
                    proj_name = action.metadata.get("project_name", self.root.name)
                    self._initialize_pyproject_metadata(proj_name)
                    result.applied.append(action)

                elif action.action_type == FixActionType.EXECUTE_COMMAND:
                    if execute_commands and (action.executable or action.command):
                        self._execute_command(action)
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
            doc = tomlkit.document()
            project = tomlkit.table()
            project["name"] = self.root.name
            project["version"] = "0.1.0"
            deps = tomlkit.array()
            deps.append(package)
            deps.multiline(True)
            project["dependencies"] = deps
            doc["project"] = project
            pyproject_file.write_text(tomlkit.dumps(doc), encoding="utf-8")
            return

        content = pyproject_file.read_text(encoding="utf-8")
        doc = tomlkit.parse(content)

        pkg_canonical = _get_canonical_package_name(package)

        if "project" not in doc:
            project = tomlkit.table()
            project["name"] = self.root.name
            project["version"] = "0.1.0"
            deps = tomlkit.array()
            deps.append(package)
            deps.multiline(True)
            project["dependencies"] = deps
            doc["project"] = project
        else:
            project = doc["project"]
            if not isinstance(project, dict):
                project = tomlkit.table()
                doc["project"] = project

            if "dependencies" not in project:
                deps = tomlkit.array()
                deps.append(package)
                deps.multiline(True)
                project["dependencies"] = deps
            else:
                existing_deps = project["dependencies"]
                existing_canonical_names = {
                    _get_canonical_package_name(str(item)) for item in existing_deps
                }
                if pkg_canonical and pkg_canonical not in existing_canonical_names:
                    existing_deps.append(package)

        pyproject_file.write_text(tomlkit.dumps(doc), encoding="utf-8")

    def _remove_dependency_from_pyproject(self, package: str) -> None:
        """Remove a dependency from pyproject.toml [project.dependencies]."""
        pyproject_file = self.root / "pyproject.toml"
        if not pyproject_file.exists():
            return

        content = pyproject_file.read_text(encoding="utf-8")
        doc = tomlkit.parse(content)

        if "project" not in doc or not isinstance(doc["project"], dict):
            return

        project = doc["project"]
        if "dependencies" not in project:
            return

        existing_deps = project["dependencies"]
        target_canonical = _get_canonical_package_name(package)
        if not target_canonical:
            return

        indices_to_remove = []
        for i, item in enumerate(existing_deps):
            item_canonical = _get_canonical_package_name(str(item))
            if item_canonical and item_canonical == target_canonical:
                indices_to_remove.append(i)

        if indices_to_remove:
            for i in reversed(indices_to_remove):
                del existing_deps[i]
            pyproject_file.write_text(tomlkit.dumps(doc), encoding="utf-8")

    def _add_dependency_to_requirements(
        self, package: str, target_file: str = "requirements.txt"
    ) -> None:
        """Add a dependency to a requirements file."""
        req_file = self.root / target_file
        target_canonical = _get_canonical_package_name(package)
        if not target_canonical:
            return

        if not req_file.exists():
            req_file.parent.mkdir(parents=True, exist_ok=True)
            req_file.write_text(f"{package}\n", encoding="utf-8")
            return

        content = req_file.read_text(encoding="utf-8")
        lines = content.splitlines()
        canonical_existing = {
            _get_canonical_package_name(line)
            for line in lines
            if line.strip() and not line.strip().startswith("#")
        }
        if target_canonical not in canonical_existing:
            updated = content.rstrip() + f"\n{package}\n"
            req_file.write_text(updated, encoding="utf-8")

    def _remove_dependency_from_requirements(
        self, package: str, target_file: str = "requirements.txt"
    ) -> None:
        """Remove a dependency from a requirements file."""
        req_file = self.root / target_file
        if not req_file.exists():
            return

        lines = req_file.read_text(encoding="utf-8").splitlines()
        target_canonical = _get_canonical_package_name(package)
        if not target_canonical:
            return

        filtered: list[str] = []
        for line in lines:
            extracted = _get_canonical_package_name(line)
            if extracted is None or extracted != target_canonical:
                filtered.append(line)

        req_file.write_text("\n".join(filtered) + "\n" if filtered else "", encoding="utf-8")

    def _initialize_pyproject_metadata(self, project_name: str) -> None:
        """Initialize standard PEP 621 metadata in pyproject.toml."""
        pyproject_file = self.root / "pyproject.toml"

        if not pyproject_file.exists():
            doc = tomlkit.document()
            project = tomlkit.table()
            project["name"] = project_name
            project["version"] = "0.1.0"
            project["description"] = "Add project description here"
            project["readme"] = "README.md"
            project["requires-python"] = ">=3.10"
            project["dependencies"] = tomlkit.array()
            doc["project"] = project
            pyproject_file.write_text(tomlkit.dumps(doc), encoding="utf-8")
            return

        content = pyproject_file.read_text(encoding="utf-8")
        doc = tomlkit.parse(content)
        if "project" not in doc:
            project = tomlkit.table()
            project["name"] = project_name
            project["version"] = "0.1.0"
            project["description"] = "Add project description here"
            project["readme"] = "README.md"
            project["requires-python"] = ">=3.10"
            project["dependencies"] = tomlkit.array()
            doc["project"] = project
            pyproject_file.write_text(tomlkit.dumps(doc), encoding="utf-8")

    ALLOWED_PACKAGE_MANAGERS: set[str] = {
        "uv",
        "poetry",
        "pip",
        "pdm",
        "pipenv",
        "flit",
        "hatch",
        "python",
        "python3",
    }

    def _execute_command(self, action: FixAction | str) -> subprocess.CompletedProcess[bytes]:
        """Safely execute a suggested remediation command using structured arguments."""
        if isinstance(action, str):
            parsed = shlex.split(action)
            if not parsed:
                raise ValueError("Remediation command cannot be empty.")
            executable = parsed[0]
            args = parsed[1:]
        else:
            executable = action.executable
            args = list(action.args) if action.args else []
            if not executable and action.command:
                parsed = shlex.split(action.command)
                if parsed:
                    executable = parsed[0]
                    args = parsed[1:]

        if not executable or not executable.strip():
            raise ValueError("Remediation command executable cannot be empty.")

        executable = executable.strip()
        exe_path = Path(executable)
        exe_name = exe_path.name.lower()
        if exe_name.endswith(".exe"):
            exe_name = exe_name[:-4]

        if exe_name not in self.ALLOWED_PACKAGE_MANAGERS:
            raise ValueError(
                f"Executable '{executable}' is not an allowed remediation command. "
                f"Allowed executables: {', '.join(sorted(self.ALLOWED_PACKAGE_MANAGERS))}"
            )

        cmd_list = [executable, *args]
        return subprocess.run(
            cmd_list,
            shell=False,
            cwd=self.root,
            check=True,
            capture_output=True,
        )
