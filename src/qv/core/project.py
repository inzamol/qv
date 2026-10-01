"""Project discovery and context builder."""

from __future__ import annotations

import ast
import importlib.metadata
import re
import sys
from pathlib import Path

from packaging.requirements import Requirement

from qv.core.config import QvConfig
from qv.core.context import (
    CIConfig,
    DependencyDeclaration,
    DockerConfig,
    ImportRecord,
    InstalledDistribution,
    ProjectContext,
    PythonRuntime,
    SourceFile,
)

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


class ProjectDiscovery:
    """Discovers project files, manifests, environment, and source files."""

    def __init__(self, root: Path, config: QvConfig | None = None) -> None:
        self.root = root.resolve()
        self.config = config or QvConfig.from_pyproject(self.root / "pyproject.toml")

    def discover_context(self) -> ProjectContext:
        """Build and return an immutable ProjectContext."""
        pyproject_path = self.root / "pyproject.toml"
        project_name = self.root.name
        manifest_files: list[Path] = []
        lock_files: list[Path] = []
        dependencies: list[DependencyDeclaration] = []

        # 1. Package manager detection & manifest parsing
        package_manager = "pip"

        if (self.root / "uv.lock").exists():
            package_manager = "uv"
            lock_files.append(self.root / "uv.lock")
        elif (self.root / "poetry.lock").exists():
            package_manager = "poetry"
            lock_files.append(self.root / "poetry.lock")
        elif (self.root / "pdm.lock").exists():
            package_manager = "pdm"
            lock_files.append(self.root / "pdm.lock")
        elif (self.root / "Pipfile.lock").exists():
            package_manager = "pipenv"
            lock_files.append(self.root / "Pipfile.lock")

        # Check pyproject.toml
        if pyproject_path.exists():
            manifest_files.append(pyproject_path)
            try:
                with open(pyproject_path, "rb") as f:
                    pyproject_data = tomllib.load(f)

                # Name
                if "project" in pyproject_data and "name" in pyproject_data["project"]:
                    project_name = pyproject_data["project"]["name"]

                # Dependencies from [project.dependencies]
                for dep_str in pyproject_data.get("project", {}).get("dependencies", []):
                    try:
                        req = Requirement(dep_str)
                        dependencies.append(
                            DependencyDeclaration(
                                name=req.name,
                                specifier=str(req.specifier),
                                source_file=pyproject_path,
                                extras=tuple(req.extras),
                            )
                        )
                    except Exception:
                        pass

                # Optional/dev dependencies
                for group, deps in (
                    pyproject_data.get("project", {}).get("optional-dependencies", {}).items()
                ):
                    is_dev = group in ("dev", "test", "lint")
                    for dep_str in deps:
                        try:
                            req = Requirement(dep_str)
                            dependencies.append(
                                DependencyDeclaration(
                                    name=req.name,
                                    specifier=str(req.specifier),
                                    source_file=pyproject_path,
                                    is_dev=is_dev,
                                    extras=tuple(req.extras),
                                )
                            )
                        except Exception:
                            pass

                # Poetry style [tool.poetry.dependencies]
                poetry_deps = (
                    pyproject_data.get("tool", {}).get("poetry", {}).get("dependencies", {})
                )
                for dep_name, dep_val in poetry_deps.items():
                    if dep_name.lower() == "python":
                        continue
                    spec = dep_val if isinstance(dep_val, str) else str(dep_val.get("version", ""))
                    dependencies.append(
                        DependencyDeclaration(
                            name=dep_name,
                            specifier=spec,
                            source_file=pyproject_path,
                        )
                    )
            except Exception:
                pass

        # Check requirements files
        req_candidates = [
            self.root / "requirements.txt",
            self.root / "requirements-dev.txt",
            self.root / "requirements" / "base.txt",
            self.root / "requirements" / "dev.txt",
            self.root / "requirements" / "prod.txt",
        ]
        for req_path in req_candidates:
            if req_path.exists():
                manifest_files.append(req_path)
                is_dev = "dev" in req_path.name.lower()
                try:
                    with open(req_path, encoding="utf-8") as f:
                        for line_idx, line in enumerate(f, 1):
                            line = line.strip()
                            if not line or line.startswith("#") or line.startswith("-"):
                                continue
                            try:
                                req = Requirement(line)
                                dependencies.append(
                                    DependencyDeclaration(
                                        name=req.name,
                                        specifier=str(req.specifier),
                                        source_file=req_path,
                                        line_number=line_idx,
                                        is_dev=is_dev,
                                        extras=tuple(req.extras),
                                    )
                                )
                            except Exception:
                                pass
                except Exception:
                    pass

        # 2. Python runtime detection
        is_venv = hasattr(sys, "real_prefix") or (
            hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
        )
        runtime = PythonRuntime(
            version_str=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            major=sys.version_info.major,
            minor=sys.version_info.minor,
            micro=sys.version_info.micro,
            executable=sys.executable,
            is_virtualenv=is_venv,
            virtualenv_path=Path(sys.prefix) if is_venv else None,
        )

        # 3. Installed packages collection
        installed_packages: dict[str, InstalledDistribution] = {}
        try:
            for dist in importlib.metadata.distributions():
                name = dist.metadata["Name"]
                if not name:
                    continue
                requires = dist.requires or []
                installed_packages[name.lower()] = InstalledDistribution(
                    name=name,
                    version=dist.version,
                    location=str(dist.locate_file("")),
                    requires=tuple(requires),
                )
        except Exception:
            pass

        # 4. Source file discovery & AST import extraction
        source_files: list[SourceFile] = []
        imports: list[ImportRecord] = []

        exclude_patterns = set(self.config.paths.exclude)
        for py_path in self.root.rglob("*.py"):
            rel_path = py_path.relative_to(self.root)
            # Check exclusions
            parts = rel_path.parts
            if any(part in exclude_patterns or part.startswith(".") for part in parts):
                continue

            try:
                content = py_path.read_text(encoding="utf-8")
                is_init = py_path.name == "__init__.py"
                # Compute logical module name
                mod_parts = list(rel_path.with_suffix("").parts)
                if is_init:
                    mod_parts = mod_parts[:-1]
                module_name = ".".join(mod_parts)

                source_file = SourceFile(
                    path=py_path,
                    relative_path=rel_path,
                    content=content,
                    is_init=is_init,
                    module_name=module_name,
                )
                source_files.append(source_file)

                # Parse AST
                try:
                    tree = ast.parse(content, filename=str(py_path))
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                imports.append(
                                    ImportRecord(
                                        module_name=alias.name,
                                        source_file=py_path,
                                        line_number=node.lineno,
                                        is_relative=False,
                                    )
                                )
                        elif isinstance(node, ast.ImportFrom):
                            mod = node.module or ""
                            is_rel = node.level > 0
                            symbols = tuple(alias.name for alias in node.names)
                            imports.append(
                                ImportRecord(
                                    module_name=mod,
                                    source_file=py_path,
                                    line_number=node.lineno,
                                    is_relative=is_rel,
                                    imported_symbols=symbols,
                                )
                            )
                except SyntaxError:
                    pass
            except Exception:
                pass

        # 5. Docker discovery
        docker_config = self._discover_docker()

        # 6. CI discovery
        ci_config = self._discover_ci()

        return ProjectContext(
            project_root=self.root,
            project_name=project_name,
            python_runtime=runtime,
            package_manager=package_manager,
            manifest_files=tuple(manifest_files),
            lock_files=tuple(lock_files),
            dependencies=tuple(dependencies),
            installed_packages=installed_packages,
            source_files=tuple(source_files),
            imports=tuple(imports),
            docker=docker_config,
            ci=ci_config,
        )

    def _discover_docker(self) -> DockerConfig:
        dockerfile = self.root / "Dockerfile"
        if not dockerfile.exists():
            return DockerConfig(has_dockerfile=False)

        base_image = None
        base_python = None
        try:
            content = dockerfile.read_text(encoding="utf-8")
            from_match = re.search(r"^FROM\s+([^\s]+)", content, re.MULTILINE | re.IGNORECASE)
            if from_match:
                base_image = from_match.group(1)
                py_match = re.search(r"python:?([0-9]+\.[0-9]+)", base_image, re.IGNORECASE)
                if py_match:
                    base_python = py_match.group(1)
        except Exception:
            pass

        return DockerConfig(
            has_dockerfile=True,
            dockerfile_path=dockerfile,
            base_image=base_image,
            base_python_version=base_python,
        )

    def _discover_ci(self) -> CIConfig:
        gh_workflows = self.root / ".github" / "workflows"
        workflow_files: list[Path] = []
        matrix_versions: list[str] = []

        if gh_workflows.exists() and gh_workflows.is_dir():
            for f in gh_workflows.glob("*.yml"):
                workflow_files.append(f)
            for f in gh_workflows.glob("*.yaml"):
                workflow_files.append(f)

            # Look for python-version in workflow files
            for wf in workflow_files:
                try:
                    text = wf.read_text(encoding="utf-8")
                    found_versions = re.findall(r'["\']?3\.\d+["\']?', text)
                    for v in found_versions:
                        clean_v = v.strip("\"'")
                        if clean_v not in matrix_versions:
                            matrix_versions.append(clean_v)
                except Exception:
                    pass

            return CIConfig(
                has_ci=True,
                provider="github_actions",
                workflow_files=tuple(workflow_files),
                matrix_python_versions=tuple(matrix_versions),
            )

        return CIConfig(has_ci=False)
