"""Project discovery and context builder."""

from __future__ import annotations

import ast
import configparser
import importlib.metadata
import re
import sys
from dataclasses import dataclass
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
from qv.core.models import Diagnostic, Evidence, Severity, Suggestion

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


@dataclass
class Project:
    """Encapsulates a loaded project's root path, configuration, and discovered context."""

    root: Path
    config: QvConfig
    context: ProjectContext


def load_project(
    root: Path | str = ".",
    config: QvConfig | None = None,
) -> Project:
    """Centralized loader for project root, configuration, and context discovery.

    Guarantees that all CLI commands, analyzers, and engines consume the same
    consistent project root, pyproject.toml configuration, suppressions, exclusions,
    and discovered context.
    """
    project_root = Path(root).resolve()
    if config is None:
        pyproject_path = project_root / "pyproject.toml"
        config = QvConfig.from_pyproject(pyproject_path if pyproject_path.exists() else None)

    discovery = ProjectDiscovery(root=project_root, config=config)
    context = discovery.discover_context()

    return Project(
        root=project_root,
        config=config,
        context=context,
    )


class ProjectDiscovery:
    """Discovers project files, manifests, environment, and source files."""

    def __init__(self, root: Path, config: QvConfig | None = None) -> None:
        self.root = root.resolve()
        self.config = config or QvConfig.from_pyproject(self.root / "pyproject.toml")

    def _is_within_boundary(self, path: Path) -> bool:
        """Check if path securely resides within the project root boundary without escaping via external symlinks."""
        try:
            resolved = path.resolve()
            return resolved.is_relative_to(self.root)
        except (ValueError, RuntimeError, OSError):
            return False

    def discover_context(self) -> ProjectContext:
        """Build and return an immutable ProjectContext."""
        pyproject_path = self.root / "pyproject.toml"
        project_name = self.root.name
        manifest_files: list[Path] = []
        lock_files: list[Path] = []
        dependencies: list[DependencyDeclaration] = []
        discovery_diagnostics: list[Diagnostic] = []

        # 1. Package manager detection & manifest parsing
        package_manager = "pip"

        if (self.root / "uv.lock").exists() and self._is_within_boundary(self.root / "uv.lock"):
            package_manager = "uv"
            lock_files.append(self.root / "uv.lock")
        elif (self.root / "poetry.lock").exists() and self._is_within_boundary(
            self.root / "poetry.lock"
        ):
            package_manager = "poetry"
            lock_files.append(self.root / "poetry.lock")
        elif (self.root / "pdm.lock").exists() and self._is_within_boundary(self.root / "pdm.lock"):
            package_manager = "pdm"
            lock_files.append(self.root / "pdm.lock")
        elif (self.root / "Pipfile.lock").exists() and self._is_within_boundary(
            self.root / "Pipfile.lock"
        ):
            package_manager = "pipenv"
            lock_files.append(self.root / "Pipfile.lock")

        target_python = self.config.target_python

        # Check pyproject.toml
        if pyproject_path.exists() and self._is_within_boundary(pyproject_path):
            manifest_files.append(pyproject_path)
            try:
                with open(pyproject_path, "rb") as f:
                    pyproject_data = tomllib.load(f)

                # Name
                if "project" in pyproject_data and "name" in pyproject_data["project"]:
                    project_name = pyproject_data["project"]["name"]

                # Target Python
                if not target_python and "project" in pyproject_data:
                    target_python = pyproject_data["project"].get("requires-python")

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

                # Optional/extra/dev dependencies (PEP 621)
                for _group, deps in (
                    pyproject_data.get("project", {}).get("optional-dependencies", {}).items()
                ):
                    for dep_str in deps:
                        try:
                            req = Requirement(dep_str)
                            dependencies.append(
                                DependencyDeclaration(
                                    name=req.name,
                                    specifier=str(req.specifier),
                                    source_file=pyproject_path,
                                    is_dev=True,
                                    extras=tuple(req.extras),
                                )
                            )
                        except Exception:
                            pass

                # PEP 735 Dependency Groups (e.g. [dependency-groups] dev = [...], test = [...])
                for _group, deps in pyproject_data.get("dependency-groups", {}).items():
                    if isinstance(deps, list):
                        for dep_item in deps:
                            if isinstance(dep_item, str):
                                try:
                                    req = Requirement(dep_item)
                                    dependencies.append(
                                        DependencyDeclaration(
                                            name=req.name,
                                            specifier=str(req.specifier),
                                            source_file=pyproject_path,
                                            is_dev=True,
                                            extras=tuple(req.extras),
                                        )
                                    )
                                except Exception:
                                    pass

                # Build system requires: [build-system] requires = [...]
                for dep_str in pyproject_data.get("build-system", {}).get("requires", []):
                    try:
                        req = Requirement(dep_str)
                        dependencies.append(
                            DependencyDeclaration(
                                name=req.name,
                                specifier=str(req.specifier),
                                source_file=pyproject_path,
                                is_dev=True,
                                extras=tuple(req.extras),
                            )
                        )
                    except Exception:
                        pass

                # uv dev dependencies: [tool.uv.dev-dependencies] or [tool.uv] dev-dependencies = [...]
                uv_dev_deps = (
                    pyproject_data.get("tool", {}).get("uv", {}).get("dev-dependencies", [])
                )
                if isinstance(uv_dev_deps, list):
                    for dep_str in uv_dev_deps:
                        try:
                            req = Requirement(dep_str)
                            dependencies.append(
                                DependencyDeclaration(
                                    name=req.name,
                                    specifier=str(req.specifier),
                                    source_file=pyproject_path,
                                    is_dev=True,
                                    extras=tuple(req.extras),
                                )
                            )
                        except Exception:
                            pass

                # Poetry style [tool.poetry.dependencies] (production)
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
                            is_dev=False,
                        )
                    )

                # Poetry dev dependencies: [tool.poetry.dev-dependencies] & [tool.poetry.group.<name>.dependencies]
                poetry_dev_deps = (
                    pyproject_data.get("tool", {}).get("poetry", {}).get("dev-dependencies", {})
                )
                for dep_name, dep_val in poetry_dev_deps.items():
                    spec = dep_val if isinstance(dep_val, str) else str(dep_val.get("version", ""))
                    dependencies.append(
                        DependencyDeclaration(
                            name=dep_name,
                            specifier=spec,
                            source_file=pyproject_path,
                            is_dev=True,
                        )
                    )

                poetry_groups = pyproject_data.get("tool", {}).get("poetry", {}).get("group", {})
                for _grp_name, grp_data in poetry_groups.items():
                    if isinstance(grp_data, dict):
                        for dep_name, dep_val in grp_data.get("dependencies", {}).items():
                            spec = (
                                dep_val
                                if isinstance(dep_val, str)
                                else str(dep_val.get("version", ""))
                            )
                            dependencies.append(
                                DependencyDeclaration(
                                    name=dep_name,
                                    specifier=spec,
                                    source_file=pyproject_path,
                                    is_dev=True,
                                )
                            )

                # PDM dev dependencies: [tool.pdm.dev-dependencies]
                pdm_dev_deps = (
                    pyproject_data.get("tool", {}).get("pdm", {}).get("dev-dependencies", {})
                )
                for _grp_name, grp_list in pdm_dev_deps.items():
                    if isinstance(grp_list, list):
                        for dep_str in grp_list:
                            try:
                                req = Requirement(dep_str)
                                dependencies.append(
                                    DependencyDeclaration(
                                        name=req.name,
                                        specifier=str(req.specifier),
                                        source_file=pyproject_path,
                                        is_dev=True,
                                        extras=tuple(req.extras),
                                    )
                                )
                            except Exception:
                                pass
            except Exception:
                pass

        # Check setup.cfg
        setup_cfg_path = self.root / "setup.cfg"
        if (
            setup_cfg_path.exists()
            and setup_cfg_path.is_file()
            and self._is_within_boundary(setup_cfg_path)
        ):
            manifest_files.append(setup_cfg_path)
            try:
                cfg = configparser.ConfigParser()
                cfg.read(setup_cfg_path, encoding="utf-8")
                if "options" in cfg and "install_requires" in cfg["options"]:
                    for req_str in cfg["options"]["install_requires"].strip().splitlines():
                        req_str = re.sub(r"\s+#.*$", "", req_str).strip()
                        if req_str:
                            try:
                                req = Requirement(req_str)
                                dependencies.append(
                                    DependencyDeclaration(
                                        name=req.name,
                                        specifier=str(req.specifier),
                                        source_file=setup_cfg_path,
                                        is_dev=False,
                                        extras=tuple(req.extras),
                                    )
                                )
                            except Exception:
                                pass
                if "options.extras_require" in cfg:
                    for _grp, req_lines in cfg["options.extras_require"].items():
                        for req_str in req_lines.strip().splitlines():
                            req_str = re.sub(r"\s+#.*$", "", req_str).strip()
                            if req_str:
                                try:
                                    req = Requirement(req_str)
                                    dependencies.append(
                                        DependencyDeclaration(
                                            name=req.name,
                                            specifier=str(req.specifier),
                                            source_file=setup_cfg_path,
                                            is_dev=True,
                                            extras=tuple(req.extras),
                                        )
                                    )
                                except Exception:
                                    pass
            except Exception:
                pass

        # Check setup.py
        setup_py_path = self.root / "setup.py"
        if (
            setup_py_path.exists()
            and setup_py_path.is_file()
            and self._is_within_boundary(setup_py_path)
        ):
            if setup_py_path not in manifest_files:
                manifest_files.append(setup_py_path)
            try:
                setup_content = setup_py_path.read_text(encoding="utf-8")
                try:
                    tree = ast.parse(setup_content, filename=str(setup_py_path))
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            for kw in node.keywords:
                                if kw.arg == "install_requires" and isinstance(
                                    kw.value, (ast.List, ast.Tuple, ast.Set)
                                ):
                                    for elt in kw.value.elts:
                                        if isinstance(elt, ast.Constant) and isinstance(
                                            elt.value, str
                                        ):
                                            try:
                                                req = Requirement(elt.value)
                                                dependencies.append(
                                                    DependencyDeclaration(
                                                        name=req.name,
                                                        specifier=str(req.specifier),
                                                        source_file=setup_py_path,
                                                        line_number=getattr(elt, "lineno", None),
                                                        is_dev=False,
                                                        extras=tuple(req.extras),
                                                    )
                                                )
                                            except Exception:
                                                pass
                                elif kw.arg == "extras_require" and isinstance(kw.value, ast.Dict):
                                    for _k, v in zip(kw.value.keys, kw.value.values, strict=False):
                                        if isinstance(v, (ast.List, ast.Tuple, ast.Set)):
                                            for elt in v.elts:
                                                if isinstance(elt, ast.Constant) and isinstance(
                                                    elt.value, str
                                                ):
                                                    try:
                                                        req = Requirement(elt.value)
                                                        dependencies.append(
                                                            DependencyDeclaration(
                                                                name=req.name,
                                                                specifier=str(req.specifier),
                                                                source_file=setup_py_path,
                                                                line_number=getattr(
                                                                    elt, "lineno", None
                                                                ),
                                                                is_dev=True,
                                                                extras=tuple(req.extras),
                                                            )
                                                        )
                                                    except Exception:
                                                        pass
                except Exception:
                    pass
            except Exception:
                pass

        # Check Pipfile
        pipfile_path = self.root / "Pipfile"
        if (
            pipfile_path.exists()
            and pipfile_path.is_file()
            and self._is_within_boundary(pipfile_path)
        ):
            if pipfile_path not in manifest_files:
                manifest_files.append(pipfile_path)
            try:
                with open(pipfile_path, "rb") as f:
                    pipfile_data = tomllib.load(f)
                for dep_name, spec in pipfile_data.get("packages", {}).items():
                    spec_str = (
                        spec
                        if isinstance(spec, str)
                        else str(spec.get("version", ""))
                        if isinstance(spec, dict)
                        else ""
                    )
                    dependencies.append(
                        DependencyDeclaration(
                            name=dep_name,
                            specifier="" if spec_str == "*" else spec_str,
                            source_file=pipfile_path,
                            is_dev=False,
                        )
                    )
                for dep_name, spec in pipfile_data.get("dev-packages", {}).items():
                    spec_str = (
                        spec
                        if isinstance(spec, str)
                        else str(spec.get("version", ""))
                        if isinstance(spec, dict)
                        else ""
                    )
                    dependencies.append(
                        DependencyDeclaration(
                            name=dep_name,
                            specifier="" if spec_str == "*" else spec_str,
                            source_file=pipfile_path,
                            is_dev=True,
                        )
                    )
            except Exception:
                pass

        # Check requirements files & directories
        discovered_req_files: set[Path] = set()

        for pat in (
            "*requirement*.txt",
            "*requirement*.in",
            "requirements*.txt",
            "requirements*.in",
            "reqs*.txt",
            "*-requirements.txt",
            "dev-requirements.txt",
            "test-requirements.txt",
            "constraints.txt",
        ):
            for p in self.root.glob(pat):
                if self._is_within_boundary(p):
                    discovered_req_files.add(p)

        for req_dir_name in ("requirements", "reqs", "deps", "requirements.d"):
            req_dir = self.root / req_dir_name
            if req_dir.is_dir() and self._is_within_boundary(req_dir):
                for ext in ("*.txt", "*.in", "*.pip"):
                    for p in req_dir.rglob(ext):
                        if self._is_within_boundary(p):
                            discovered_req_files.add(p)

        for req_path in sorted(discovered_req_files):
            if req_path.is_file():
                if req_path not in manifest_files:
                    manifest_files.append(req_path)
                p_str = str(req_path).lower()
                is_dev = any(
                    k in p_str
                    for k in (
                        "dev",
                        "test",
                        "doc",
                        "lint",
                        "type",
                        "ci",
                        "bench",
                        "local",
                        "stage",
                    )
                )
                try:
                    with open(req_path, encoding="utf-8") as f:
                        for line_idx, raw_line in enumerate(f, 1):
                            line = re.sub(r"\s+#.*$", "", raw_line).strip()
                            if not line or line.startswith("#"):
                                continue
                            if line.startswith("-"):
                                if line.startswith("-e ") or line.startswith("--editable "):
                                    egg_match = re.search(r"#egg=([\w\-_]+)", line)
                                    if egg_match:
                                        try:
                                            req = Requirement(egg_match.group(1))
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
        project_site_packages: list[str] = []
        for venv_name in (".venv", "venv", "env", ".env"):
            venv_dir = self.root / venv_name
            if venv_dir.is_dir() and self._is_within_boundary(venv_dir):
                win_sp = venv_dir / "Lib" / "site-packages"
                if win_sp.is_dir():
                    project_site_packages.append(str(win_sp))
                lib_dir = venv_dir / "lib"
                if lib_dir.is_dir():
                    for py_dir in lib_dir.glob("python*"):
                        sp = py_dir / "site-packages"
                        if sp.is_dir():
                            project_site_packages.append(str(sp))

        try:
            dists = (
                importlib.metadata.distributions(path=project_site_packages)
                if project_site_packages
                else importlib.metadata.distributions()
            )
            for dist in dists:
                name = dist.metadata["Name"]
                if not name:
                    continue
                requires = dist.requires or []
                requires_python = (
                    dist.metadata["Requires-Python"] if "Requires-Python" in dist.metadata else None
                )
                installed_packages[name.lower()] = InstalledDistribution(
                    name=name,
                    version=dist.version,
                    location=str(dist.locate_file("")),
                    requires=tuple(requires),
                    requires_python=requires_python,
                )
        except Exception:
            pass

        # 4. Source file discovery & AST import extraction
        source_files: list[SourceFile] = []
        imports: list[ImportRecord] = []

        exclude_patterns = set(self.config.paths.exclude)
        for py_path in self.root.rglob("*.py"):
            if not self._is_within_boundary(py_path):
                continue

            rel_path = py_path.relative_to(self.root)
            # Check exclusions
            parts = rel_path.parts
            if any(part in exclude_patterns or part.startswith(".") for part in parts):
                continue

            try:
                content = py_path.read_text(encoding="utf-8")
                is_init = py_path.name == "__init__.py"
                # Compute logical module name (strip 'src' prefix if using standard src layout)
                mod_parts = list(rel_path.with_suffix("").parts)
                if mod_parts and mod_parts[0] == "src" and len(mod_parts) > 1:
                    mod_parts = mod_parts[1:]
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

                # Base package name for relative import resolution
                file_pkg_parts = mod_parts if is_init else mod_parts[:-1]

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
                                        level=0,
                                        resolved_module=alias.name,
                                    )
                                )
                        elif isinstance(node, ast.ImportFrom):
                            mod = node.module or ""
                            level = node.level or 0
                            is_rel = level > 0
                            symbols = tuple(alias.name for alias in node.names)

                            resolved_mod: str | None = mod
                            if is_rel:
                                if level == 1:
                                    base_pkg = ".".join(file_pkg_parts)
                                else:
                                    cutoff = len(file_pkg_parts) - (level - 1)
                                    base_pkg = (
                                        ".".join(file_pkg_parts[:cutoff])
                                        if cutoff >= 0 and file_pkg_parts
                                        else ""
                                    )

                                if mod:
                                    resolved_mod = f"{base_pkg}.{mod}" if base_pkg else mod
                                else:
                                    resolved_mod = base_pkg if base_pkg else None

                            imports.append(
                                ImportRecord(
                                    module_name=mod,
                                    source_file=py_path,
                                    line_number=node.lineno,
                                    is_relative=is_rel,
                                    imported_symbols=symbols,
                                    level=level,
                                    resolved_module=resolved_mod,
                                )
                            )
                except SyntaxError as exc:
                    rel_p = str(rel_path).replace("\\", "/")
                    discovery_diagnostics.append(
                        Diagnostic(
                            id="DISC-002",
                            severity=Severity.WARNING,
                            category="discovery",
                            title=f"Python syntax error in {py_path.name}",
                            message=f"Syntax error parsing '{rel_p}' at line {exc.lineno}: {exc.msg}",
                            file=rel_p,
                            line=exc.lineno,
                            column=exc.offset,
                            evidence=[
                                Evidence(
                                    fact=f"SyntaxError: {exc.msg} in {rel_p}:{exc.lineno}",
                                    source="ProjectDiscovery",
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description=f"Fix Python syntax error in '{rel_p}' at line {exc.lineno}.",
                                    is_safe=False,
                                )
                            ],
                        )
                    )
            except Exception as exc:
                rel_p = str(rel_path).replace("\\", "/")
                discovery_diagnostics.append(
                    Diagnostic(
                        id="DISC-001",
                        severity=Severity.WARNING,
                        category="discovery",
                        title=f"Unreadable source file: {py_path.name}",
                        message=f"Could not read source file '{rel_p}': {exc}",
                        file=rel_p,
                        evidence=[
                            Evidence(
                                fact=f"Failed to read file: {py_path} ({type(exc).__name__}: {exc})",
                                source="ProjectDiscovery",
                            )
                        ],
                        suggestions=[
                            Suggestion(
                                description=f"Check file permissions and encoding for '{rel_p}'.",
                                is_safe=False,
                            )
                        ],
                    )
                )

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
            discovery_diagnostics=tuple(discovery_diagnostics),
            config={
                "target_python": target_python,
                "offline": self.config.offline,
                "ignored_dependencies": self.config.ignored_dependencies,
            },
        )

    def _discover_docker(self) -> DockerConfig:
        dockerfile = self.root / "Dockerfile"
        if not dockerfile.exists() or not self._is_within_boundary(dockerfile):
            alt_dockerfile = self.root / "docker" / "Dockerfile"
            if alt_dockerfile.exists() and self._is_within_boundary(alt_dockerfile):
                dockerfile = alt_dockerfile
            else:
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

        dockerignore = self.root / ".dockerignore"
        has_dockerignore = dockerignore.exists() and self._is_within_boundary(dockerignore)

        compose_files: list[Path] = []
        for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            cfile = self.root / name
            if cfile.exists() and self._is_within_boundary(cfile):
                compose_files.append(cfile)

        return DockerConfig(
            has_dockerfile=True,
            dockerfile_path=dockerfile,
            base_image=base_image,
            base_python_version=base_python,
            has_dockerignore=has_dockerignore,
            dockerignore_path=dockerignore if has_dockerignore else None,
            compose_files=tuple(compose_files),
        )

    def _discover_ci(self) -> CIConfig:
        gh_workflows = self.root / ".github" / "workflows"
        workflow_files: list[Path] = []
        matrix_versions: list[str] = []

        if (
            gh_workflows.exists()
            and gh_workflows.is_dir()
            and self._is_within_boundary(gh_workflows)
        ):
            for f in gh_workflows.glob("*.yml"):
                if self._is_within_boundary(f):
                    workflow_files.append(f)
            for f in gh_workflows.glob("*.yaml"):
                if self._is_within_boundary(f):
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
