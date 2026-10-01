"""Lockfile and pinned requirement parser for dependency security audits."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from packaging.requirements import Requirement

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from qv.core.context import ProjectContext


@dataclass(frozen=True)
class ResolvedPackage:
    """A resolved package with exact version from lockfile or environment."""

    name: str
    version: str
    source_file: Path | None = None
    is_direct: bool = False


class LockfileParser:
    """Extracts resolved packages and exact pinned versions from lockfiles or environment."""

    @classmethod
    def parse_context(cls, context: ProjectContext) -> list[ResolvedPackage]:
        """Parse all available lockfiles or fallback to installed packages."""
        packages: dict[str, ResolvedPackage] = {}
        direct_names = {d.name.lower() for d in context.dependencies}

        # 1. Check uv.lock
        uv_lock = context.project_root / "uv.lock"
        if uv_lock.exists():
            for pkg in cls.parse_uv_lock(uv_lock, direct_names):
                packages[pkg.name.lower()] = pkg

        # 2. Check poetry.lock
        poetry_lock = context.project_root / "poetry.lock"
        if poetry_lock.exists() and not packages:
            for pkg in cls.parse_poetry_lock(poetry_lock, direct_names):
                packages[pkg.name.lower()] = pkg

        # 3. Check Pipfile.lock
        pipfile_lock = context.project_root / "Pipfile.lock"
        if pipfile_lock.exists() and not packages:
            for pkg in cls.parse_pipfile_lock(pipfile_lock, direct_names):
                packages[pkg.name.lower()] = pkg

        # 4. Check requirements files with exact pinned versions (==)
        for req_path in context.manifest_files:
            if req_path.suffix == ".txt" and req_path.exists():
                for pkg in cls.parse_requirements_txt(req_path, direct_names):
                    if pkg.name.lower() not in packages:
                        packages[pkg.name.lower()] = pkg

        # 5. Fallback to installed distributions in the environment
        if not packages and context.installed_packages:
            for name, dist in context.installed_packages.items():
                packages[name.lower()] = ResolvedPackage(
                    name=dist.name,
                    version=dist.version,
                    source_file=None,
                    is_direct=name.lower() in direct_names,
                )

        return list(packages.values())

    @classmethod
    def parse_uv_lock(cls, path: Path, direct_names: set[str]) -> list[ResolvedPackage]:
        """Parse uv.lock (TOML format)."""
        packages: list[ResolvedPackage] = []
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
            for pkg in data.get("package", []):
                name = pkg.get("name")
                version = pkg.get("version")
                if name and version:
                    packages.append(
                        ResolvedPackage(
                            name=name,
                            version=str(version),
                            source_file=path,
                            is_direct=name.lower() in direct_names,
                        )
                    )
        except Exception:
            pass
        return packages

    @classmethod
    def parse_poetry_lock(cls, path: Path, direct_names: set[str]) -> list[ResolvedPackage]:
        """Parse poetry.lock (TOML format)."""
        packages: list[ResolvedPackage] = []
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
            for pkg in data.get("package", []):
                name = pkg.get("name")
                version = pkg.get("version")
                if name and version:
                    packages.append(
                        ResolvedPackage(
                            name=name,
                            version=str(version),
                            source_file=path,
                            is_direct=name.lower() in direct_names,
                        )
                    )
        except Exception:
            pass
        return packages

    @classmethod
    def parse_pipfile_lock(cls, path: Path, direct_names: set[str]) -> list[ResolvedPackage]:
        """Parse Pipfile.lock (JSON format)."""
        packages: list[ResolvedPackage] = []
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            for section in ("default", "develop"):
                for name, info in data.get(section, {}).items():
                    ver_raw = info.get("version", "")
                    ver_clean = re.sub(r"^==\s*", "", ver_raw).strip()
                    if ver_clean:
                        packages.append(
                            ResolvedPackage(
                                name=name,
                                version=ver_clean,
                                source_file=path,
                                is_direct=name.lower() in direct_names,
                            )
                        )
        except Exception:
            pass
        return packages

    @classmethod
    def parse_requirements_txt(cls, path: Path, direct_names: set[str]) -> list[ResolvedPackage]:
        """Parse requirements.txt lines with exact '==' pins."""
        packages: list[ResolvedPackage] = []
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    try:
                        req = Requirement(line)
                        specs = list(req.specifier)
                        if len(specs) == 1 and specs[0].operator == "==":
                            packages.append(
                                ResolvedPackage(
                                    name=req.name,
                                    version=specs[0].version,
                                    source_file=path,
                                    is_direct=req.name.lower() in direct_names,
                                )
                            )
                    except Exception:
                        pass
        except Exception:
            pass
        return packages
