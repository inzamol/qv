"""Docker analyzer implementing DOC-001 through DOC-014."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from qv.core.context import ProjectContext
from qv.core.models import Diagnostic, Evidence, Suggestion
from qv.rules.registry import get_rule_definition


@dataclass
class DockerInstruction:
    """Parsed Dockerfile instruction with line number and text."""

    name: str
    args: str
    line_number: int
    raw_text: str


WEB_SERVER_KEYWORDS = (
    "uvicorn",
    "gunicorn",
    "fastapi",
    "flask",
    "daphne",
    "hypercorn",
    "granian",
    "waitress",
    "runserver",
    "aiohttp",
)


class DockerAnalyzer:
    """Analyzes Dockerfiles and container configuration for caching, security, and best practices."""

    id = "docker"
    name = "Docker Analyzer"
    description = (
        "Checks Dockerfiles for layer caching, root execution, unpinned base images, "
        "missing .dockerignore, security risks, and Python runtime container best practices."
    )
    rules: tuple[str, ...] = (
        "DOC-001",
        "DOC-002",
        "DOC-003",
        "DOC-004",
        "DOC-005",
        "DOC-006",
        "DOC-007",
        "DOC-008",
        "DOC-009",
        "DOC-010",
        "DOC-011",
        "DOC-012",
        "DOC-013",
        "DOC-014",
    )

    def analyze(self, context: ProjectContext) -> list[Diagnostic]:
        diagnostics: list[Diagnostic] = []

        if not context.docker.has_dockerfile or not context.docker.dockerfile_path:
            return diagnostics

        dockerfile_path = context.docker.dockerfile_path
        try:
            content = dockerfile_path.read_text(encoding="utf-8")
        except Exception:
            return diagnostics

        instructions = self._parse_instructions(content)
        if not instructions:
            return diagnostics

        stages = self._group_into_stages(instructions)

        # 1. Project/File-level checks
        diagnostics.extend(self._check_missing_dockerignore(context, dockerfile_path))
        diagnostics.extend(self._check_python_unbuffered(instructions, dockerfile_path))
        diagnostics.extend(self._check_dont_write_bytecode(instructions, dockerfile_path))
        diagnostics.extend(self._check_healthcheck(instructions, dockerfile_path))
        diagnostics.extend(self._check_web_server_expose(instructions, dockerfile_path))

        # 2. Stage-by-stage and instruction-level checks
        for stage_idx, stage_instructions in enumerate(stages):
            is_final_stage = stage_idx == len(stages) - 1
            diagnostics.extend(self._check_layer_caching(stage_instructions, dockerfile_path))
            diagnostics.extend(
                self._check_unpinned_base_image(
                    stage_instructions, dockerfile_path, stages, stage_idx
                )
            )
            diagnostics.extend(self._check_pip_cache_flag(stage_instructions, dockerfile_path))
            diagnostics.extend(self._check_sensitive_copies(stage_instructions, dockerfile_path))
            diagnostics.extend(
                self._check_deprecated_maintainer(stage_instructions, dockerfile_path)
            )
            diagnostics.extend(self._check_sudo_usage(stage_instructions, dockerfile_path))
            diagnostics.extend(self._check_apt_cleanup(stage_instructions, dockerfile_path))
            diagnostics.extend(self._check_add_usage(stage_instructions, dockerfile_path))

            if is_final_stage:
                diagnostics.extend(
                    self._check_root_user_execution(stage_instructions, dockerfile_path)
                )

        return diagnostics

    def _parse_instructions(self, content: str) -> list[DockerInstruction]:
        """Parse Dockerfile content into structured instructions respecting line continuations."""
        instructions: list[DockerInstruction] = []
        lines = content.splitlines()

        current_inst_name: str | None = None
        current_args: list[str] = []
        current_start_line = 1
        in_continuation = False

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Ignore empty lines and pure comments outside continuations
            if not in_continuation and (not stripped or stripped.startswith("#")):
                continue

            if in_continuation:
                if stripped.endswith("\\"):
                    current_args.append(stripped[:-1].strip())
                else:
                    current_args.append(stripped)
                    if current_inst_name:
                        instructions.append(
                            DockerInstruction(
                                name=current_inst_name,
                                args=" ".join(current_args),
                                line_number=current_start_line,
                                raw_text=" ".join(current_args),
                            )
                        )
                    in_continuation = False
                    current_inst_name = None
                    current_args = []
            else:
                parts = stripped.split(None, 1)
                if not parts:
                    continue

                inst_name = parts[0].upper()
                inst_args = parts[1] if len(parts) > 1 else ""

                if inst_args.endswith("\\"):
                    in_continuation = True
                    current_inst_name = inst_name
                    current_start_line = idx
                    current_args = [inst_args[:-1].strip()]
                else:
                    instructions.append(
                        DockerInstruction(
                            name=inst_name,
                            args=inst_args.strip(),
                            line_number=idx,
                            raw_text=stripped,
                        )
                    )

        if in_continuation and current_inst_name:
            instructions.append(
                DockerInstruction(
                    name=current_inst_name,
                    args=" ".join(current_args),
                    line_number=current_start_line,
                    raw_text=" ".join(current_args),
                )
            )

        return instructions

    def _group_into_stages(
        self, instructions: list[DockerInstruction]
    ) -> list[list[DockerInstruction]]:
        """Group instructions by Docker build stage (split on FROM)."""
        stages: list[list[DockerInstruction]] = []
        current_stage: list[DockerInstruction] = []

        for inst in instructions:
            if inst.name == "FROM":
                if current_stage:
                    stages.append(current_stage)
                current_stage = [inst]
            else:
                current_stage.append(inst)

        if current_stage:
            stages.append(current_stage)

        return stages

    def _check_missing_dockerignore(
        self, context: ProjectContext, dockerfile_path: Path
    ) -> list[Diagnostic]:
        """DOC-004: Flag when Dockerfile exists but .dockerignore is missing."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DOC-004")
        if not rule:
            return diagnostics

        if not context.docker.has_dockerignore:
            diagnostics.append(
                Diagnostic(
                    id=rule.id,
                    severity=rule.default_severity,
                    category=rule.category,
                    title=rule.title,
                    message="Dockerfile detected without a corresponding .dockerignore file.",
                    evidence=[
                        Evidence(
                            fact=f"Dockerfile found at: {dockerfile_path.name}",
                            source=str(dockerfile_path),
                        ),
                        Evidence(
                            fact="No .dockerignore file found in repository root.",
                            source=str(context.project_root),
                        ),
                    ],
                    suggestions=[
                        Suggestion(
                            description=(
                                "Create a .dockerignore file in the repository root to exclude "
                                ".venv, .git, __pycache__, and temporary build files from build context."
                            )
                        )
                    ],
                    file=str(dockerfile_path),
                    doc_url=rule.doc_url,
                )
            )
        return diagnostics

    def _check_layer_caching(
        self, stage_instructions: list[DockerInstruction], dockerfile_path: Path
    ) -> list[Diagnostic]:
        """DOC-001: Flag broad COPY . . executed before dependency install commands."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DOC-001")
        if not rule:
            return diagnostics

        broad_copy_inst: DockerInstruction | None = None
        dependency_patterns = (
            "pip install",
            "pip3 install",
            "uv sync",
            "uv pip install",
            "poetry install",
            "pdm install",
            "pipenv install",
            "flit install",
        )

        for inst in stage_instructions:
            if inst.name in ("COPY", "ADD"):
                parts = inst.args.split()
                if parts and parts[0] in (".", "./", "/"):
                    broad_copy_inst = inst
            elif inst.name == "RUN" and broad_copy_inst is not None:
                args_lower = inst.args.lower()
                if any(pat in args_lower for pat in dependency_patterns):
                    diagnostics.append(
                        Diagnostic(
                            id=rule.id,
                            severity=rule.default_severity,
                            category=rule.category,
                            title=rule.title,
                            message=(
                                f"Broad '{broad_copy_inst.name} {broad_copy_inst.args}' (line {broad_copy_inst.line_number}) "
                                f"executes before package installation command on line {inst.line_number}."
                            ),
                            evidence=[
                                Evidence(
                                    fact=f"Broad context copy on line {broad_copy_inst.line_number}: {broad_copy_inst.raw_text}",
                                    source=str(dockerfile_path),
                                ),
                                Evidence(
                                    fact=f"Dependency install on line {inst.line_number}: {inst.raw_text}",
                                    source=str(dockerfile_path),
                                ),
                            ],
                            suggestions=[
                                Suggestion(
                                    description=(
                                        "Copy dependency manifests (e.g. pyproject.toml, uv.lock, requirements.txt) "
                                        "and install dependencies before copying the full application source code."
                                    )
                                )
                            ],
                            file=str(dockerfile_path),
                            line=broad_copy_inst.line_number,
                            doc_url=rule.doc_url,
                        )
                    )
                    break

        return diagnostics

    def _check_unpinned_base_image(
        self,
        stage_instructions: list[DockerInstruction],
        dockerfile_path: Path,
        all_stages: list[list[DockerInstruction]],
        stage_idx: int,
    ) -> list[Diagnostic]:
        """DOC-003: Flag base image using ':latest' or missing version tag."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DOC-003")
        if not rule:
            return diagnostics

        for inst in stage_instructions:
            if inst.name == "FROM":
                parts = inst.args.split()
                if not parts:
                    continue
                image_ref = parts[0]

                previous_stage_names = set()
                for prev_idx in range(stage_idx):
                    prev_insts = all_stages[prev_idx]
                    if prev_insts and prev_insts[0].name == "FROM":
                        from_parts = prev_insts[0].args.split()
                        if "as" in [p.lower() for p in from_parts]:
                            as_idx = [p.lower() for p in from_parts].index("as")
                            if as_idx + 1 < len(from_parts):
                                previous_stage_names.add(from_parts[as_idx + 1].lower())

                if image_ref.lower() in previous_stage_names or image_ref.lower() == "scratch":
                    continue

                is_unpinned = False
                if image_ref.endswith(":latest") or ":" not in image_ref:
                    is_unpinned = True

                if is_unpinned:
                    diagnostics.append(
                        Diagnostic(
                            id=rule.id,
                            severity=rule.default_severity,
                            category=rule.category,
                            title=rule.title,
                            message=f"Base image '{image_ref}' uses an unpinned tag or ':latest'.",
                            evidence=[
                                Evidence(
                                    fact=f"FROM instruction on line {inst.line_number}: {inst.raw_text}",
                                    source=str(dockerfile_path),
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description=(
                                        f"Pin base image '{image_ref}' to a specific version or hash "
                                        "(e.g., 'python:3.12-slim-bookworm')."
                                    )
                                )
                            ],
                            file=str(dockerfile_path),
                            line=inst.line_number,
                            doc_url=rule.doc_url,
                        )
                    )
        return diagnostics

    def _check_root_user_execution(
        self, stage_instructions: list[DockerInstruction], dockerfile_path: Path
    ) -> list[Diagnostic]:
        """DOC-002: Flag when final container stage defines CMD/ENTRYPOINT without non-root USER."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DOC-002")
        if not rule:
            return diagnostics

        has_entrypoint = False
        entrypoint_inst: DockerInstruction | None = None
        has_non_root_user = False

        for inst in stage_instructions:
            if inst.name in ("CMD", "ENTRYPOINT"):
                has_entrypoint = True
                entrypoint_inst = inst
            elif inst.name == "USER":
                user_val = inst.args.strip().lower()
                if user_val not in ("root", "0", "0:0"):
                    has_non_root_user = True

        if has_entrypoint and not has_non_root_user and entrypoint_inst is not None:
            diagnostics.append(
                Diagnostic(
                    id=rule.id,
                    severity=rule.default_severity,
                    category=rule.category,
                    title=rule.title,
                    message="Container specifies an execution entrypoint but executes as the root user.",
                    evidence=[
                        Evidence(
                            fact=f"Entrypoint on line {entrypoint_inst.line_number}: {entrypoint_inst.raw_text}",
                            source=str(dockerfile_path),
                        ),
                        Evidence(
                            fact="No non-root USER instruction found in final stage.",
                            source=str(dockerfile_path),
                        ),
                    ],
                    suggestions=[
                        Suggestion(
                            description=(
                                "Create a non-privileged user and switch before running the application: "
                                "'RUN useradd -m -u 1000 appuser && USER appuser'."
                            )
                        )
                    ],
                    file=str(dockerfile_path),
                    line=entrypoint_inst.line_number,
                    doc_url=rule.doc_url,
                )
            )
        return diagnostics

    def _check_pip_cache_flag(
        self, stage_instructions: list[DockerInstruction], dockerfile_path: Path
    ) -> list[Diagnostic]:
        """DOC-005: Flag pip install commands missing --no-cache-dir in Dockerfile."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DOC-005")
        if not rule:
            return diagnostics

        for inst in stage_instructions:
            if inst.name == "RUN":
                args_lower = inst.args.lower()
                if ("pip install" in args_lower or "pip3 install" in args_lower) and (
                    "--no-cache-dir" not in args_lower and "--mount=type=cache" not in args_lower
                ):
                    diagnostics.append(
                        Diagnostic(
                            id=rule.id,
                            severity=rule.default_severity,
                            category=rule.category,
                            title=rule.title,
                            message="pip install command in Dockerfile is missing '--no-cache-dir'.",
                            evidence=[
                                Evidence(
                                    fact=f"RUN command on line {inst.line_number}: {inst.raw_text}",
                                    source=str(dockerfile_path),
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description=(
                                        "Add '--no-cache-dir' to pip install in Dockerfile to prevent caching wheel "
                                        "archives and reduce container image size."
                                    )
                                )
                            ],
                            file=str(dockerfile_path),
                            line=inst.line_number,
                            doc_url=rule.doc_url,
                        )
                    )
        return diagnostics

    def _check_sensitive_copies(
        self, stage_instructions: list[DockerInstruction], dockerfile_path: Path
    ) -> list[Diagnostic]:
        """DOC-006: Flag explicit copying of sensitive credentials or .env files."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DOC-006")
        if not rule:
            return diagnostics

        sensitive_pattern = re.compile(
            r"(?i)(\.env($|\s)|\.pem($|\s)|id_rsa|id_ed25519|credentials\.json|service[_-]account.*\.json|secrets?\.ya?ml|secrets?\.json)"
        )

        for inst in stage_instructions:
            if inst.name in ("COPY", "ADD"):
                match = sensitive_pattern.search(inst.args)
                if match:
                    matched_target = match.group(0).strip()
                    diagnostics.append(
                        Diagnostic(
                            id=rule.id,
                            severity=rule.default_severity,
                            category=rule.category,
                            title=rule.title,
                            message=f"Potentially sensitive file or credential pattern '{matched_target}' copied into image layer.",
                            evidence=[
                                Evidence(
                                    fact=f"COPY instruction on line {inst.line_number}: {inst.raw_text}",
                                    source=str(dockerfile_path),
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description=(
                                        "Do not bake secret or environment files directly into Docker layers. "
                                        "Inject secrets via runtime environment variables or Docker BuildKit secrets."
                                    )
                                )
                            ],
                            file=str(dockerfile_path),
                            line=inst.line_number,
                            doc_url=rule.doc_url,
                        )
                    )
        return diagnostics

    def _check_healthcheck(
        self, instructions: list[DockerInstruction], dockerfile_path: Path
    ) -> list[Diagnostic]:
        """DOC-007: Flag missing HEALTHCHECK when network service or entrypoint is defined."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DOC-007")
        if not rule:
            return diagnostics

        has_healthcheck = any(inst.name == "HEALTHCHECK" for inst in instructions)
        has_expose = any(inst.name == "EXPOSE" for inst in instructions)
        has_web_server = any(
            inst.name in ("CMD", "ENTRYPOINT")
            and any(kw in inst.args.lower() for kw in WEB_SERVER_KEYWORDS)
            for inst in instructions
        )

        if (has_expose or has_web_server) and not has_healthcheck:
            first_line = instructions[0].line_number if instructions else 1
            diagnostics.append(
                Diagnostic(
                    id=rule.id,
                    severity=rule.default_severity,
                    category=rule.category,
                    title=rule.title,
                    message="Dockerfile defines a web service or network entrypoint but lacks a HEALTHCHECK instruction.",
                    evidence=[
                        Evidence(
                            fact="Web service/port exposed without container HEALTHCHECK.",
                            source=str(dockerfile_path),
                        )
                    ],
                    suggestions=[
                        Suggestion(
                            description=(
                                "Add a HEALTHCHECK instruction (e.g. 'HEALTHCHECK --interval=30s "
                                "CMD curl -f http://localhost:8000/health || exit 1') for orchestrators."
                            )
                        )
                    ],
                    file=str(dockerfile_path),
                    line=first_line,
                    doc_url=rule.doc_url,
                )
            )
        return diagnostics

    def _check_python_unbuffered(
        self, instructions: list[DockerInstruction], dockerfile_path: Path
    ) -> list[Diagnostic]:
        """DOC-008: Flag when PYTHONUNBUFFERED=1 is missing from Docker environment."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DOC-008")
        if not rule:
            return diagnostics

        has_unbuffered = False
        for inst in instructions:
            if inst.name == "ENV":
                if "PYTHONUNBUFFERED=1" in inst.args.replace(" ", "") or (
                    "PYTHONUNBUFFERED" in inst.args and "1" in inst.args
                ):
                    has_unbuffered = True
            elif inst.name in ("CMD", "ENTRYPOINT") and "python -u" in inst.args.lower():
                has_unbuffered = True

        if not has_unbuffered:
            diagnostics.append(
                Diagnostic(
                    id=rule.id,
                    severity=rule.default_severity,
                    category=rule.category,
                    title=rule.title,
                    message="Python container environment is missing 'ENV PYTHONUNBUFFERED=1'.",
                    evidence=[
                        Evidence(
                            fact="PYTHONUNBUFFERED environment variable not set in Dockerfile.",
                            source=str(dockerfile_path),
                        )
                    ],
                    suggestions=[
                        Suggestion(
                            description=(
                                "Set 'ENV PYTHONUNBUFFERED=1' in your Dockerfile to ensure stdout and stderr "
                                "are flushed immediately to container log collectors."
                            )
                        )
                    ],
                    file=str(dockerfile_path),
                    line=1,
                    doc_url=rule.doc_url,
                )
            )
        return diagnostics

    def _check_deprecated_maintainer(
        self, stage_instructions: list[DockerInstruction], dockerfile_path: Path
    ) -> list[Diagnostic]:
        """DOC-009: Flag deprecated MAINTAINER instruction."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DOC-009")
        if not rule:
            return diagnostics

        for inst in stage_instructions:
            if inst.name == "MAINTAINER":
                diagnostics.append(
                    Diagnostic(
                        id=rule.id,
                        severity=rule.default_severity,
                        category=rule.category,
                        title=rule.title,
                        message=f"Deprecated MAINTAINER instruction used: '{inst.raw_text}'.",
                        evidence=[
                            Evidence(
                                fact=f"MAINTAINER on line {inst.line_number}: {inst.raw_text}",
                                source=str(dockerfile_path),
                            )
                        ],
                        suggestions=[
                            Suggestion(
                                description=f"Replace with LABEL: 'LABEL maintainer=\"{inst.args}\"'."
                            )
                        ],
                        file=str(dockerfile_path),
                        line=inst.line_number,
                        doc_url=rule.doc_url,
                    )
                )
        return diagnostics

    def _check_sudo_usage(
        self, stage_instructions: list[DockerInstruction], dockerfile_path: Path
    ) -> list[Diagnostic]:
        """DOC-010: Flag redundant/unsafe sudo command in RUN instruction."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DOC-010")
        if not rule:
            return diagnostics

        sudo_pattern = re.compile(r"(^|\s|;|&&|\|\|)sudo(\s+|$)", re.IGNORECASE)
        for inst in stage_instructions:
            if inst.name == "RUN" and sudo_pattern.search(inst.args):
                diagnostics.append(
                    Diagnostic(
                        id=rule.id,
                        severity=rule.default_severity,
                        category=rule.category,
                        title=rule.title,
                        message=f"Unnecessary 'sudo' command used in RUN instruction on line {inst.line_number}.",
                        evidence=[
                            Evidence(
                                fact=f"RUN instruction contains sudo: {inst.raw_text}",
                                source=str(dockerfile_path),
                            )
                        ],
                        suggestions=[
                            Suggestion(
                                description="Remove 'sudo' from RUN instructions. Docker build commands already run with root privileges."
                            )
                        ],
                        file=str(dockerfile_path),
                        line=inst.line_number,
                        doc_url=rule.doc_url,
                    )
                )
        return diagnostics

    def _check_apt_cleanup(
        self, stage_instructions: list[DockerInstruction], dockerfile_path: Path
    ) -> list[Diagnostic]:
        """DOC-011: Flag apt-get install without cache cleanup or --no-install-recommends."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DOC-011")
        if not rule:
            return diagnostics

        for inst in stage_instructions:
            if inst.name == "RUN":
                args_lower = inst.args.lower()
                if "apt-get install" in args_lower or "apt install" in args_lower:
                    missing_cleanup = "rm -rf /var/lib/apt/lists" not in args_lower
                    missing_recommends = "--no-install-recommends" not in args_lower
                    if missing_cleanup or missing_recommends:
                        reasons: list[str] = []
                        if missing_recommends:
                            reasons.append("omits '--no-install-recommends'")
                        if missing_cleanup:
                            reasons.append("omits 'rm -rf /var/lib/apt/lists/*'")

                        diagnostics.append(
                            Diagnostic(
                                id=rule.id,
                                severity=rule.default_severity,
                                category=rule.category,
                                title=rule.title,
                                message=(
                                    f"apt-get install on line {inst.line_number} {' and '.join(reasons)}."
                                ),
                                evidence=[
                                    Evidence(
                                        fact=f"RUN instruction: {inst.raw_text}",
                                        source=str(dockerfile_path),
                                    )
                                ],
                                suggestions=[
                                    Suggestion(
                                        description=(
                                            "Combine apt commands and clean lists: "
                                            "'apt-get update && apt-get install -y --no-install-recommends <pkgs> "
                                            "&& rm -rf /var/lib/apt/lists/*'"
                                        )
                                    )
                                ],
                                file=str(dockerfile_path),
                                line=inst.line_number,
                                doc_url=rule.doc_url,
                            )
                        )
        return diagnostics

    def _check_add_usage(
        self, stage_instructions: list[DockerInstruction], dockerfile_path: Path
    ) -> list[Diagnostic]:
        """DOC-012: Flag ADD instruction used for local file copying where COPY is preferred."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DOC-012")
        if not rule:
            return diagnostics

        tar_extensions = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".zip")

        for inst in stage_instructions:
            if inst.name == "ADD":
                parts = inst.args.split()
                src = parts[0] if parts else ""
                is_url = src.lower().startswith(("http://", "https://", "ftp://"))
                is_tar = any(src.lower().endswith(ext) for ext in tar_extensions)

                if not is_url and not is_tar:
                    diagnostics.append(
                        Diagnostic(
                            id=rule.id,
                            severity=rule.default_severity,
                            category=rule.category,
                            title=rule.title,
                            message=f"ADD instruction on line {inst.line_number} used for local file copy.",
                            evidence=[
                                Evidence(
                                    fact=f"ADD instruction: {inst.raw_text}",
                                    source=str(dockerfile_path),
                                )
                            ],
                            suggestions=[
                                Suggestion(
                                    description=(
                                        f"Replace 'ADD {inst.args}' with 'COPY {inst.args}' for predictable local file copies."
                                    )
                                )
                            ],
                            file=str(dockerfile_path),
                            line=inst.line_number,
                            doc_url=rule.doc_url,
                        )
                    )
        return diagnostics

    def _check_dont_write_bytecode(
        self, instructions: list[DockerInstruction], dockerfile_path: Path
    ) -> list[Diagnostic]:
        """DOC-013: Flag missing PYTHONDONTWRITEBYTECODE=1 in container environment."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DOC-013")
        if not rule:
            return diagnostics

        has_bytecode_flag = False
        for inst in instructions:
            if inst.name == "ENV" and "PYTHONDONTWRITEBYTECODE" in inst.args and "1" in inst.args:
                has_bytecode_flag = True
                break

        if not has_bytecode_flag:
            diagnostics.append(
                Diagnostic(
                    id=rule.id,
                    severity=rule.default_severity,
                    category=rule.category,
                    title=rule.title,
                    message="Python container environment is missing 'ENV PYTHONDONTWRITEBYTECODE=1'.",
                    evidence=[
                        Evidence(
                            fact="PYTHONDONTWRITEBYTECODE environment variable not set in Dockerfile.",
                            source=str(dockerfile_path),
                        )
                    ],
                    suggestions=[
                        Suggestion(
                            description=(
                                "Set 'ENV PYTHONDONTWRITEBYTECODE=1' to prevent Python from writing .pyc files into image layers."
                            )
                        )
                    ],
                    file=str(dockerfile_path),
                    line=1,
                    doc_url=rule.doc_url,
                )
            )
        return diagnostics

    def _check_web_server_expose(
        self, instructions: list[DockerInstruction], dockerfile_path: Path
    ) -> list[Diagnostic]:
        """DOC-014: Flag web server entrypoint missing EXPOSE instruction."""
        diagnostics: list[Diagnostic] = []
        rule = get_rule_definition("DOC-014")
        if not rule:
            return diagnostics

        has_expose = any(inst.name == "EXPOSE" for inst in instructions)
        web_server_inst: DockerInstruction | None = None
        for inst in instructions:
            if inst.name in ("CMD", "ENTRYPOINT"):
                if any(kw in inst.args.lower() for kw in WEB_SERVER_KEYWORDS):
                    web_server_inst = inst
                    break

        if web_server_inst is not None and not has_expose:
            diagnostics.append(
                Diagnostic(
                    id=rule.id,
                    severity=rule.default_severity,
                    category=rule.category,
                    title=rule.title,
                    message=f"Container starts web server on line {web_server_inst.line_number} without an EXPOSE instruction.",
                    evidence=[
                        Evidence(
                            fact=f"Web server command: {web_server_inst.raw_text}",
                            source=str(dockerfile_path),
                        ),
                        Evidence(
                            fact="No EXPOSE instruction found in Dockerfile.",
                            source=str(dockerfile_path),
                        ),
                    ],
                    suggestions=[
                        Suggestion(
                            description="Add 'EXPOSE <port>' (e.g. 'EXPOSE 8000') to document listening container ports."
                        )
                    ],
                    file=str(dockerfile_path),
                    line=web_server_inst.line_number,
                    doc_url=rule.doc_url,
                )
            )
        return diagnostics
