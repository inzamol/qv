"""GitHub Action runner script for qv.

This script executes inside the GitHub Actions composite action environment,
validates inputs safely, executes the qv CLI without shell injection risks,
formats concise logs matching Marketplace specifications, parses SARIF/JSON
diagnostics, writes step outputs to $GITHUB_OUTPUT, and exits with the
appropriate status code according to the configured fail-on threshold.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


action_path_env = os.environ.get("ACTION_PATH")
if action_path_env:
    src_dir = str(Path(action_path_env) / "src")
    if Path(src_dir).is_dir() and src_dir not in sys.path:
        sys.path.insert(0, src_dir)


def _log_error(msg: str) -> None:
    print(f"::error::{msg}", flush=True)
    print(msg, file=sys.stderr, flush=True)


def _log_warning(msg: str) -> None:
    print(f"::warning::{msg}", flush=True)
    print(msg, file=sys.stderr, flush=True)


def get_qv_version() -> str:
    try:
        import qv

        return getattr(qv, "__version__", "unknown")
    except Exception:
        cli_bin = shutil.which("qv")
        if cli_bin:
            try:
                res = subprocess.run(
                    [cli_bin, "--version"], capture_output=True, text=True, check=True
                )
                return res.stdout.strip().replace("qv, version ", "").replace("qv v", "")
            except Exception:
                pass
        return "unknown"


def main() -> int:
    # 1. Read environment inputs
    raw_path = os.environ.get("INPUT_PATH", ".").strip() or "."
    raw_format = os.environ.get("INPUT_FORMAT", "sarif").strip().lower() or "sarif"
    raw_output = os.environ.get("INPUT_OUTPUT", "qv-results.sarif").strip()
    raw_fail_on = os.environ.get("INPUT_FAIL_ON", "error").strip().lower() or "error"
    raw_github_annotations = os.environ.get("INPUT_GITHUB_ANNOTATIONS", "true").strip().lower()
    raw_offline = os.environ.get("INPUT_OFFLINE", "false").strip().lower()
    raw_baseline = os.environ.get("INPUT_BASELINE", "").strip()
    raw_args = os.environ.get("INPUT_ARGS", "").strip()

    # 2. Validate target project path (Section 10)
    target_path = Path(raw_path)
    if not target_path.exists():
        msg = f"qv: project path does not exist: {raw_path}"
        _log_error(msg)
        return 1

    # 3. Validate format input
    supported_formats = ("sarif", "terminal", "json", "html", "text")
    if raw_format not in supported_formats:
        _log_error(
            f"qv: invalid format '{raw_format}'. Supported formats: {', '.join(supported_formats)}."
        )
        return 1

    # 4. Validate fail-on input (Section 13)
    supported_fail_on = ("error", "warning", "none", "never")
    if raw_fail_on not in supported_fail_on:
        _log_error(f"qv: invalid fail-on '{raw_fail_on}'. Supported options: error, warning, none.")
        return 1

    # 5. Build CLI command safely
    cli_bin = shutil.which("qv")
    if cli_bin:
        cmd: list[str] = [cli_bin, "scan", str(target_path)]
    else:
        cmd = [sys.executable, "-m", "qv", "scan", str(target_path)]

    sarif_output_path: Path | None = None

    if raw_format == "sarif":
        cmd.append("--sarif")
        if raw_output:
            cmd.extend(["--output", raw_output])
            sarif_output_path = Path(raw_output)
    elif raw_format == "json":
        cmd.append("--json")
        if raw_output:
            cmd.extend(["--output", raw_output])
    elif raw_format == "html":
        if raw_output:
            cmd.extend(["--html", raw_output])
        else:
            cmd.extend(["--html", "qv-report.html"])
    elif raw_format in ("terminal", "text"):
        cmd.extend(["--format", raw_format])
        if raw_output:
            cmd.extend(["--output", raw_output])

    # GitHub annotations
    if raw_github_annotations in ("true", "1", "yes"):
        cmd.append("--github-annotations")

    # Offline mode
    if raw_offline in ("true", "1", "yes"):
        cmd.append("--offline")

    # Baseline snapshot
    if raw_baseline:
        baseline_path = Path(raw_baseline)
        if not baseline_path.exists():
            _log_warning(
                f"qv: baseline file '{raw_baseline}' does not exist. Running without baseline."
            )
        else:
            cmd.extend(["--baseline", raw_baseline])

    # Severity failure threshold
    if raw_fail_on == "warning":
        cmd.append("--strict")

    # Additional CLI arguments (Section 14: Safe argument parsing)
    if raw_args:
        try:
            extra_tokens = shlex.split(raw_args)
            cmd.extend(extra_tokens)
        except ValueError as e:
            _log_error(f"qv: failed to parse additional arguments '{raw_args}': {e}")
            return 1

    # 6. Concise action banner & logging (Section 16)
    qv_ver = get_qv_version()
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    print("qv", flush=True)
    print("────────────────────────────────", flush=True)
    print(f"Project: {raw_path}", flush=True)
    print(f"Python:  {py_ver}", flush=True)
    print(f"qv:      {qv_ver}", flush=True)
    print("", flush=True)
    print("Analyzing project...", flush=True)
    # Clean up any pre-existing report file at destination to ensure only reports from this scan are used
    expected_report: Path | None = (
        sarif_output_path if raw_format == "sarif" else (Path(raw_output) if raw_output else None)
    )
    if expected_report and expected_report.is_file():
        try:
            expected_report.unlink()
        except OSError:
            pass

    # 7. Execute qv CLI
    sub_env = os.environ.copy()
    if action_path_env:
        src_path = str(Path(action_path_env) / "src")
        if Path(src_path).is_dir():
            existing_pythonpath = sub_env.get("PYTHONPATH", "")
            sub_env["PYTHONPATH"] = (
                f"{src_path}{os.pathsep}{existing_pythonpath}" if existing_pythonpath else src_path
            )
    process = subprocess.run(cmd, env=sub_env)
    raw_exit_code = process.returncode

    # 8. Extract findings & metrics for outputs and summary logging
    findings = 0
    errors = 0
    warnings = 0
    info = 0
    sarif_resolved_path = ""

    if raw_exit_code in (0, 1) and sarif_output_path and sarif_output_path.is_file():
        try:
            sarif_data = json.loads(sarif_output_path.read_text(encoding="utf-8"))
            runs = sarif_data.get("runs", [])
            if isinstance(runs, list):
                sarif_resolved_path = str(sarif_output_path)
                if runs:
                    results = runs[0].get("results", [])
                    findings = len(results)
                    for r in results:
                        lvl = r.get("level", "warning")
                        if lvl == "error":
                            errors += 1
                        elif lvl == "warning":
                            warnings += 1
                        else:
                            info += 1
        except Exception:
            sarif_resolved_path = ""
    elif (
        raw_exit_code in (0, 1)
        and raw_format == "json"
        and raw_output
        and Path(raw_output).is_file()
    ):
        try:
            json_data = json.loads(Path(raw_output).read_text(encoding="utf-8"))
            diags = json_data.get("diagnostics", [])
            findings = len(diags)
            for d in diags:
                sev = d.get("severity")
                if sev == "error":
                    errors += 1
                elif sev == "warning":
                    warnings += 1
                else:
                    info += 1
        except Exception:
            pass
    elif raw_exit_code == 0:
        findings = 0
        errors = 0
        warnings = 0
        info = 0

    # 9. Concise output summary (Section 16)
    print("", flush=True)
    print(f"Errors:   {errors}", flush=True)
    print(f"Warnings: {warnings}", flush=True)
    print(f"Info:     {info}", flush=True)
    if sarif_resolved_path:
        print("", flush=True)
        print(f"SARIF:    {sarif_resolved_path}", flush=True)
    print("", flush=True)

    if errors > 0:
        print(f"qv found {errors} error(s).", flush=True)
    elif warnings > 0:
        print(f"qv found {warnings} warning(s).", flush=True)
    else:
        print("qv found 0 errors.", flush=True)

    # 10. Write action outputs to $GITHUB_OUTPUT (Section 15)
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        try:
            with open(github_output, "a", encoding="utf-8") as f:
                f.write(f"sarif-file={sarif_resolved_path}\n")
                f.write(f"findings={findings}\n")
                f.write(f"errors={errors}\n")
                f.write(f"warnings={warnings}\n")
                f.write(f"exit-code={raw_exit_code}\n")
        except Exception as e:
            _log_warning(f"Failed to write GITHUB_OUTPUT: {e}")

    # 11. Determine return code based on fail-on (Section 13)
    # Only finding-based failures (exit code 1) are eligible to be suppressed by fail-on: none/never.
    # CLI usage errors (code 2), configuration/runtime errors, or crashes must propagate.
    if raw_exit_code not in (0, 1):
        return raw_exit_code

    if raw_fail_on in ("none", "never"):
        # If SARIF was requested but no report was produced on failure, this was an execution failure rather than findings.
        if (
            raw_format == "sarif"
            and raw_exit_code == 1
            and not (sarif_output_path and sarif_output_path.is_file())
        ):
            return raw_exit_code
        return 0

    return raw_exit_code


if __name__ == "__main__":
    sys.exit(main())
