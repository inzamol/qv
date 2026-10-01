"""GitHub Actions Annotator and Step Summary Reporter."""

from __future__ import annotations

import os

from qv.core.models import ScanResult, Severity


class GitHubAnnotator:
    """Emits GitHub Actions workflow command annotations and step summaries."""

    def emit_annotations(self, result: ScanResult) -> None:
        """Print GitHub workflow command annotations for each diagnostic finding."""
        for d in result.diagnostics:
            level = "error" if d.severity == Severity.ERROR else "warning"
            file_part = f"file={d.file}" if d.file else ""
            line_part = f",line={d.line}" if d.line else ""
            title_part = f",title={d.id}: {d.title}"

            options = f"{file_part}{line_part}{title_part}".lstrip(",")
            opt_str = f" {options}" if options else ""
            print(f"::{level}{opt_str}::{d.message}")

    def write_step_summary(self, result: ScanResult) -> None:
        """Write rich Markdown summary table to GITHUB_STEP_SUMMARY environment file."""
        summary_path = os.getenv("GITHUB_STEP_SUMMARY")
        if not summary_path:
            return

        score_badge = (
            f"![Score: {result.health_score}](https://img.shields.io/badge/Health_Score-{result.health_score}%2F100-brightgreen)"
            if result.health_score >= 80
            else f"![Score: {result.health_score}](https://img.shields.io/badge/Health_Score-{result.health_score}%2F100-red)"
        )

        lines: list[str] = [
            f"# 🔍 qv Health Report: {result.project_name}",
            "",
            f"**Health Score:** {result.health_score}/100 &nbsp; {score_badge}",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| **Blocking Errors** | 🔴 {result.error_count} |",
            f"| **Warnings** | 🟡 {result.warning_count} |",
            f"| **Checks Evaluated** | 🟢 {result.checks_passed} |",
            f"| **Python Runtime** | `{result.python_version}` |",
            f"| **Package Manager** | `{result.package_manager.upper()}` |",
            "",
        ]

        if result.diagnostics:
            lines.extend(
                [
                    "## 📋 Diagnostics Details",
                    "",
                    "| Severity | Rule ID | Title | File | Message |",
                    "|---|---|---|---|---|",
                ]
            )
            for d in result.diagnostics:
                sev_icon = "🔴 Error" if d.severity == Severity.ERROR else "🟡 Warning"
                loc = (
                    f"`{d.file}:{d.line}`"
                    if d.file and d.line
                    else (f"`{d.file}`" if d.file else "—")
                )
                lines.append(f"| {sev_icon} | `{d.id}` | **{d.title}** | {loc} | {d.message} |")
            lines.append("")

        if result.root_causes:
            lines.extend(
                [
                    "## 🧠 Correlated Root Causes",
                    "",
                ]
            )
            for rc in result.root_causes:
                lines.append(f"### {rc.id}: {rc.title}")
                lines.append(f"- **Summary:** {rc.summary}")
                lines.append(f"- **Recommendation:** {rc.recommendation.description}")
                lines.append("")

        try:
            with open(summary_path, "a", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except Exception:
            pass
