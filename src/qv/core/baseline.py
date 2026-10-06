"""Baseline snapshot and differential scanning for managing legacy project debt."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from qv.core.models import Diagnostic, ScanResult


def compute_diagnostic_fingerprint(diag: Diagnostic) -> str:
    """Compute a stable hash fingerprint for a diagnostic based on rule ID, file, and title/line."""
    raw = f"{diag.id}:{diag.file or ''}:{diag.title}:{diag.message}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def create_baseline_data(scan_result: ScanResult) -> dict[str, Any]:
    """Generate baseline snapshot dictionary from a ScanResult."""
    records = []
    for diag in scan_result.diagnostics:
        fingerprint = compute_diagnostic_fingerprint(diag)
        records.append(
            {
                "id": diag.id,
                "title": diag.title,
                "file": diag.file,
                "line": diag.line,
                "severity": diag.severity.value,
                "fingerprint": fingerprint,
            }
        )

    return {
        "version": "1.0",
        "project_name": scan_result.project_name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "total_diagnostics": len(records),
        "diagnostics": records,
    }


def save_baseline(scan_result: ScanResult, baseline_path: Path) -> None:
    """Save the current scan result diagnostics into a baseline snapshot file."""
    data = create_baseline_data(scan_result)
    baseline_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_baseline_fingerprints(baseline_path: Path) -> set[str]:
    """Load baseline snapshot and extract existing diagnostic fingerprints."""
    if not baseline_path.exists() or not baseline_path.is_file():
        return set()

    try:
        content = baseline_path.read_text(encoding="utf-8")
        data = json.loads(content)
        records = data.get("diagnostics", [])
        fingerprints: set[str] = set()
        for r in records:
            if isinstance(r, dict) and "fingerprint" in r:
                fingerprints.add(r["fingerprint"])
        return fingerprints
    except Exception:
        return set()


def filter_against_baseline(
    diagnostics: list[Diagnostic], baseline_fingerprints: set[str]
) -> tuple[list[Diagnostic], int]:
    """
    Filter diagnostics against baseline snapshot.
    Returns (new_violations, suppressed_baseline_count).
    """
    new_diags: list[Diagnostic] = []
    suppressed_count = 0

    for diag in diagnostics:
        fp = compute_diagnostic_fingerprint(diag)
        if fp in baseline_fingerprints:
            suppressed_count += 1
        else:
            new_diags.append(diag)

    return new_diags, suppressed_count
