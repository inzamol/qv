"""SARIF (Static Analysis Results Interchange Format) reporter conforming to v2.1.0."""

from __future__ import annotations

import json
from typing import Any

from qv import __version__
from qv.core.models import ScanResult, Severity
from qv.rules.registry import RULES_CATALOG


class SarifReporter:
    """Generates standard SARIF v2.1.0 output for CI / Code Scanning integration."""

    def __init__(self, tool_version: str | None = None) -> None:
        self.tool_version = tool_version or __version__

    def render(self, result: ScanResult) -> str:
        """Render scan result to SARIF v2.1.0 JSON format."""
        sarif_data = self.to_sarif_dict(result)
        return json.dumps(sarif_data, indent=2)

    def to_sarif_dict(self, result: ScanResult) -> dict[str, Any]:
        rules_dict: list[dict[str, Any]] = []
        seen_rules = set()

        for diag in result.diagnostics:
            if diag.id not in seen_rules:
                seen_rules.add(diag.id)
                rule_def = RULES_CATALOG.get(diag.id)
                rule_entry: dict[str, Any] = {
                    "id": diag.id,
                    "name": diag.id.replace("-", "_"),
                    "shortDescription": {"text": diag.title},
                    "fullDescription": {"text": rule_def.description if rule_def else diag.title},
                }
                if diag.doc_url:
                    rule_entry["helpUri"] = diag.doc_url
                rules_dict.append(rule_entry)

        sarif_results: list[dict[str, Any]] = []
        for diag in result.diagnostics:
            level = (
                "error"
                if diag.severity == Severity.ERROR
                else "warning"
                if diag.severity == Severity.WARNING
                else "note"
            )
            res_entry: dict[str, Any] = {
                "ruleId": diag.id,
                "level": level,
                "message": {"text": diag.message},
            }

            if diag.file:
                res_entry["locations"] = [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": diag.file.replace("\\", "/"),
                            },
                            "region": {
                                "startLine": diag.line or 1,
                                "startColumn": diag.column or 1,
                            },
                        }
                    }
                ]
            sarif_results.append(res_entry)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "qv",
                            "semanticVersion": self.tool_version,
                            "informationUri": "https://github.com/inzamol/qv",
                            "rules": rules_dict,
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }
