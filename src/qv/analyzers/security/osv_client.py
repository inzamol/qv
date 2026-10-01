"""Client for querying the Open Source Vulnerabilities (OSV.dev) database."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Vulnerability:
    """Represents a discovered CVE/GHSA vulnerability."""

    id: str
    package_name: str
    installed_version: str
    summary: str
    details: str
    aliases: tuple[str, ...]
    fixed_versions: tuple[str, ...]
    advisory_url: str | None = None
    severity: str | None = None


class OsvClient:
    """Fast, lightweight client for the OSV.dev batch query API."""

    OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

    def __init__(self, timeout_seconds: float = 6.0) -> None:
        self.timeout = timeout_seconds
        self._cache: dict[tuple[str, str], list[Vulnerability]] = {}

    def query_packages(
        self, packages: list[tuple[str, str]]
    ) -> dict[tuple[str, str], list[Vulnerability]]:
        """Batch query multiple (package_name, version) pairs against OSV.dev."""
        results: dict[tuple[str, str], list[Vulnerability]] = {}
        uncached: list[tuple[str, str]] = []

        for pkg_tuple in packages:
            key = (pkg_tuple[0].lower(), pkg_tuple[1])
            if key in self._cache:
                results[key] = self._cache[key]
            else:
                uncached.append(pkg_tuple)

        if not uncached:
            return results

        # Process uncached in chunks of up to 500 (OSV API limit is 1000)
        chunk_size = 500
        for i in range(0, len(uncached), chunk_size):
            chunk = uncached[i : i + chunk_size]
            queries = [
                {"package": {"name": name, "ecosystem": "PyPI"}, "version": ver}
                for name, ver in chunk
            ]
            payload = json.dumps({"queries": queries}).encode("utf-8")

            req = urllib.request.Request(
                self.OSV_BATCH_URL,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "qv-security-analyzer/0.1.0",
                },
                method="POST",
            )

            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    data = json.loads(response.read().decode("utf-8"))
                    raw_results = data.get("results", [])

                    for (name, ver), res in zip(chunk, raw_results, strict=False):
                        key = (name.lower(), ver)
                        vulns_list: list[Vulnerability] = []
                        for vuln_data in res.get("vulns", []):
                            vuln = self._parse_vuln(vuln_data, name, ver)
                            vulns_list.append(vuln)
                        self._cache[key] = vulns_list
                        results[key] = vulns_list
            except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
                # Return empty list on network or parse failures without crashing
                for name, ver in chunk:
                    key = (name.lower(), ver)
                    self._cache[key] = []
                    results[key] = []

        return results

    def _parse_vuln(self, data: dict[str, Any], pkg_name: str, pkg_ver: str) -> Vulnerability:
        vuln_id = data.get("id", "")
        summary = data.get("summary", "") or f"Vulnerability detected in {pkg_name}"
        details = data.get("details", "")
        aliases = tuple(data.get("aliases", []))

        # Extract fixed version if available
        fixed_versions: list[str] = []
        for affected in data.get("affected", []):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        fixed_versions.append(event["fixed"])

        # Determine advisory URL
        advisory_url = None
        for ref in data.get("references", []):
            if ref.get("type") in ("ADVISORY", "WEB"):
                advisory_url = ref.get("url")
                break
        if not advisory_url:
            advisory_url = f"https://osv.dev/vulnerability/{vuln_id}"

        # Determine severity
        sev = None
        if data.get("database_specific", {}).get("severity"):
            sev = data["database_specific"]["severity"]
        elif data.get("severity"):
            for s in data["severity"]:
                if s.get("type") == "CVSS_V3":
                    sev = s.get("score")

        return Vulnerability(
            id=vuln_id,
            package_name=pkg_name,
            installed_version=pkg_ver,
            summary=summary,
            details=details,
            aliases=aliases,
            fixed_versions=tuple(fixed_versions),
            advisory_url=advisory_url,
            severity=sev,
        )
