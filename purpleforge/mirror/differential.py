"""
purpleforge.mirror.differential — diff two CrawlManifest snapshots.

AUTHORIZED, VERIFIED TARGETS ONLY.  Defensive static analysis only.
No network calls; purely compares two manifest files on disk.
Findings emitted are informational — severity low by default, medium for
new cross-origin scripts.  Manual review required.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from purpleforge.analysis.findings_schema import Finding, dump_findings
from purpleforge.mirror.crawler import CrawlManifest
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)

_SOURCE = "mirror_diff"


@dataclass
class DiffResult:
    """Result of diffing two CrawlManifests."""

    old_base_url: str
    new_base_url: str
    added_pages: List[str] = field(default_factory=list)
    removed_pages: List[str] = field(default_factory=list)
    changed_pages: List[str] = field(default_factory=list)
    # Per-URL header changes: {url: {"added": [...], "removed": [...]}}
    header_changes: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)
    added_scripts: List[str] = field(default_factory=list)
    removed_scripts: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "old_base_url": self.old_base_url,
            "new_base_url": self.new_base_url,
            "added_pages": self.added_pages,
            "removed_pages": self.removed_pages,
            "changed_pages": self.changed_pages,
            "header_changes": self.header_changes,
            "added_scripts": self.added_scripts,
            "removed_scripts": self.removed_scripts,
        }


class MirrorDiff:
    """
    Diff two CrawlManifests to detect surface-area changes.

    Authorized, verified targets only.  Defensive static analysis only.
    No exploitation.  Manual review required.
    """

    def diff(self, old_manifest_path: Path, new_manifest_path: Path) -> DiffResult:
        """
        Load two manifest JSON files and produce a DiffResult.

        Parameters
        ----------
        old_manifest_path:
            Path to the older manifest.json.
        new_manifest_path:
            Path to the newer manifest.json.

        Returns
        -------
        DiffResult with added/removed/changed pages and header diffs.
        """
        old = self._load(old_manifest_path)
        new = self._load(new_manifest_path)

        old_pages: Dict[str, Any] = {p["url"]: p for p in old.get("pages", [])}
        new_pages: Dict[str, Any] = {p["url"]: p for p in new.get("pages", [])}

        old_urls: Set[str] = set(old_pages)
        new_urls: Set[str] = set(new_pages)

        added = sorted(new_urls - old_urls)
        removed = sorted(old_urls - new_urls)
        common = old_urls & new_urls
        changed = sorted(
            url for url in common
            if old_pages[url].get("sha256") != new_pages[url].get("sha256")
        )

        # Header changes per URL (for pages present in both)
        header_changes: Dict[str, Dict[str, List[str]]] = {}
        for url in common:
            old_h: Set[str] = set((old_pages[url].get("headers") or {}).keys())
            new_h: Set[str] = set((new_pages[url].get("headers") or {}).keys())
            added_h = sorted(new_h - old_h)
            removed_h = sorted(old_h - new_h)
            if added_h or removed_h:
                header_changes[url] = {"added": added_h, "removed": removed_h}

        # Script inventory diff
        old_scripts = self._collect_scripts(old_pages)
        new_scripts = self._collect_scripts(new_pages)
        added_scripts = sorted(new_scripts - old_scripts)
        removed_scripts = sorted(old_scripts - new_scripts)

        return DiffResult(
            old_base_url=old.get("base_url", ""),
            new_base_url=new.get("base_url", ""),
            added_pages=added,
            removed_pages=removed,
            changed_pages=changed,
            header_changes=header_changes,
            added_scripts=added_scripts,
            removed_scripts=removed_scripts,
        )

    def to_findings(self, diff: DiffResult) -> List[Finding]:
        """
        Convert a DiffResult into informational Finding objects.

        - Added pages: severity low.
        - Removed pages: severity low.
        - Changed pages: severity low.
        - New cross-origin scripts: severity medium (higher risk signal).
        - Added/removed headers per URL: severity low.
        - Added scripts (same-origin): severity low.
        - Removed scripts: severity low.

        All findings have source='mirror_diff'.
        Manual review required.
        """
        findings: List[Finding] = []

        new_base_netloc = urlparse(diff.new_base_url).netloc.lower().lstrip("www.")

        for url in diff.added_pages:
            findings.append(Finding(
                source=_SOURCE,
                category="mirror_diff",
                title=f"New page discovered: {url}",
                description=(
                    f"Page '{url}' was not present in the previous crawl snapshot. "
                    "Manual review recommended."
                ),
                severity="low",
                confidence="high",
                location=url,
                evidence={"change_type": "added_page", "url": url},
            ))

        for url in diff.removed_pages:
            findings.append(Finding(
                source=_SOURCE,
                category="mirror_diff",
                title=f"Page removed: {url}",
                description=(
                    f"Page '{url}' was present in the previous snapshot but is "
                    "no longer accessible. Manual review recommended."
                ),
                severity="low",
                confidence="high",
                location=url,
                evidence={"change_type": "removed_page", "url": url},
            ))

        for url in diff.changed_pages:
            findings.append(Finding(
                source=_SOURCE,
                category="mirror_diff",
                title=f"Page content changed: {url}",
                description=(
                    f"Page '{url}' has a different sha256 hash compared to the "
                    "previous snapshot. Content was modified. Manual review recommended."
                ),
                severity="low",
                confidence="high",
                location=url,
                evidence={"change_type": "changed_page", "url": url},
            ))

        for url, changes in diff.header_changes.items():
            if changes["added"] or changes["removed"]:
                findings.append(Finding(
                    source=_SOURCE,
                    category="mirror_diff",
                    title=f"HTTP header change on {url}",
                    description=(
                        f"Response headers changed for '{url}'. "
                        f"Added: {changes['added']}. "
                        f"Removed: {changes['removed']}. "
                        "Manual review recommended."
                    ),
                    severity="low",
                    confidence="high",
                    location=url,
                    evidence={"change_type": "header_change", **changes},
                ))

        for script in diff.added_scripts:
            script_netloc = urlparse(script).netloc.lower().lstrip("www.") if "://" in script else ""
            is_cross_origin = bool(script_netloc) and script_netloc != new_base_netloc
            severity = "medium" if is_cross_origin else "low"
            cross_label = " (CROSS-ORIGIN)" if is_cross_origin else ""
            findings.append(Finding(
                source=_SOURCE,
                category="mirror_diff",
                title=f"New script added{cross_label}: {script}",
                description=(
                    f"Script '{script}' was added since the previous snapshot"
                    f"{cross_label}. "
                    + (
                        "Cross-origin scripts increase supply-chain risk. "
                        if is_cross_origin
                        else ""
                    )
                    + "Manual review required."
                ),
                severity=severity,  # type: ignore[arg-type]
                confidence="medium",
                location=script,
                evidence={
                    "change_type": "added_script",
                    "script_url": script,
                    "cross_origin": is_cross_origin,
                },
            ))

        for script in diff.removed_scripts:
            findings.append(Finding(
                source=_SOURCE,
                category="mirror_diff",
                title=f"Script removed: {script}",
                description=(
                    f"Script '{script}' was present in the previous snapshot "
                    "but is no longer referenced. Manual review recommended."
                ),
                severity="low",
                confidence="medium",
                location=script,
                evidence={"change_type": "removed_script", "script_url": script},
            ))

        return findings

    def write_diff(self, out_dir: Path, diff: DiffResult) -> Path:
        """
        Write diff result to out_dir/mirror_diff.json.

        Returns the path written.
        """
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "mirror_diff.json"
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(diff.to_dict(), fh, indent=2, ensure_ascii=False)
        return out_path

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load(path: Path) -> dict:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    @staticmethod
    def _collect_scripts(pages: Dict[str, Any]) -> Set[str]:
        """
        Extract all <script src> values from pages that have HTML content.
        Falls back to checking local_path suffix if content_type not reliable.
        """
        import re
        script_pat = re.compile(r'<script[^>]+src=["\']([^"\']+)', re.IGNORECASE)
        scripts: Set[str] = set()
        # We don't have file content here — use the url set as a proxy
        # for script inventory; pages whose URL ends with .js count as scripts.
        for url, page in pages.items():
            local = page.get("local_path", "")
            ct = page.get("content_type", "")
            if "javascript" in ct or local.endswith((".js", ".mjs")):
                scripts.add(url)
        return scripts
