"""
Unified findings schema for PurpleForge static analysis.

Defensive static analysis only. Authorized binaries only. Does not generate exploits.

This module defines the canonical Finding model that all analyzers (binary, web, etc.)
emit into. It serves as the architectural backbone for the findings pipeline.
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, model_validator


def compute_finding_id(
    source: str,
    category: str,
    location: Optional[str],
    description: str,
) -> str:
    """
    Compute a deterministic 16-hex-char finding ID from normalized inputs.

    Lowercases and strips all fields, joins with '|', sha256-hashes the result,
    returns the first 16 hex characters.

    Args:
        source: Finding source identifier (e.g. "ghidra_binary").
        category: Finding category (e.g. "suspicious_import").
        location: Optional location string (e.g. function name or section).
        description: Human-readable description of the finding.

    Returns:
        16-character lowercase hex string.
    """
    parts = [
        source.lower().strip(),
        category.lower().strip(),
        (location or "").lower().strip(),
        description.lower().strip(),
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class Finding(BaseModel):
    """
    Normalized security finding produced by any PurpleForge analyzer.

    Severity is a practical heuristic label (low / medium / high).
    It does NOT represent a CVSS score or any formal vulnerability rating.
    Manual review is always required.
    """

    finding_id: str = Field(default="", description="Deterministic 16-char hex ID (auto-computed if empty).")
    source: str = Field(..., description="Analyzer that produced this finding, e.g. 'ghidra_binary'.")
    category: str = Field(..., description="Finding category, e.g. 'suspicious_import', 'rwx_section', 'suspicious_string'.")
    title: str = Field(..., description="Short human-readable title.")
    description: str = Field(..., description="Detailed description of the finding.")
    severity: Literal["low", "medium", "high"] = Field(
        ...,
        description="Heuristic severity label only. NOT a CVSS score. Manual review required.",
    )
    confidence: Literal["low", "medium", "high"] = Field(
        ...,
        description="Heuristic confidence in this finding. NOT a formal probability.",
    )
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Raw evidence dict from the analyzer.")
    location: Optional[str] = Field(default=None, description="Optional location (function name, section, address, etc.).")
    file_path: Optional[str] = Field(default=None, description="Path to the analyzed file, if applicable.")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="UTC timestamp when this finding was created.")

    @model_validator(mode="after")
    def _backfill_finding_id(self) -> "Finding":
        """Auto-compute finding_id when not provided."""
        if not self.finding_id:
            self.finding_id = compute_finding_id(
                self.source,
                self.category,
                self.location,
                self.description,
            )
        return self

    model_config = {"populate_by_name": True}


def summarize(findings: List[Finding]) -> Dict[str, Any]:
    """
    Produce aggregate counts for a list of findings.

    Args:
        findings: List of Finding instances to summarize.

    Returns:
        Dict with keys:
          - total (int)
          - by_severity (dict with keys low, medium, high)
          - by_category (dict mapping category -> count)
    """
    by_severity: Dict[str, int] = {"low": 0, "medium": 0, "high": 0}
    by_category: Dict[str, int] = {}

    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_category[f.category] = by_category.get(f.category, 0) + 1

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
    }


def dump_findings(findings: List[Finding], path: Path) -> None:
    """
    Serialize findings to a UTF-8 pretty-printed JSON file.

    Datetimes are serialized as ISO 8601 strings.

    Args:
        findings: List of Finding instances to write.
        path: Destination file path (parent directory must exist).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    records = []
    for f in findings:
        d = f.model_dump()
        # Serialize datetime to ISO 8601
        if isinstance(d.get("created_at"), datetime):
            d["created_at"] = d["created_at"].isoformat()
        records.append(d)

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2, ensure_ascii=False)


def load_findings(path: Path) -> List[Finding]:
    """
    Load findings from a UTF-8 JSON file written by dump_findings.

    Args:
        path: Path to the JSON file.

    Returns:
        List of validated Finding instances.
    """
    with open(path, "r", encoding="utf-8") as fh:
        records = json.load(fh)
    return [Finding(**r) for r in records]
