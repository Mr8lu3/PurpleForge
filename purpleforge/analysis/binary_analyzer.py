"""
Ghidra-backed binary analyzer producing normalized findings.

Defensive static analysis only. Authorized binaries only. Does not generate exploits.

This module wraps the GhidraAnalyzer to convert raw Ghidra output and suspicious
indicators into canonical Finding objects, writing both the raw Ghidra JSON and
a normalized findings JSON to the output directory.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from purpleforge.analysis.findings_schema import Finding, dump_findings
from purpleforge.analysis.ghidra_adapter import GhidraAnalyzer, get_ghidra_analyzer
from purpleforge.utils.exceptions import AnalysisError
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)

# Confidence mapping by indicator type (heuristic — not a formal probability)
_CONFIDENCE_MAP: Dict[str, str] = {
    "suspicious_section": "high",
    "suspicious_import": "medium",
    "suspicious_string": "low",
}


class BinaryAnalyzer:
    """
    Defensive static binary analyzer backed by Ghidra headless analysis.

    Converts Ghidra suspicious indicators into normalized Finding objects.
    Authorized binaries only. No exploit generation.
    """

    def __init__(self, ghidra_analyzer: Optional[GhidraAnalyzer] = None) -> None:
        """
        Initialize BinaryAnalyzer.

        Args:
            ghidra_analyzer: Optional pre-constructed GhidraAnalyzer instance.
                             If None, calls get_ghidra_analyzer() to obtain one.
        """
        self._analyzer = ghidra_analyzer if ghidra_analyzer is not None else get_ghidra_analyzer()

    def analyze(
        self,
        binary_path: Path,
        output_dir: Path,
        timeout: int = 300,
    ) -> List[Finding]:
        """
        Analyze a binary and return normalized findings.

        Authorized binaries only. Defensive static analysis only.

        Steps:
          1. Validates Ghidra availability and binary existence.
          2. Runs Ghidra headless analysis (writes ghidra_analysis.json).
          3. Converts suspicious indicators to Finding objects.
          4. Writes normalized findings to binary_findings.json.

        Args:
            binary_path: Path to the binary to analyze (authorized use only).
            output_dir: Directory to write output files into.
            timeout: Ghidra analysis timeout in seconds (default 300).

        Returns:
            List of normalized Finding objects.

        Raises:
            AnalysisError: If Ghidra is unavailable, binary is missing, or analysis fails.
        """
        if self._analyzer is None:
            raise AnalysisError(
                "Ghidra not available",
                hint=(
                    "Set GHIDRA_HOME to a valid Ghidra install directory. "
                    "Only authorized binaries should be analyzed."
                ),
            )

        if not binary_path.exists():
            raise AnalysisError(f"Binary not found: {binary_path}")

        output_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Starting Ghidra analysis of {binary_path.name}")
        results = self._analyzer.analyze(binary_path, output_dir=output_dir, timeout=timeout)

        if results is None:
            raise AnalysisError(
                "Ghidra analysis failed — see logs",
                hint="Check GHIDRA_HOME and that the binary is a supported format.",
            )

        # Confirm ghidra_analysis.json was written (GhidraAnalyzer handles this)
        ghidra_json = output_dir / "ghidra_analysis.json"
        if not ghidra_json.exists():
            logger.warning("ghidra_analysis.json not found in output_dir after analysis")

        # Convert indicators to normalized findings
        indicators = self._analyzer.get_suspicious_indicators(results)
        findings: List[Finding] = []
        for indicator in indicators:
            finding = self._indicator_to_finding(indicator, binary_path)
            findings.append(finding)

        # Write normalized findings
        findings_path = output_dir / "binary_findings.json"
        dump_findings(findings, findings_path)
        logger.info(f"Wrote {len(findings)} finding(s) to {findings_path}")

        return findings

    def _indicator_to_finding(
        self,
        indicator: Dict[str, Any],
        binary_path: Path,
    ) -> Finding:
        """
        Convert a raw GhidraAnalyzer indicator dict into a normalized Finding.

        Severity is passed through from the indicator (low|medium|high) — heuristic only.
        Confidence is mapped by indicator type: suspicious_section→high,
        suspicious_import→medium, suspicious_string→low.

        Args:
            indicator: Raw indicator dict from get_suspicious_indicators().
            binary_path: Path to the analyzed binary (for file_path field).

        Returns:
            Normalized Finding instance with auto-computed finding_id.
        """
        indicator_type = indicator.get("type", "unknown")
        value = indicator.get("value", "")
        description = indicator.get("description", "No description provided")
        severity = indicator.get("severity", "low")

        # Ensure severity is one of the allowed literals; fall back to "low"
        if severity not in ("low", "medium", "high"):
            severity = "low"

        confidence = _CONFIDENCE_MAP.get(indicator_type, "low")

        # Build a short title from description (first 80 chars, no newlines)
        title = description.replace("\n", " ").strip()[:80]

        return Finding(
            source="ghidra_binary",
            category=indicator_type,
            title=title,
            description=description,
            severity=severity,  # type: ignore[arg-type]
            confidence=confidence,  # type: ignore[arg-type]
            location=value if value else None,
            file_path=str(binary_path),
            evidence=dict(indicator),
        )
