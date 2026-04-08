"""Static analysis and artifact management."""

from purpleforge.analysis.artifacts import (
    ArtifactManager,
    ArtifactMetadata,
    ArtifactHashes,
    calculate_hashes,
    detect_file_type,
)
from purpleforge.analysis.pe_analyzer import PEAnalyzer, analyze_pe
from purpleforge.analysis.ghidra_adapter import GhidraAnalyzer, get_ghidra_analyzer
from purpleforge.analysis.findings_schema import (
    Finding,
    compute_finding_id,
    summarize,
    dump_findings,
    load_findings,
)
from purpleforge.analysis.binary_analyzer import BinaryAnalyzer

__all__ = [
    "ArtifactManager",
    "ArtifactMetadata",
    "ArtifactHashes",
    "calculate_hashes",
    "detect_file_type",
    "PEAnalyzer",
    "analyze_pe",
    "GhidraAnalyzer",
    "get_ghidra_analyzer",
    "Finding",
    "compute_finding_id",
    "summarize",
    "dump_findings",
    "load_findings",
    "BinaryAnalyzer",
]
