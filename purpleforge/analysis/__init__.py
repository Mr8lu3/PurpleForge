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
]
