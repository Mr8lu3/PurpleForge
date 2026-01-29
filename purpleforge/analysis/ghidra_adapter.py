"""Ghidra headless analyzer integration."""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


class GhidraAnalyzer:
    """
    Interface to Ghidra's headless analyzer.

    Requires GHIDRA_HOME environment variable to be set.
    """

    # Ghidra analysis script for extracting information
    ANALYSIS_SCRIPT = '''
# PurpleForge Ghidra Analysis Script
# Exports analysis results to JSON

from ghidra.program.model.listing import *
from ghidra.program.model.symbol import *
import json
import os

def get_functions():
    """Extract function information."""
    funcs = []
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        funcs.append({
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "size": func.getBody().getNumAddresses(),
            "is_external": func.isExternal(),
            "calling_convention": str(func.getCallingConventionName()),
            "return_type": str(func.getReturnType()),
            "param_count": func.getParameterCount(),
        })
    return funcs

def get_imports():
    """Extract import table."""
    imports = []
    st = currentProgram.getSymbolTable()
    for sym in st.getExternalSymbols():
        imports.append({
            "name": sym.getName(),
            "address": str(sym.getAddress()),
            "library": str(sym.getParentNamespace()),
        })
    return imports

def get_exports():
    """Extract export table."""
    exports = []
    st = currentProgram.getSymbolTable()
    for sym in st.getAllSymbols(True):
        if sym.isExternalEntryPoint():
            exports.append({
                "name": sym.getName(),
                "address": str(sym.getAddress()),
            })
    return exports

def get_strings():
    """Extract defined strings."""
    strings = []
    dm = currentProgram.getDataManager()
    data = currentProgram.getListing().getDefinedData(True)
    count = 0
    for d in data:
        if count >= 500:  # Limit to 500 strings
            break
        dt = d.getDataType()
        if "string" in dt.getName().lower():
            val = d.getValue()
            if val and len(str(val)) > 3:
                strings.append({
                    "address": str(d.getAddress()),
                    "value": str(val)[:200],  # Limit string length
                    "type": dt.getName(),
                })
                count += 1
    return strings

def get_sections():
    """Extract section information."""
    sections = []
    mem = currentProgram.getMemory()
    for block in mem.getBlocks():
        sections.append({
            "name": block.getName(),
            "start": str(block.getStart()),
            "end": str(block.getEnd()),
            "size": block.getSize(),
            "permissions": {
                "read": block.isRead(),
                "write": block.isWrite(),
                "execute": block.isExecute(),
            },
        })
    return sections

def get_metadata():
    """Extract program metadata."""
    return {
        "name": currentProgram.getName(),
        "language": str(currentProgram.getLanguage()),
        "compiler": str(currentProgram.getCompiler()),
        "format": str(currentProgram.getExecutableFormat()),
        "image_base": str(currentProgram.getImageBase()),
        "min_address": str(currentProgram.getMinAddress()),
        "max_address": str(currentProgram.getMaxAddress()),
    }

# Main analysis
output_path = os.environ.get("PURPLEFORGE_OUTPUT", "/tmp/ghidra_analysis.json")

results = {
    "metadata": get_metadata(),
    "sections": get_sections(),
    "functions": get_functions(),
    "imports": get_imports(),
    "exports": get_exports(),
    "strings": get_strings(),
}

with open(output_path, "w") as f:
    json.dump(results, f, indent=2)

print(f"Analysis complete. Results written to {output_path}")
'''

    def __init__(self, ghidra_home: Optional[str] = None):
        """
        Initialize Ghidra analyzer.

        Args:
            ghidra_home: Path to Ghidra installation (or uses GHIDRA_HOME env var)
        """
        self.ghidra_home = Path(ghidra_home or os.environ.get("GHIDRA_HOME", ""))
        self._validate_installation()

    def _validate_installation(self) -> bool:
        """Check if Ghidra is properly installed."""
        if not self.ghidra_home or not self.ghidra_home.exists():
            logger.warning("GHIDRA_HOME not set or invalid - Ghidra analysis unavailable")
            return False

        # Check for analyzeHeadless
        headless_path = self._get_headless_path()
        if not headless_path.exists():
            logger.warning(f"analyzeHeadless not found at {headless_path}")
            return False

        return True

    def _get_headless_path(self) -> Path:
        """Get path to analyzeHeadless script."""
        # Windows
        if os.name == "nt":
            return self.ghidra_home / "support" / "analyzeHeadless.bat"
        # Linux/Mac
        return self.ghidra_home / "support" / "analyzeHeadless"

    def is_available(self) -> bool:
        """Check if Ghidra analysis is available."""
        return self._validate_installation()

    def analyze(
        self,
        binary_path: Path,
        output_dir: Optional[Path] = None,
        timeout: int = 300,
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze a binary using Ghidra headless analyzer.

        Args:
            binary_path: Path to binary to analyze
            output_dir: Directory for analysis output (temp if not specified)
            timeout: Analysis timeout in seconds

        Returns:
            Analysis results dictionary or None if failed
        """
        if not self.is_available():
            logger.error("Ghidra is not available")
            return None

        if not binary_path.exists():
            logger.error(f"Binary not found: {binary_path}")
            return None

        # Create temp directory for Ghidra project
        with tempfile.TemporaryDirectory(prefix="purpleforge_ghidra_") as temp_dir:
            temp_path = Path(temp_dir)
            project_dir = temp_path / "project"
            project_dir.mkdir()

            # Write analysis script
            script_path = temp_path / "analyze_export.py"
            with open(script_path, "w") as f:
                f.write(self.ANALYSIS_SCRIPT)

            # Output path for results
            output_path = temp_path / "analysis_results.json"

            # Build command
            headless = self._get_headless_path()
            cmd = [
                str(headless),
                str(project_dir),
                "PurpleForgeProject",
                "-import", str(binary_path),
                "-postScript", str(script_path),
                "-deleteProject",
                "-noanalysis",  # We'll do targeted analysis
            ]

            # Set environment with output path
            env = os.environ.copy()
            env["PURPLEFORGE_OUTPUT"] = str(output_path)

            logger.info(f"Running Ghidra analysis on {binary_path.name}...")

            try:
                result = subprocess.run(
                    cmd,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=str(temp_path),
                )

                if result.returncode != 0:
                    logger.error(f"Ghidra analysis failed: {result.stderr[:500]}")
                    return None

                # Read results
                if output_path.exists():
                    with open(output_path, "r") as f:
                        results = json.load(f)

                    # Copy to output directory if specified
                    if output_dir:
                        output_dir.mkdir(parents=True, exist_ok=True)
                        final_path = output_dir / "ghidra_analysis.json"
                        with open(final_path, "w") as f:
                            json.dump(results, f, indent=2)

                    logger.info("Ghidra analysis complete")
                    return results
                else:
                    logger.error("Analysis output file not created")
                    return None

            except subprocess.TimeoutExpired:
                logger.error(f"Ghidra analysis timed out after {timeout}s")
                return None
            except Exception as e:
                logger.error(f"Ghidra analysis error: {e}")
                return None

    def get_functions(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract functions from analysis results."""
        return analysis_results.get("functions", [])

    def get_imports(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract imports from analysis results."""
        return analysis_results.get("imports", [])

    def get_suspicious_indicators(
        self,
        analysis_results: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """
        Identify potentially suspicious indicators in analysis.

        Args:
            analysis_results: Ghidra analysis results

        Returns:
            List of suspicious indicators with descriptions
        """
        indicators = []

        # Check for suspicious imports
        suspicious_imports = [
            "VirtualAlloc", "VirtualProtect", "CreateRemoteThread",
            "WriteProcessMemory", "ReadProcessMemory", "NtUnmapViewOfSection",
            "LoadLibrary", "GetProcAddress", "ShellExecute", "WinExec",
            "CreateProcess", "OpenProcess", "TerminateProcess",
            "RegSetValue", "RegCreateKey", "InternetOpen", "URLDownloadToFile",
            "WSAStartup", "connect", "send", "recv", "socket",
        ]

        imports = analysis_results.get("imports", [])
        for imp in imports:
            name = imp.get("name", "")
            if any(sus in name for sus in suspicious_imports):
                indicators.append({
                    "type": "suspicious_import",
                    "value": name,
                    "description": f"Potentially suspicious API import: {name}",
                    "severity": "medium",
                })

        # Check for suspicious strings
        suspicious_patterns = [
            ("http://", "URL string found"),
            ("https://", "URL string found"),
            (".exe", "Executable reference"),
            (".dll", "DLL reference"),
            ("cmd.exe", "Command shell reference"),
            ("powershell", "PowerShell reference"),
            ("reg add", "Registry modification"),
            ("password", "Password-related string"),
            ("admin", "Admin-related string"),
            ("HKEY_", "Registry key reference"),
        ]

        strings = analysis_results.get("strings", [])
        for s in strings:
            value = s.get("value", "").lower()
            for pattern, desc in suspicious_patterns:
                if pattern.lower() in value:
                    indicators.append({
                        "type": "suspicious_string",
                        "value": s.get("value", "")[:100],
                        "description": desc,
                        "severity": "low",
                    })
                    break

        # Check sections for anomalies
        sections = analysis_results.get("sections", [])
        for section in sections:
            perms = section.get("permissions", {})
            # RWX sections are suspicious
            if perms.get("read") and perms.get("write") and perms.get("execute"):
                indicators.append({
                    "type": "suspicious_section",
                    "value": section.get("name", ""),
                    "description": f"Section {section.get('name')} has RWX permissions",
                    "severity": "high",
                })

        return indicators


def get_ghidra_analyzer() -> Optional[GhidraAnalyzer]:
    """
    Get Ghidra analyzer instance if available.

    Returns:
        GhidraAnalyzer instance or None if Ghidra not installed
    """
    try:
        analyzer = GhidraAnalyzer()
        if analyzer.is_available():
            return analyzer
    except Exception:
        pass
    return None
