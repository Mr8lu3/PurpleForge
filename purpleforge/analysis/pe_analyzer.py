"""PE (Portable Executable) file analysis without Ghidra."""

import math
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.

    High entropy (>7.0) may indicate packing/encryption.

    Args:
        data: Bytes to analyze

    Returns:
        Entropy value (0-8 for byte data)
    """
    if not data:
        return 0.0

    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    entropy = 0.0
    length = len(data)
    for count in freq.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy


def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
    """
    Extract ASCII and Unicode strings from binary data.

    Args:
        data: Binary data
        min_length: Minimum string length

    Returns:
        List of extracted strings
    """
    strings = []

    # ASCII strings
    current = []
    for byte in data:
        if 32 <= byte < 127:  # Printable ASCII
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []
    if len(current) >= min_length:
        strings.append("".join(current))

    # Simple Unicode detection (UTF-16LE with null bytes)
    current = []
    i = 0
    while i < len(data) - 1:
        if 32 <= data[i] < 127 and data[i + 1] == 0:
            current.append(chr(data[i]))
            i += 2
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []
            i += 1
    if len(current) >= min_length:
        strings.append("".join(current))

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for s in strings:
        if s not in seen:
            seen.add(s)
            unique.append(s)

    return unique[:500]  # Limit to 500 strings


class PEAnalyzer:
    """
    Analyze PE (Portable Executable) files.

    Uses pefile library if available, falls back to manual parsing.
    """

    def __init__(self, file_path: Path):
        """
        Initialize PE analyzer.

        Args:
            file_path: Path to PE file
        """
        self.file_path = file_path
        self.pe = None
        self._use_pefile = False

        try:
            import pefile
            self.pe = pefile.PE(str(file_path))
            self._use_pefile = True
        except ImportError:
            logger.info("pefile not installed, using basic analysis")
        except Exception as e:
            logger.warning(f"Failed to parse PE with pefile: {e}")

    def analyze(self) -> Dict[str, Any]:
        """
        Perform comprehensive PE analysis.

        Returns:
            Analysis results dictionary
        """
        if self._use_pefile and self.pe:
            return self._analyze_with_pefile()
        return self._analyze_basic()

    def _analyze_with_pefile(self) -> Dict[str, Any]:
        """Analyze using pefile library."""
        pe = self.pe

        # Basic info
        results = {
            "format": "PE",
            "machine": self._get_machine_type(),
            "timestamp": self._get_timestamp(),
            "subsystem": self._get_subsystem(),
            "is_dll": pe.is_dll(),
            "is_exe": pe.is_exe(),
            "is_driver": pe.is_driver(),
        }

        # Entry point
        results["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        results["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)

        # Sections
        results["sections"] = []
        for section in pe.sections:
            section_data = section.get_data()
            entropy = calculate_entropy(section_data)
            results["sections"].append({
                "name": section.Name.decode("utf-8", errors="ignore").rstrip("\x00"),
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(entropy, 2),
                "characteristics": hex(section.Characteristics),
                "is_executable": bool(section.Characteristics & 0x20000000),
                "is_writable": bool(section.Characteristics & 0x80000000),
            })

        # Imports
        results["imports"] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore")
                for imp in entry.imports:
                    func_name = imp.name.decode("utf-8", errors="ignore") if imp.name else f"Ordinal_{imp.ordinal}"
                    results["imports"].append({
                        "dll": dll_name,
                        "function": func_name,
                        "address": hex(imp.address) if imp.address else None,
                    })

        # Exports
        results["exports"] = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exp_name = exp.name.decode("utf-8", errors="ignore") if exp.name else f"Ordinal_{exp.ordinal}"
                results["exports"].append({
                    "name": exp_name,
                    "ordinal": exp.ordinal,
                    "address": hex(exp.address) if exp.address else None,
                })

        # Resources (summary only)
        results["resources"] = []
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                type_name = str(res_type.name) if res_type.name else str(res_type.struct.Id)
                if hasattr(res_type, "directory"):
                    for res_id in res_type.directory.entries:
                        results["resources"].append({
                            "type": type_name,
                            "id": str(res_id.name) if res_id.name else str(res_id.struct.Id),
                        })

        # Strings (from file)
        with open(self.file_path, "rb") as f:
            data = f.read()
        results["strings"] = extract_strings(data)[:200]

        # Overall entropy
        results["entropy"] = round(calculate_entropy(data), 2)

        # Suspicious indicators
        results["indicators"] = self._detect_suspicious_indicators(results)

        return results

    def _analyze_basic(self) -> Dict[str, Any]:
        """Basic analysis without pefile."""
        with open(self.file_path, "rb") as f:
            data = f.read()

        results = {
            "format": "PE",
            "analysis_type": "basic",
            "file_size": len(data),
            "entropy": round(calculate_entropy(data), 2),
            "strings": extract_strings(data)[:200],
        }

        # Check MZ header
        if data[:2] == b"MZ":
            results["has_mz_header"] = True

            # Get PE header offset
            if len(data) > 0x3c + 4:
                pe_offset = int.from_bytes(data[0x3c:0x40], "little")
                if len(data) > pe_offset + 4:
                    pe_sig = data[pe_offset:pe_offset + 4]
                    results["has_pe_signature"] = (pe_sig == b"PE\x00\x00")

        results["indicators"] = self._detect_basic_indicators(results)

        return results

    def _get_machine_type(self) -> str:
        """Get machine type string."""
        if not self.pe:
            return "Unknown"

        machine_types = {
            0x14c: "i386",
            0x8664: "AMD64",
            0x1c0: "ARM",
            0xaa64: "ARM64",
        }
        return machine_types.get(self.pe.FILE_HEADER.Machine, f"Unknown (0x{self.pe.FILE_HEADER.Machine:x})")

    def _get_timestamp(self) -> Optional[str]:
        """Get compilation timestamp."""
        if not self.pe:
            return None
        try:
            ts = self.pe.FILE_HEADER.TimeDateStamp
            return datetime.utcfromtimestamp(ts).isoformat()
        except Exception:
            return None

    def _get_subsystem(self) -> str:
        """Get subsystem string."""
        if not self.pe:
            return "Unknown"

        subsystems = {
            1: "Native",
            2: "Windows GUI",
            3: "Windows Console",
            5: "OS/2 Console",
            7: "POSIX Console",
            9: "Windows CE GUI",
            10: "EFI Application",
            11: "EFI Boot Service Driver",
            12: "EFI Runtime Driver",
            13: "EFI ROM",
            14: "Xbox",
            16: "Windows Boot Application",
        }
        return subsystems.get(self.pe.OPTIONAL_HEADER.Subsystem, "Unknown")

    def _detect_suspicious_indicators(self, results: Dict[str, Any]) -> List[Dict[str, str]]:
        """Detect suspicious indicators in PE analysis."""
        indicators = []

        # High entropy suggests packing
        if results.get("entropy", 0) > 7.0:
            indicators.append({
                "type": "high_entropy",
                "description": f"High file entropy ({results['entropy']}) may indicate packing",
                "severity": "medium",
            })

        # Section entropy check
        for section in results.get("sections", []):
            if section.get("entropy", 0) > 7.5:
                indicators.append({
                    "type": "packed_section",
                    "description": f"Section {section['name']} has high entropy ({section['entropy']})",
                    "severity": "medium",
                })
            # RWX sections
            if section.get("is_executable") and section.get("is_writable"):
                indicators.append({
                    "type": "rwx_section",
                    "description": f"Section {section['name']} is both writable and executable",
                    "severity": "high",
                })

        # Suspicious imports
        suspicious_apis = [
            "VirtualAlloc", "VirtualProtect", "CreateRemoteThread",
            "WriteProcessMemory", "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
        ]
        for imp in results.get("imports", []):
            if any(api in imp.get("function", "") for api in suspicious_apis):
                indicators.append({
                    "type": "suspicious_import",
                    "description": f"Suspicious API: {imp['function']} from {imp['dll']}",
                    "severity": "medium",
                })

        # Suspicious strings
        suspicious_strings = ["http://", "https://", "cmd.exe", "powershell", "reg add"]
        for s in results.get("strings", []):
            for sus in suspicious_strings:
                if sus.lower() in s.lower():
                    indicators.append({
                        "type": "suspicious_string",
                        "description": f"Suspicious string: {s[:50]}...",
                        "severity": "low",
                    })
                    break

        return indicators[:50]  # Limit indicators

    def _detect_basic_indicators(self, results: Dict[str, Any]) -> List[Dict[str, str]]:
        """Detect indicators from basic analysis."""
        indicators = []

        if results.get("entropy", 0) > 7.0:
            indicators.append({
                "type": "high_entropy",
                "description": f"High entropy ({results['entropy']}) may indicate packing",
                "severity": "medium",
            })

        return indicators

    def close(self) -> None:
        """Close PE file."""
        if self.pe:
            self.pe.close()


def analyze_pe(file_path: Path) -> Dict[str, Any]:
    """
    Analyze a PE file.

    Args:
        file_path: Path to PE file

    Returns:
        Analysis results dictionary
    """
    analyzer = PEAnalyzer(file_path)
    try:
        return analyzer.analyze()
    finally:
        analyzer.close()
