"""Platform-specific utilities for Windows 11 compatibility."""

import platform
import sys
from pathlib import Path
from typing import Dict


def get_platform_info() -> Dict[str, str]:
    """Get platform information for run metadata."""
    return {
        "os": platform.system(),
        "os_version": platform.version(),
        "python_version": sys.version.split()[0],
        "architecture": platform.machine(),
    }


def get_user_config_dir() -> Path:
    r"""
    Get user configuration directory in a platform-aware manner.

    On Windows: %USERPROFILE%\.purpleforge
    On Linux/Mac: ~/.purpleforge
    """
    if platform.system() == "Windows":
        base = Path.home()
    else:
        base = Path.home()

    config_dir = base / ".purpleforge"
    return config_dir


def ensure_long_path_support() -> None:
    """
    Check for long path support on Windows.

    This is informational only - actual long path support requires
    registry changes or app manifest on Windows.
    """
    if platform.system() == "Windows" and sys.version_info >= (3, 6):
        # Python 3.6+ has better long path support on Windows
        pass


def normalize_path(path: Path) -> Path:
    """
    Normalize path for cross-platform compatibility.

    Resolves relative paths and handles both forward and backslashes.
    """
    return path.resolve()
