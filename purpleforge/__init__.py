"""
PurpleForge - CLI-driven purple team training and evaluation platform.

A security assessment tool with strict ethical guardrails, comprehensive auditability,
and Windows 11 first-class support.
"""

__version__ = "0.1.0"
__tool_name__ = "PurpleForge"

from purpleforge.utils.exceptions import (
    PurpleForgeError,
    VerificationError,
    ScenarioValidationError,
)

__all__ = [
    "__version__",
    "__tool_name__",
    "PurpleForgeError",
    "VerificationError",
    "ScenarioValidationError",
]
