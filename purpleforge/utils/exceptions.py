"""Custom exception hierarchy for PurpleForge."""

from typing import Optional


class PurpleForgeError(Exception):
    """Base exception for PurpleForge with Rich-formatted output."""

    def __init__(self, message: str, hint: Optional[str] = None) -> None:
        self.message = message
        self.hint = hint
        super().__init__(message)

    def __str__(self) -> str:
        if self.hint:
            return f"{self.message}\nHint: {self.hint}"
        return self.message


class VerificationError(PurpleForgeError):
    """Target ownership verification failed."""

    pass


class ScenarioValidationError(PurpleForgeError):
    """Scenario YAML failed schema validation."""

    pass


class WorkspaceError(PurpleForgeError):
    """Workspace creation or access error."""

    pass


class ConfigurationError(PurpleForgeError):
    """Configuration file error."""

    pass


class RunnerError(PurpleForgeError):
    """Error during scenario execution."""

    pass


class ReportError(PurpleForgeError):
    """Error during report generation."""

    pass
