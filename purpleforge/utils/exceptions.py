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


class AnalysisError(PurpleForgeError):
    """Error during static binary analysis."""

    pass


class EvaluationError(PurpleForgeError):
    """Error during evaluation framework operation (authorized datasets only)."""

    pass


class CampaignError(PurpleForgeError):
    """Error in campaign definition or orchestration (authorized targets only)."""

    pass


class MirrorError(PurpleForgeError):
    """
    Error during site mirror or static analysis operation.

    Raised when:
    - The target is not in the verified allowlist (ownership gate).
    - robots.txt disallows crawling for the configured user-agent.
    - A crawler configuration parameter is out of bounds.

    Authorized, verified targets only; polite crawl; defensive static analysis only;
    no exploitation; manual review required.
    """

    pass
