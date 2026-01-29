"""Target ownership verification implementation."""

import hashlib
import secrets
from datetime import datetime
from enum import Enum
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

from purpleforge.utils.exceptions import VerificationError
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


class VerificationStatus(str, Enum):
    """Verification outcome status."""

    VERIFIED = "verified"
    DOCKER_VERIFIED = "docker_verified"
    FAILED = "failed"
    TIMEOUT = "timeout"
    ERROR = "error"
    SKIPPED = "skipped"


class VerificationResult:
    """Result of verification attempt."""

    def __init__(
        self,
        status: VerificationStatus,
        checked_at: datetime,
        method: str,
        message: str,
    ):
        self.status = status
        self.checked_at = checked_at
        self.method = method
        self.message = message


def generate_verification_token() -> str:
    """
    Generate a secure random verification token.

    Returns:
        32-character hexadecimal token
    """
    return secrets.token_hex(16)


def hash_token(token: str) -> str:
    """
    Hash a verification token for storage.

    Args:
        token: Plain token string

    Returns:
        SHA-256 hash of token
    """
    return hashlib.sha256(token.encode()).hexdigest()


def is_local_target(base_url: str) -> bool:
    """
    Check if target is a local/Docker environment.

    Args:
        base_url: Target base URL

    Returns:
        True if target appears to be local/Docker
    """
    parsed = urlparse(base_url)
    hostname = parsed.hostname or ""

    local_indicators = [
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        ".local",
    ]

    return any(indicator in hostname.lower() for indicator in local_indicators)


def verify_target_ownership(
    base_url: str,
    expected_token: str,
    timeout: int = 10,
) -> VerificationResult:
    """
    Verify ownership of a target by checking for verification token.

    For web targets, attempts to fetch:
        {base_url}/.well-known/purpleforge-verify.txt

    The file must contain the expected_token.

    For local/Docker targets, applies relaxed verification.

    Args:
        base_url: Target base URL
        expected_token: Token to verify against
        timeout: Request timeout in seconds

    Returns:
        VerificationResult with status and details

    Raises:
        VerificationError: If verification fails critically
    """
    checked_at = datetime.utcnow()

    # Normalize base URL
    if not base_url.startswith(("http://", "https://")):
        base_url = f"http://{base_url}"

    # Check if local target
    if is_local_target(base_url):
        logger.info(f"Target {base_url} appears to be local/Docker environment")
        # For MVP, we'll still do HTTP verification but with relaxed failure handling
        # Future: implement Docker label inspection

    # Construct verification URL
    verify_url = urljoin(base_url, "/.well-known/purpleforge-verify.txt")

    logger.info(f"Attempting verification at: {verify_url}")

    try:
        response = requests.get(
            verify_url,
            timeout=timeout,
            allow_redirects=False,
            verify=True,  # Verify SSL certificates
        )

        if response.status_code == 200:
            content = response.text.strip()

            # Check if token matches
            if content == expected_token:
                logger.info("Verification successful - token matched")
                return VerificationResult(
                    status=VerificationStatus.VERIFIED,
                    checked_at=checked_at,
                    method="http_wellknown",
                    message="Token verified successfully",
                )
            else:
                logger.warning("Verification failed - token mismatch")
                return VerificationResult(
                    status=VerificationStatus.FAILED,
                    checked_at=checked_at,
                    method="http_wellknown",
                    message="Token mismatch",
                )
        else:
            logger.warning(f"Verification failed - HTTP {response.status_code}")
            return VerificationResult(
                status=VerificationStatus.FAILED,
                checked_at=checked_at,
                method="http_wellknown",
                message=f"HTTP {response.status_code}",
            )

    except requests.Timeout:
        logger.error("Verification timeout")
        return VerificationResult(
            status=VerificationStatus.TIMEOUT,
            checked_at=checked_at,
            method="http_wellknown",
            message="Request timeout",
        )
    except requests.RequestException as e:
        logger.error(f"Verification error: {e}")
        return VerificationResult(
            status=VerificationStatus.ERROR,
            checked_at=checked_at,
            method="http_wellknown",
            message=str(e),
        )
