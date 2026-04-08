"""
purpleforge.audit.redaction — PII and secret redaction pipeline.

Redaction protects data subjects per UK DPA 2018 / GDPR Article 5(1)(f)
(integrity and confidentiality principle) and supports the data minimisation
principle (Article 5(1)(c)).  Telemetry written to disk is sanitised at write
time so that no assessment log constitutes a personal-data store without
the operator's explicit intent.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Built-in patterns:  (compiled_pattern, replacement_string)
# ---------------------------------------------------------------------------

_BUILTIN_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    # Private key PEM blocks (multi-line, consumed first)
    (
        re.compile(
            r"-----BEGIN [A-Z ]* PRIVATE KEY-----.*?-----END [A-Z ]* PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    # JWT  eyJ<b64>.<b64>.<b64>
    (
        re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
        "[REDACTED_JWT]",
    ),
    # AWS access key
    (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "[REDACTED_AWS_KEY]",
    ),
    # Bearer token
    (
        re.compile(r"Bearer\s+\S+", re.IGNORECASE),
        "Bearer [REDACTED]",
    ),
    # api-key / x-api-key header  — keep key name, redact value
    (
        re.compile(
            r"(api[_\-]?key|x-api-key)\s*[:=]\s*\S+",
            re.IGNORECASE,
        ),
        r"\1=[REDACTED]",
    ),
    # password = / password :
    (
        re.compile(r"password\s*[:=]\s*\S+", re.IGNORECASE),
        "password=[REDACTED]",
    ),
    # UK NI number  AB 12 34 56 C  (loose)
    (
        re.compile(
            r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
            re.IGNORECASE,
        ),
        "[REDACTED_PII]",
    ),
    # UK postcode  SW1A 1AA, EC1A 1BB, etc. (loose)
    (
        re.compile(
            r"\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b",
            re.IGNORECASE,
        ),
        "[REDACTED_PII]",
    ),
    # UK / international phone (loose): +44 7xxx xxxxxx, 07xxx xxxxxx, etc.
    (
        re.compile(
            r"(?:\+44\s?|0)(?:\d\s?){9,10}\d",
        ),
        "[REDACTED_PII]",
    ),
    # Email address
    (
        re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
        "[REDACTED_EMAIL]",
    ),
]

# Keys whose *values* should always be redacted in dict walks
_SENSITIVE_KEY_RE = re.compile(
    r"(password|secret|token|api[_\-]?key|authorization)$",
    re.IGNORECASE,
)


class Redactor:
    """
    Redact PII and secrets from free-text strings and nested dicts.

    Parameters
    ----------
    enabled:
        When *False* the instance is a pure pass-through — all methods return
        their input unchanged.  Useful when ``Config.redaction_enabled`` is
        *False* (e.g. isolated lab with no real user data).
    custom_patterns:
        Additional ``(pattern_str, replacement_str)`` tuples compiled and
        applied *after* the built-in set.
    """

    def __init__(
        self,
        *,
        enabled: bool = True,
        custom_patterns: Optional[List[Tuple[str, str]]] = None,
    ) -> None:
        self.enabled = enabled
        self._patterns: List[Tuple[re.Pattern[str], str]] = list(_BUILTIN_PATTERNS)
        if custom_patterns:
            for raw_pat, replacement in custom_patterns:
                try:
                    self._patterns.append((re.compile(raw_pat), replacement))
                except re.error as exc:
                    logger.warning("Redactor: invalid custom pattern %r: %s", raw_pat, exc)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def redact_text(self, text: str) -> str:
        """
        Apply all built-in and custom patterns to *text*.

        Returns the (possibly modified) string.  Never raises — on any
        unexpected error the original *text* is returned with a warning logged.
        """
        if not self.enabled:
            return text
        if not isinstance(text, str):
            try:
                text = str(text)
            except Exception:
                return text
        try:
            for pattern, replacement in self._patterns:
                text = pattern.sub(replacement, text)
            return text
        except Exception as exc:
            logger.warning("Redactor.redact_text: unexpected error: %s", exc)
            return text

    def redact_dict(self, obj: Any) -> Any:
        """
        Deep-walk *obj* (dict or list) and redact string values.

        - Dict values whose *key* matches the sensitive-key regex are replaced
          wholesale with ``"[REDACTED]"`` regardless of content.
        - All other string values are passed through :meth:`redact_text`.
        - Non-string leaf values are left untouched.
        - Never raises — on error returns the input with a warning logged.
        """
        if not self.enabled:
            return obj
        try:
            return self._walk(obj)
        except Exception as exc:
            logger.warning("Redactor.redact_dict: unexpected error: %s", exc)
            return obj

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _walk(self, obj: Any, *, _key: Optional[str] = None) -> Any:
        if isinstance(obj, dict):
            out: Dict[str, Any] = {}
            for k, v in obj.items():
                if isinstance(k, str) and _SENSITIVE_KEY_RE.search(k):
                    # Value for sensitive key — redact entirely
                    out[k] = "[REDACTED]" if v is not None else v
                else:
                    out[k] = self._walk(v, _key=k if isinstance(k, str) else None)
            return out
        if isinstance(obj, list):
            return [self._walk(item) for item in obj]
        if isinstance(obj, str):
            return self.redact_text(obj)
        return obj


# ---------------------------------------------------------------------------
# Module-level singleton and convenience functions
# ---------------------------------------------------------------------------

redactor = Redactor()


def redact_text(text: str) -> str:
    """Apply default redactor to a string."""
    return redactor.redact_text(text)


def redact_dict(obj: Any) -> Any:
    """Apply default redactor to a dict/list structure."""
    return redactor.redact_dict(obj)
