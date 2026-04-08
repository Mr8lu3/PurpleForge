"""
Evidence confidence scoring for the PurpleForge correlation engine.

This module implements a **documented heuristic scoring model**, not a statistical
classifier. Weights were selected by engineering judgment to reflect the relative
trustworthiness of each signal dimension and are documented here so they can be
cited and adjusted in coursework write-ups.

Scoring formula
---------------
Given a (ground_truth_step, candidate_evidence_event) pair:

    temporal_weight    = max(0.0, 1.0 - (delta_seconds / window_seconds))
    field_weight       = {"exact": 1.0, "regex": 0.75, "heuristic": 0.5}[field_match_strength]
    source_weight      = {"high": 1.0, "medium": 0.75, "low": 0.5}[source_reliability]
    corroboration_bonus = min(0.2, 0.05 * max(0, corroboration_count - 1))

    base       = 0.5 * temporal_weight + 0.3 * field_weight + 0.2 * source_weight
    confidence = min(1.0, base + corroboration_bonus)

    tier = "A" if confidence >= 0.8 else "B" if confidence >= 0.55 else "C"

Weight rationale
----------------
- temporal_weight (50 %): Proximity in time is the strongest single signal that an
  event is genuinely related to a ground-truth step; a linear decay within the
  correlation window is the simplest defensible model.
- field_weight (30 %): The precision of the matching logic directly affects
  false-positive risk; exact field matches warrant higher trust than heuristic
  keyword presence.
- source_weight (20 %): Source reliability captures the chain-of-custody quality of
  the log origin; built-in PurpleForge runner output is fully controlled, whereas
  externally ingested CSV data may have been transformed by unknown tools.
- corroboration_bonus (capped 20 %): Independent corroborating events reduce the
  probability that a match is coincidental; diminishing returns are applied after
  the first additional event.

Quality tiers
-------------
A: confidence >= 0.80  — high-quality match, suitable for automated decisions
B: confidence >= 0.55  — moderate-quality match, warrants analyst review
C: confidence <  0.55  — low-quality match, treat as a hint only
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Literal

from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

FieldMatchStrength = Literal["exact", "regex", "heuristic"]
SourceReliability = Literal["high", "medium", "low"]
QualityTier = Literal["A", "B", "C"]

# ---------------------------------------------------------------------------
# Lookup maps (exported so callers can introspect or override)
# ---------------------------------------------------------------------------

SOURCE_RELIABILITY_MAP: Dict[str, str] = {
    # Built-in PurpleForge runner outputs — fully controlled provenance.
    "web_requests": "high",
    "normalized_events": "high",
    # Structured external ingests — well-defined formats but external origin.
    "sysmon": "medium",
    "winevtx": "medium",
    "webserver": "medium",
    # Heuristic or weakly-structured ingests.
    "csv": "low",
}
"""Maps evidence source type identifiers to reliability levels.

Sources produced by PurpleForge's own runner are classified as *high* because
provenance and format are fully controlled. Recognised external structured log
sources (Sysmon, Windows Event XML, web-server access logs) are *medium*.
Unknown or CSV-derived sources default to *low* at call time via the
``_resolve_source_reliability`` helper.
"""

# TODO: Once the engine exposes distinct matcher names, map them here.
#       For now every match is treated as "heuristic" pending that refactor.
FIELD_MATCH_STRENGTH_MAP: Dict[str, str] = {
    "exact_field": "exact",
    "regex_pattern": "regex",
    "heuristic_keyword": "heuristic",
    # Default fallback key used when the engine has not yet distinguished matchers.
    "default": "heuristic",
}
"""Maps correlation matcher identifiers to field-match strength levels.

When the engine does not yet distinguish matchers, the caller should pass
``"heuristic"`` directly (or look up ``FIELD_MATCH_STRENGTH_MAP["default"]``).
"""

# ---------------------------------------------------------------------------
# Internal weight tables (mirrors the docstring formula)
# ---------------------------------------------------------------------------

_FIELD_WEIGHTS: Dict[str, float] = {
    "exact": 1.0,
    "regex": 0.75,
    "heuristic": 0.5,
}

_SOURCE_WEIGHTS: Dict[str, float] = {
    "high": 1.0,
    "medium": 0.75,
    "low": 0.5,
}

_TIER_THRESHOLDS: tuple[tuple[float, str], ...] = (
    (0.8, "A"),
    (0.55, "B"),
    (0.0, "C"),
)

# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConfidenceResult:
    """Immutable result of a single confidence computation.

    Attributes
    ----------
    confidence:
        Overall confidence score in [0.0, 1.0].
    quality_tier:
        Categorical tier derived from ``confidence``.
    breakdown:
        Per-component weights so a report can explain *why* a score was
        awarded.  Keys: ``temporal_weight``, ``field_weight``,
        ``source_weight``, ``corroboration_bonus``.
    """

    confidence: float
    quality_tier: QualityTier
    breakdown: Dict[str, float] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_source_reliability(source_type: str) -> SourceReliability:
    """Return reliability level for *source_type*, defaulting to 'low'."""
    resolved = SOURCE_RELIABILITY_MAP.get(source_type, "low")
    # Narrow the return type; the map only contains valid literals.
    if resolved not in ("high", "medium", "low"):
        logger.warning(
            "SOURCE_RELIABILITY_MAP contains unexpected value %r for source %r; "
            "falling back to 'low'",
            resolved,
            source_type,
        )
        return "low"
    return resolved  # type: ignore[return-value]


def _assign_tier(confidence: float) -> QualityTier:
    """Map a confidence value to a quality tier using the documented thresholds."""
    for threshold, tier in _TIER_THRESHOLDS:
        if confidence >= threshold:
            return tier  # type: ignore[return-value]
    return "C"  # unreachable but satisfies type checker


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compute_confidence(
    *,
    temporal_delta_seconds: float,
    field_match_strength: FieldMatchStrength,
    source_reliability: SourceReliability,
    corroboration_count: int,
    window_seconds: float = 300.0,
) -> ConfidenceResult:
    """Compute a heuristic confidence score for one evidence-to-step match.

    This is a **heuristic scoring function, not a statistical classifier**.
    All weights are engineering judgements documented in the module docstring.

    Parameters
    ----------
    temporal_delta_seconds:
        Absolute time difference between the event timestamp and the ground-
        truth step timestamp, in seconds.  Must be non-negative.
    field_match_strength:
        How the evidence field was matched against the expected evidence
        descriptor: ``"exact"`` > ``"regex"`` > ``"heuristic"``.
    source_reliability:
        Trustworthiness of the log origin: ``"high"`` (built-in runner
        output), ``"medium"`` (external structured log), ``"low"``
        (heuristic or unknown).
    corroboration_count:
        Total number of independent events (including this one) that back
        the same ground-truth step.  Must be >= 1.
    window_seconds:
        Correlation time window in seconds.  Events outside this window
        receive a temporal weight of 0.0.  Defaults to 300 s (5 min).

    Returns
    -------
    ConfidenceResult
        Frozen dataclass with ``confidence``, ``quality_tier``, and
        ``breakdown`` dict.
    """
    # --- temporal component ---------------------------------------------------
    temporal_weight = max(0.0, 1.0 - (temporal_delta_seconds / window_seconds))

    # --- field match component ------------------------------------------------
    field_weight = _FIELD_WEIGHTS[field_match_strength]

    # --- source reliability component -----------------------------------------
    source_weight = _SOURCE_WEIGHTS[source_reliability]

    # --- corroboration bonus --------------------------------------------------
    corroboration_bonus = min(0.2, 0.05 * max(0, corroboration_count - 1))

    # --- combine --------------------------------------------------------------
    base = 0.5 * temporal_weight + 0.3 * field_weight + 0.2 * source_weight
    confidence = min(1.0, base + corroboration_bonus)

    tier = _assign_tier(confidence)

    logger.debug(
        "confidence=%.3f tier=%s "
        "(temporal=%.3f field=%.3f source=%.3f corroboration=%.3f)",
        confidence,
        tier,
        temporal_weight,
        field_weight,
        source_weight,
        corroboration_bonus,
    )

    return ConfidenceResult(
        confidence=round(confidence, 6),
        quality_tier=tier,
        breakdown={
            "temporal_weight": round(temporal_weight, 6),
            "field_weight": round(field_weight, 6),
            "source_weight": round(source_weight, 6),
            "corroboration_bonus": round(corroboration_bonus, 6),
        },
    )


def compute_confidence_from_source_type(
    *,
    temporal_delta_seconds: float,
    field_match_strength: FieldMatchStrength,
    source_type: str,
    corroboration_count: int,
    window_seconds: float = 300.0,
) -> ConfidenceResult:
    """Convenience wrapper that resolves *source_type* via ``SOURCE_RELIABILITY_MAP``.

    Unknown source types fall back to reliability ``"low"``.
    """
    source_reliability = _resolve_source_reliability(source_type)
    return compute_confidence(
        temporal_delta_seconds=temporal_delta_seconds,
        field_match_strength=field_match_strength,
        source_reliability=source_reliability,
        corroboration_count=corroboration_count,
        window_seconds=window_seconds,
    )
