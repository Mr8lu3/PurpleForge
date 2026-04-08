"""Event correlation and timeline building."""

from purpleforge.correlation.engine import CorrelationEngine
from purpleforge.correlation.scoring import (
    ConfidenceResult,
    SOURCE_RELIABILITY_MAP,
    FIELD_MATCH_STRENGTH_MAP,
    compute_confidence,
    compute_confidence_from_source_type,
)

__all__ = [
    "CorrelationEngine",
    "ConfidenceResult",
    "SOURCE_RELIABILITY_MAP",
    "FIELD_MATCH_STRENGTH_MAP",
    "compute_confidence",
    "compute_confidence_from_source_type",
]
