"""Blue team telemetry ingestion and correlation."""

from purpleforge.blueteam.ingest import BlueTeamIngester
from purpleforge.blueteam.normalizer import BlueTeamEvent, EventNormalizer
from purpleforge.blueteam.correlator import (
    RedBlueCorrelator,
    CorrelationResult,
    CorrelationMatch,
    correlate_events,
)

__all__ = [
    "BlueTeamIngester",
    "BlueTeamEvent",
    "EventNormalizer",
    "RedBlueCorrelator",
    "CorrelationResult",
    "CorrelationMatch",
    "correlate_events",
]
