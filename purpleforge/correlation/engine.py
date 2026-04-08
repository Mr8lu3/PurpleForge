"""Correlation engine for timeline and coverage analysis."""

import json
import statistics
from pathlib import Path
from typing import Any, Dict, List, Optional

from purpleforge.audit.redaction import Redactor
from purpleforge.correlation.scoring import (
    FIELD_MATCH_STRENGTH_MAP,
    SOURCE_RELIABILITY_MAP,
    ConfidenceResult,
    compute_confidence,
    _resolve_source_reliability,
)
from purpleforge.telemetry import TelemetryCollector
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)

# Default correlation time window used when ground-truth step has no explicit timeout.
_DEFAULT_WINDOW_SECONDS: float = 300.0

# Tier B threshold — evidence is considered "present" only at or above this value.
_TIER_B_THRESHOLD: float = 0.55


def _event_source_type(event: Dict[str, Any]) -> str:
    """Derive the source-type key for an event, used to resolve source reliability."""
    # The telemetry collector stamps events with event_type; web requests map to
    # "web_requests" which is the canonical high-reliability source.
    event_type = event.get("event_type", "")
    if event_type == "http_request":
        return "web_requests"
    # Fall back to whatever the event carries, or "csv" as the lowest-trust default.
    return event.get("source_type", "csv")


def _temporal_delta(gt_timestamp: str, event_timestamp: str) -> float:
    """Return absolute delta in seconds between two ISO-8601 timestamp strings.

    Falls back to 0.0 if either timestamp cannot be parsed, logging a warning.
    """
    from datetime import datetime, timezone

    def _parse(ts: str) -> Optional[datetime]:
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    gt_dt = _parse(gt_timestamp)
    ev_dt = _parse(event_timestamp)
    if gt_dt is None or ev_dt is None:
        logger.warning(
            "Could not parse timestamps for delta: gt=%r ev=%r; using 0.0",
            gt_timestamp,
            event_timestamp,
        )
        return 0.0
    return abs((ev_dt - gt_dt).total_seconds())


def _score_event(
    gt: Dict[str, Any],
    event: Dict[str, Any],
    corroboration_count: int,
    window_seconds: float,
) -> ConfidenceResult:
    """Compute a ConfidenceResult for one (ground_truth, event) pair."""
    # Temporal delta
    delta = _temporal_delta(
        str(gt.get("timestamp", "")),
        str(event.get("timestamp", "")),
    )

    # Field match strength — engine does not yet distinguish matchers, use default.
    # TODO: when the engine exposes matcher names, look them up in FIELD_MATCH_STRENGTH_MAP.
    field_strength_key = event.get("match_strength", "default")
    field_strength = FIELD_MATCH_STRENGTH_MAP.get(field_strength_key, "heuristic")  # type: ignore[arg-type]

    # Source reliability
    source_type = _event_source_type(event)
    source_reliability = _resolve_source_reliability(source_type)

    return compute_confidence(
        temporal_delta_seconds=delta,
        field_match_strength=field_strength,  # type: ignore[arg-type]
        source_reliability=source_reliability,
        corroboration_count=corroboration_count,
        window_seconds=window_seconds,
    )


class CorrelationEngine:
    """Correlate evidence with ground truth and build timeline."""

    def __init__(self, run_dir: Path, redaction_enabled: bool = True):
        """
        Initialize correlation engine.

        Args:
            run_dir: Run directory containing telemetry and ground truth
            redaction_enabled: Whether to redact string fields in outputs
        """
        self.run_dir = run_dir
        self.correlation_dir = run_dir / "correlation"
        self.ground_truth_dir = run_dir / "ground_truth"
        self.telemetry_collector = TelemetryCollector(run_dir)
        self._redactor = Redactor(enabled=redaction_enabled)

    def correlate(self) -> Dict[str, Any]:
        """
        Perform correlation analysis.

        Returns:
            Correlation results including timeline and coverage
        """
        logger.info("Starting correlation analysis")

        # Load ground truth
        ground_truth = self._load_ground_truth()

        # Collect normalized events
        events = self.telemetry_collector.normalize_events()

        # Build timeline
        timeline = self._build_timeline(ground_truth, events)

        # Calculate coverage
        coverage = self._calculate_coverage(ground_truth, events)

        # Save results
        self._save_timeline(timeline)
        self._save_coverage(coverage)

        logger.info(
            f"Correlation complete: {len(timeline)} timeline entries, "
            f"{coverage['coverage_percentage']:.1f}% coverage"
        )

        return {
            "timeline": timeline,
            "coverage": coverage,
        }

    def _load_ground_truth(self) -> List[Dict[str, Any]]:
        """Load ground truth entries."""
        ground_truth_path = self.ground_truth_dir / "expected_evidence.jsonl"

        if not ground_truth_path.exists():
            logger.warning("No ground truth file found")
            return []

        entries = []
        with open(ground_truth_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))

        logger.info(f"Loaded {len(entries)} ground truth entries")
        return entries

    def _build_timeline(
        self, ground_truth: List[Dict[str, Any]], events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Build unified timeline from ground truth and events.

        Each evidence entry is annotated with ``confidence``, ``quality_tier``,
        and ``confidence_breakdown`` derived from the scoring module.

        Args:
            ground_truth: Ground truth entries
            events: Normalized event entries

        Returns:
            Unified timeline sorted by timestamp
        """
        timeline: List[Dict[str, Any]] = []

        # Index events by step_id so we can compute corroboration count per step.
        events_by_step: Dict[str, List[Dict[str, Any]]] = {}
        for event in events:
            sid = event.get("step_id")
            if sid:
                events_by_step.setdefault(sid, []).append(event)

        # Build a lookup from step_id to ground-truth entry (last wins on dup).
        gt_by_step: Dict[str, Dict[str, Any]] = {
            gt["step_id"]: gt for gt in ground_truth
        }

        # Add ground truth entries.
        for gt in ground_truth:
            timeline.append(
                {
                    "timestamp": gt["timestamp"],
                    "type": "ground_truth",
                    "step_id": gt["step_id"],
                    "step_type": gt["step_type"],
                    "expected_evidence": gt["expected_evidence"],
                    "success": gt["success"],
                }
            )

        # Add evidence events with confidence annotation.
        for event in events:
            step_id = event.get("step_id")
            gt = gt_by_step.get(step_id) if step_id else None
            corroboration_count = len(events_by_step.get(step_id, [])) if step_id else 1
            window_seconds = _DEFAULT_WINDOW_SECONDS

            if gt is not None:
                result = _score_event(gt, event, corroboration_count, window_seconds)
                confidence_val = result.confidence
                quality_tier = result.quality_tier
                breakdown = result.breakdown
            else:
                # No matching ground truth — assign minimum confidence.
                confidence_val = 0.0
                quality_tier = "C"
                breakdown = {
                    "temporal_weight": 0.0,
                    "field_weight": 0.0,
                    "source_weight": 0.0,
                    "corroboration_bonus": 0.0,
                }

            timeline.append(
                {
                    "timestamp": event["timestamp"],
                    "type": "evidence",
                    "event_type": event["event_type"],
                    "step_id": event["step_id"],
                    "data": event["data"],
                    "confidence": confidence_val,
                    "quality_tier": quality_tier,
                    "confidence_breakdown": breakdown,
                }
            )

        # Sort by timestamp
        timeline.sort(key=lambda x: x["timestamp"])

        return timeline

    def _calculate_coverage(
        self, ground_truth: List[Dict[str, Any]], events: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Calculate coverage metrics with per-step confidence scoring.

        New fields added (additive — existing field names unchanged):
          - Per step: ``best_confidence``, ``quality_tier``, ``has_any_evidence``
          - ``has_evidence`` now uses the tier-B threshold (>= 0.55) instead of binary
            presence.  Old binary behaviour is preserved in ``has_any_evidence``.
        - Top-level aggregates: ``coverage_confidence_mean``,
          ``coverage_confidence_median``, ``tier_distribution``.

        Args:
            ground_truth: Ground truth entries
            events: Normalized event entries

        Returns:
            Coverage metrics dict
        """
        total_steps = len(ground_truth)

        # Index events by step_id
        events_by_step: Dict[str, List[Dict[str, Any]]] = {}
        for event in events:
            step_id = event.get("step_id")
            if step_id:
                events_by_step.setdefault(step_id, []).append(event)

        step_coverage: List[Dict[str, Any]] = []
        best_confidences: List[float] = []
        tier_distribution: Dict[str, int] = {"A": 0, "B": 0, "C": 0, "none": 0}

        steps_with_evidence = 0  # threshold-based (tier B)

        for gt in ground_truth:
            step_id = gt["step_id"]
            step_events = events_by_step.get(step_id, [])
            has_any_evidence = len(step_events) > 0
            corroboration_count = len(step_events)
            window_seconds = _DEFAULT_WINDOW_SECONDS

            # Score each candidate event and take the maximum confidence.
            best_confidence = 0.0
            best_tier: str = "none"

            if step_events:
                for event in step_events:
                    result = _score_event(gt, event, corroboration_count, window_seconds)
                    if result.confidence > best_confidence:
                        best_confidence = result.confidence
                        best_tier = result.quality_tier

            # Threshold-based has_evidence (tier B = 0.55).
            has_evidence = best_confidence >= _TIER_B_THRESHOLD

            if has_evidence:
                steps_with_evidence += 1

            tier_distribution[best_tier] += 1
            best_confidences.append(best_confidence)

            step_coverage.append(
                {
                    "step_id": step_id,
                    "step_type": gt["step_type"],
                    "expected_evidence": gt["expected_evidence"],
                    "has_evidence": has_evidence,
                    "has_any_evidence": has_any_evidence,
                    "evidence_count": len(step_events),
                    "best_confidence": round(best_confidence, 4),
                    "quality_tier": best_tier,
                }
            )

        coverage_percentage = (
            (steps_with_evidence / total_steps * 100) if total_steps > 0 else 0.0
        )

        # Aggregate confidence statistics.
        if best_confidences:
            mean_conf = round(statistics.mean(best_confidences), 4)
            median_conf = round(statistics.median(best_confidences), 4)
        else:
            mean_conf = 0.0
            median_conf = 0.0

        return {
            "total_steps": total_steps,
            "steps_with_evidence": steps_with_evidence,
            "coverage_percentage": coverage_percentage,
            "step_coverage": step_coverage,
            "coverage_confidence_mean": mean_conf,
            "coverage_confidence_median": median_conf,
            "tier_distribution": tier_distribution,
        }

    def _save_timeline(self, timeline: List[Dict[str, Any]]) -> None:
        """Save timeline to JSON file (string fields redacted)."""
        timeline_path = self.correlation_dir / "timeline.json"
        redacted = self._redactor.redact_dict(timeline)
        with open(timeline_path, "w", encoding="utf-8") as f:
            json.dump(redacted, f, indent=2, default=str)
        logger.info(f"Timeline saved to {timeline_path}")

    def _save_coverage(self, coverage: Dict[str, Any]) -> None:
        """Save coverage metrics to JSON file (string fields redacted)."""
        coverage_path = self.correlation_dir / "coverage.json"
        redacted = self._redactor.redact_dict(coverage)
        with open(coverage_path, "w", encoding="utf-8") as f:
            json.dump(redacted, f, indent=2, default=str)
        logger.info(f"Coverage saved to {coverage_path}")
