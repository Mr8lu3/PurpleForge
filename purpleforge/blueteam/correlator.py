"""Correlate red team actions with blue team detections."""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from purpleforge.blueteam.normalizer import BlueTeamEvent, EventType
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class CorrelationMatch:
    """A match between red team action and blue team detection."""
    red_team_step_id: str
    red_team_timestamp: datetime
    red_team_action: str
    blue_team_event_id: str
    blue_team_timestamp: datetime
    blue_team_source: str
    blue_team_event_type: str
    confidence: float  # 0.0 to 1.0
    time_delta_seconds: float
    match_reason: str


@dataclass
class CorrelationResult:
    """Result of red/blue team correlation."""
    total_red_team_steps: int
    total_blue_team_events: int
    matched_steps: int
    unmatched_steps: List[str]
    matches: List[CorrelationMatch]
    detection_coverage: float  # Percentage of red team steps detected
    summary: Dict[str, Any] = field(default_factory=dict)


class RedBlueCorrelator:
    """
    Correlate red team scenario execution with blue team telemetry.

    This is the core "purple" functionality - showing which red team
    actions were visible in defensive logs.
    """

    # Time window for correlation (seconds before/after red team action)
    DEFAULT_TIME_WINDOW = 60

    # Mapping of red team step types to expected blue team event types
    STEP_TO_EVENT_MAP = {
        "http_get_baseline": [EventType.HTTP_REQUEST, EventType.NETWORK_CONNECTION],
        "reflected_xss_probe_safe": [EventType.HTTP_REQUEST],
        "sqli_error_probe_safe": [EventType.HTTP_REQUEST],
        "process_create": [EventType.PROCESS_CREATE],
        "file_create": [EventType.FILE_CREATE],
        "network_connection": [EventType.NETWORK_CONNECTION],
    }

    def __init__(
        self,
        run_dir: Path,
        time_window: int = DEFAULT_TIME_WINDOW,
    ):
        """
        Initialize correlator.

        Args:
            run_dir: Path to run directory
            time_window: Seconds around red team action to look for blue team events
        """
        self.run_dir = run_dir
        self.time_window = time_window
        self.red_team_events: List[Dict[str, Any]] = []
        self.blue_team_events: List[BlueTeamEvent] = []

    def load_red_team_events(self) -> List[Dict[str, Any]]:
        """Load red team ground truth events."""
        ground_truth_path = self.run_dir / "groundtruth.jsonl"
        events = []

        if ground_truth_path.exists():
            with open(ground_truth_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))

        self.red_team_events = events
        logger.info(f"Loaded {len(events)} red team events")
        return events

    def load_blue_team_events(self) -> List[BlueTeamEvent]:
        """Load normalized blue team events."""
        blue_team_path = self.run_dir / "telemetry" / "blueteam" / "normalized.jsonl"
        events = []

        if blue_team_path.exists():
            with open(blue_team_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        data = json.loads(line)
                        # Convert string timestamp to datetime
                        if isinstance(data.get("timestamp"), str):
                            data["timestamp"] = datetime.fromisoformat(
                                data["timestamp"].replace("Z", "+00:00")
                            )
                        events.append(BlueTeamEvent(**data))

        self.blue_team_events = events
        logger.info(f"Loaded {len(events)} blue team events")
        return events

    def correlate(self) -> CorrelationResult:
        """
        Perform correlation between red and blue team events.

        Returns:
            CorrelationResult with matches and statistics
        """
        if not self.red_team_events:
            self.load_red_team_events()
        if not self.blue_team_events:
            self.load_blue_team_events()

        matches: List[CorrelationMatch] = []
        matched_step_ids = set()
        unmatched_steps: List[str] = []

        for red_event in self.red_team_events:
            step_id = red_event.get("step_id", "unknown")
            step_type = red_event.get("step_type", "unknown")
            red_timestamp = self._parse_timestamp(red_event.get("timestamp"))

            if not red_timestamp:
                continue

            # Find matching blue team events
            step_matches = self._find_matches(
                step_id=step_id,
                step_type=step_type,
                red_timestamp=red_timestamp,
                red_details=red_event,
            )

            if step_matches:
                matches.extend(step_matches)
                matched_step_ids.add(step_id)
            else:
                if step_id not in unmatched_steps:
                    unmatched_steps.append(step_id)

        # Calculate coverage
        unique_steps = set(e.get("step_id") for e in self.red_team_events if e.get("step_id"))
        coverage = (len(matched_step_ids) / len(unique_steps) * 100) if unique_steps else 0

        result = CorrelationResult(
            total_red_team_steps=len(unique_steps),
            total_blue_team_events=len(self.blue_team_events),
            matched_steps=len(matched_step_ids),
            unmatched_steps=unmatched_steps,
            matches=matches,
            detection_coverage=round(coverage, 1),
            summary=self._generate_summary(matches, matched_step_ids, unmatched_steps),
        )

        logger.info(
            f"Correlation complete: {result.matched_steps}/{result.total_red_team_steps} "
            f"steps detected ({result.detection_coverage}% coverage)"
        )

        return result

    def _find_matches(
        self,
        step_id: str,
        step_type: str,
        red_timestamp: datetime,
        red_details: Dict[str, Any],
    ) -> List[CorrelationMatch]:
        """Find blue team events matching a red team action."""
        matches = []

        # Get expected event types for this step type
        expected_types = self.STEP_TO_EVENT_MAP.get(step_type, [])

        # Time window
        window_start = red_timestamp - timedelta(seconds=self.time_window)
        window_end = red_timestamp + timedelta(seconds=self.time_window)

        for blue_event in self.blue_team_events:
            # Check time window
            if not (window_start <= blue_event.timestamp <= window_end):
                continue

            # Calculate confidence based on various factors
            confidence, reason = self._calculate_match_confidence(
                step_type=step_type,
                expected_types=expected_types,
                red_details=red_details,
                blue_event=blue_event,
            )

            if confidence > 0.3:  # Minimum threshold
                time_delta = abs((blue_event.timestamp - red_timestamp).total_seconds())
                matches.append(CorrelationMatch(
                    red_team_step_id=step_id,
                    red_team_timestamp=red_timestamp,
                    red_team_action=step_type,
                    blue_team_event_id=blue_event.event_id,
                    blue_team_timestamp=blue_event.timestamp,
                    blue_team_source=blue_event.source,
                    blue_team_event_type=blue_event.event_type.value,
                    confidence=confidence,
                    time_delta_seconds=time_delta,
                    match_reason=reason,
                ))

        return matches

    def _calculate_match_confidence(
        self,
        step_type: str,
        expected_types: List[EventType],
        red_details: Dict[str, Any],
        blue_event: BlueTeamEvent,
    ) -> Tuple[float, str]:
        """Calculate confidence score for a potential match."""
        confidence = 0.0
        reasons = []

        # Event type match
        if blue_event.event_type in expected_types:
            confidence += 0.4
            reasons.append("event_type_match")

        # URL/target match for HTTP events
        if blue_event.event_type == EventType.HTTP_REQUEST:
            red_url = red_details.get("url", "")
            if blue_event.http_url and red_url:
                if red_url in blue_event.http_url or blue_event.http_url in red_url:
                    confidence += 0.4
                    reasons.append("url_match")

        # IP address match for network events
        if blue_event.event_type == EventType.NETWORK_CONNECTION:
            red_target = red_details.get("target_ip", "")
            if blue_event.dest_ip and red_target:
                if red_target == blue_event.dest_ip:
                    confidence += 0.3
                    reasons.append("ip_match")

        # Process name match
        if blue_event.event_type == EventType.PROCESS_CREATE:
            red_process = red_details.get("process", "")
            if blue_event.process_name and red_process:
                if red_process.lower() in blue_event.process_name.lower():
                    confidence += 0.3
                    reasons.append("process_match")

        # Time proximity bonus (closer = higher confidence)
        time_delta = abs(
            (blue_event.timestamp - self._parse_timestamp(red_details.get("timestamp"))).total_seconds()
        ) if red_details.get("timestamp") else 60

        if time_delta < 5:
            confidence += 0.2
            reasons.append("time_proximity_high")
        elif time_delta < 30:
            confidence += 0.1
            reasons.append("time_proximity_medium")

        return min(confidence, 1.0), ", ".join(reasons)

    def _parse_timestamp(self, ts: Any) -> Optional[datetime]:
        """Parse timestamp from various formats."""
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                pass
        return None

    def _generate_summary(
        self,
        matches: List[CorrelationMatch],
        matched_step_ids: set,
        unmatched_steps: List[str],
    ) -> Dict[str, Any]:
        """Generate correlation summary statistics."""
        summary = {
            "by_blue_team_source": {},
            "by_event_type": {},
            "average_confidence": 0.0,
            "average_time_delta": 0.0,
            "detection_gaps": [],
        }

        if matches:
            # Count by source
            for match in matches:
                source = match.blue_team_source
                summary["by_blue_team_source"][source] = \
                    summary["by_blue_team_source"].get(source, 0) + 1

                event_type = match.blue_team_event_type
                summary["by_event_type"][event_type] = \
                    summary["by_event_type"].get(event_type, 0) + 1

            # Averages
            summary["average_confidence"] = round(
                sum(m.confidence for m in matches) / len(matches), 2
            )
            summary["average_time_delta"] = round(
                sum(m.time_delta_seconds for m in matches) / len(matches), 2
            )

        # Detection gaps (steps not detected)
        summary["detection_gaps"] = unmatched_steps

        return summary

    def save_results(self, result: CorrelationResult) -> Path:
        """Save correlation results to file."""
        output_path = self.run_dir / "correlation" / "red_blue_correlation.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "total_red_team_steps": result.total_red_team_steps,
            "total_blue_team_events": result.total_blue_team_events,
            "matched_steps": result.matched_steps,
            "unmatched_steps": result.unmatched_steps,
            "detection_coverage": result.detection_coverage,
            "matches": [
                {
                    "red_team_step_id": m.red_team_step_id,
                    "red_team_timestamp": m.red_team_timestamp.isoformat(),
                    "red_team_action": m.red_team_action,
                    "blue_team_event_id": m.blue_team_event_id,
                    "blue_team_timestamp": m.blue_team_timestamp.isoformat(),
                    "blue_team_source": m.blue_team_source,
                    "blue_team_event_type": m.blue_team_event_type,
                    "confidence": m.confidence,
                    "time_delta_seconds": m.time_delta_seconds,
                    "match_reason": m.match_reason,
                }
                for m in result.matches
            ],
            "summary": result.summary,
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Correlation results saved to {output_path}")
        return output_path


def correlate_events(run_dir: Path, time_window: int = 60) -> CorrelationResult:
    """
    Convenience function to run correlation.

    Args:
        run_dir: Path to run directory
        time_window: Seconds around red team action to search

    Returns:
        CorrelationResult
    """
    correlator = RedBlueCorrelator(run_dir, time_window)
    result = correlator.correlate()
    correlator.save_results(result)
    return result
