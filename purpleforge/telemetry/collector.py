"""Telemetry collection and JSONL normalization."""

import json
from pathlib import Path
from typing import Any, Dict, List

from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


class TelemetryCollector:
    """Collect and normalize telemetry from run directory."""

    def __init__(self, run_dir: Path):
        """
        Initialize telemetry collector.

        Args:
            run_dir: Run directory containing telemetry
        """
        self.run_dir = run_dir
        self.telemetry_dir = run_dir / "telemetry"

    def collect_web_requests(self) -> List[Dict[str, Any]]:
        """
        Collect web request logs.

        Returns:
            List of web request log entries
        """
        web_requests_path = self.telemetry_dir / "web_requests.jsonl"

        if not web_requests_path.exists():
            logger.warning("No web requests log found")
            return []

        entries = []
        with open(web_requests_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))

        logger.info(f"Collected {len(entries)} web request entries")
        return entries

    def normalize_events(self) -> List[Dict[str, Any]]:
        """
        Normalize all events into common format.

        Returns:
            List of normalized event entries
        """
        normalized = []

        # Normalize web requests
        web_requests = self.collect_web_requests()
        for req in web_requests:
            normalized.append(
                {
                    "timestamp": req["timestamp"],
                    "event_type": "http_request",
                    "step_id": req["step_id"],
                    "data": {
                        "method": req["method"],
                        "url": req["url"],
                        "status_code": req["status_code"],
                        "response_length": req["response_length"],
                    },
                }
            )

        # Sort by timestamp
        normalized.sort(key=lambda x: x["timestamp"])

        # Write normalized events
        normalized_path = self.telemetry_dir / "normalized_events.jsonl"
        with open(normalized_path, "w", encoding="utf-8") as f:
            for event in normalized:
                f.write(json.dumps(event) + "\n")

        logger.info(f"Normalized {len(normalized)} events")
        return normalized
