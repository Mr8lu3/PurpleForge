"""Blue team event normalization."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


class BlueTeamEvent(BaseModel):
    """Normalized blue team event."""

    timestamp: datetime
    source: str  # sysmon, winevtx, webserver, csv
    event_type: str  # process_create, network_connection, file_create, http_request, etc.
    severity: str  # info, low, medium, high, critical
    details: Dict[str, Any] = Field(default_factory=dict)
    raw_event: Optional[str] = None
    matched_red_team_step: Optional[str] = None  # Correlation result

    model_config = {"frozen": False}


class EventNormalizer:
    """Normalize blue team events to common schema."""

    def __init__(self, run_dir: Path):
        """
        Initialize event normalizer.

        Args:
            run_dir: Run directory for storing normalized events
        """
        self.run_dir = run_dir
        self.blueteam_dir = run_dir / "telemetry" / "blueteam"
        self.blueteam_dir.mkdir(parents=True, exist_ok=True)

    def save_event(self, event: BlueTeamEvent) -> None:
        """
        Save normalized event to JSONL.

        Args:
            event: BlueTeamEvent to save
        """
        output_path = self.blueteam_dir / "normalized_events.jsonl"

        with open(output_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event.model_dump(mode="json"), default=str) + "\n")

    def load_events(self) -> List[BlueTeamEvent]:
        """
        Load all normalized blue team events.

        Returns:
            List of BlueTeamEvent objects
        """
        output_path = self.blueteam_dir / "normalized_events.jsonl"

        if not output_path.exists():
            return []

        events = []
        with open(output_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    data = json.loads(line)
                    events.append(BlueTeamEvent(**data))

        logger.info(f"Loaded {len(events)} normalized blue team events")
        return events

    def normalize_batch(self, events: List[BlueTeamEvent]) -> None:
        """
        Save a batch of normalized events.

        Args:
            events: List of BlueTeamEvent objects
        """
        for event in events:
            self.save_event(event)

        logger.info(f"Normalized and saved {len(events)} blue team events")
