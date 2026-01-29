"""Blue team log ingestion coordinator."""

from pathlib import Path
from typing import List, Optional

from purpleforge.blueteam.normalizer import BlueTeamEvent, EventNormalizer
from purpleforge.blueteam.parsers import (
    CSVParser,
    SysmonParser,
    WebServerParser,
    WinEvtxParser,
)
from purpleforge.utils.exceptions import PurpleForgeError
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


class BlueTeamIngester:
    """Coordinate blue team log ingestion."""

    SUPPORTED_SOURCES = ["sysmon", "winevtx", "webserver", "csv"]

    def __init__(self, run_dir: Path):
        """
        Initialize blue team ingester.

        Args:
            run_dir: Run directory for storing ingested logs
        """
        self.run_dir = run_dir
        self.normalizer = EventNormalizer(run_dir)

        # Initialize parsers
        self.parsers = {
            "sysmon": SysmonParser(),
            "winevtx": WinEvtxParser(),
            "webserver": WebServerParser(),
            "csv": CSVParser(),
        }

    def ingest(
        self, source: str, file_path: Path, run_id: Optional[str] = None
    ) -> int:
        """
        Ingest blue team logs.

        Args:
            source: Log source type (sysmon, winevtx, webserver, csv)
            file_path: Path to log file
            run_id: Optional run ID to associate with

        Returns:
            Number of events ingested

        Raises:
            PurpleForgeError: If ingestion fails
        """
        if source not in self.SUPPORTED_SOURCES:
            raise PurpleForgeError(
                f"Unsupported source: {source}",
                hint=f"Supported sources: {', '.join(self.SUPPORTED_SOURCES)}",
            )

        if not file_path.exists():
            raise PurpleForgeError(
                f"Log file not found: {file_path}",
                hint="Check that the file path is correct",
            )

        logger.info(f"Ingesting {source} logs from {file_path}")

        try:
            # Parse logs
            parser = self.parsers[source]
            events = parser.parse(file_path)

            # Normalize and save
            self.normalizer.normalize_batch(events)

            logger.info(
                f"Successfully ingested {len(events)} events from {source} logs"
            )
            return len(events)

        except PurpleForgeError:
            raise
        except Exception as e:
            raise PurpleForgeError(
                f"Failed to ingest {source} logs: {e}",
                hint="Check log file format and permissions",
            )

    def list_ingested_events(self) -> List[BlueTeamEvent]:
        """
        List all ingested blue team events.

        Returns:
            List of BlueTeamEvent objects
        """
        return self.normalizer.load_events()

    def get_event_statistics(self) -> dict:
        """
        Get statistics about ingested events.

        Returns:
            Dictionary with event statistics
        """
        events = self.list_ingested_events()

        if not events:
            return {
                "total_events": 0,
                "by_source": {},
                "by_event_type": {},
                "by_severity": {},
            }

        # Count by source
        by_source = {}
        for event in events:
            by_source[event.source] = by_source.get(event.source, 0) + 1

        # Count by event type
        by_event_type = {}
        for event in events:
            by_event_type[event.event_type] = by_event_type.get(event.event_type, 0) + 1

        # Count by severity
        by_severity = {}
        for event in events:
            by_severity[event.severity] = by_severity.get(event.severity, 0) + 1

        return {
            "total_events": len(events),
            "by_source": by_source,
            "by_event_type": by_event_type,
            "by_severity": by_severity,
        }
