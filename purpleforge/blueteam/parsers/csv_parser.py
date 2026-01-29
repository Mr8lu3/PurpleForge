"""Generic CSV log parser."""

import csv
from datetime import datetime
from pathlib import Path
from typing import List

from purpleforge.blueteam.normalizer import BlueTeamEvent
from purpleforge.utils.exceptions import PurpleForgeError
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


class CSVParser:
    """Parse generic CSV logs with timestamp, source, event_type, details columns."""

    REQUIRED_COLUMNS = ["timestamp", "source", "event_type"]
    OPTIONAL_COLUMNS = ["severity", "details"]

    def parse(self, file_path: Path) -> List[BlueTeamEvent]:
        """
        Parse CSV log file.

        Expected columns: timestamp, source, event_type, severity (optional), details (optional)

        Args:
            file_path: Path to CSV log file

        Returns:
            List of normalized BlueTeamEvent objects

        Raises:
            PurpleForgeError: If parsing fails
        """
        logger.info(f"Parsing CSV log: {file_path}")

        try:
            events = []
            with open(file_path, "r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)

                # Validate required columns
                if not all(col in reader.fieldnames for col in self.REQUIRED_COLUMNS):
                    raise PurpleForgeError(
                        f"CSV missing required columns. Required: {self.REQUIRED_COLUMNS}",
                        hint=f"Found columns: {reader.fieldnames}",
                    )

                for row_num, row in enumerate(reader, 2):  # Start at 2 (header is 1)
                    try:
                        event = self._parse_row(row)
                        if event:
                            events.append(event)
                    except Exception as e:
                        logger.warning(f"Failed to parse CSV row {row_num}: {e}")
                        continue

            logger.info(f"Parsed {len(events)} CSV log entries")
            return events

        except csv.Error as e:
            raise PurpleForgeError(
                f"CSV parsing error: {e}",
                hint="Ensure the file is valid CSV format",
            )
        except Exception as e:
            raise PurpleForgeError(
                f"Error parsing CSV log: {e}",
                hint="Check file format and column names",
            )

    def _parse_row(self, row: dict) -> BlueTeamEvent:
        """Parse individual CSV row."""
        # Parse timestamp (try common formats)
        timestamp_str = row["timestamp"]
        timestamp = self._parse_timestamp(timestamp_str)

        # Get required fields
        source = row["source"]
        event_type = row["event_type"]

        # Get optional fields
        severity = row.get("severity", "info").lower()
        if severity not in ["info", "low", "medium", "high", "critical"]:
            severity = "info"

        # Parse details (can be JSON string or plain text)
        details_str = row.get("details", "")
        details = {}

        if details_str:
            try:
                import json
                details = json.loads(details_str)
            except json.JSONDecodeError:
                # If not JSON, store as plain text
                details = {"raw_details": details_str}

        # Add all other columns to details
        for key, value in row.items():
            if key not in self.REQUIRED_COLUMNS + self.OPTIONAL_COLUMNS:
                details[key] = value

        return BlueTeamEvent(
            timestamp=timestamp,
            source=source,
            event_type=event_type,
            severity=severity,
            details=details,
            raw_event=str(row),
        )

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """
        Parse timestamp from various formats.

        Args:
            timestamp_str: Timestamp string

        Returns:
            datetime object

        Raises:
            ValueError: If timestamp cannot be parsed
        """
        # Try common timestamp formats
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%d/%b/%Y:%H:%M:%S %z",
            "%Y-%m-%d",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue

        # Try ISO format
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except ValueError:
            pass

        # Try Unix timestamp
        try:
            return datetime.fromtimestamp(float(timestamp_str))
        except (ValueError, OSError):
            pass

        raise ValueError(f"Unable to parse timestamp: {timestamp_str}")
