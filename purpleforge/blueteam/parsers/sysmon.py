"""Sysmon XML/EVTX log parser."""

import defusedxml.ElementTree as ET  # XML hardened against XXE/billion-laughs
from datetime import datetime
from pathlib import Path
from typing import List

from purpleforge.blueteam.normalizer import BlueTeamEvent
from purpleforge.utils.exceptions import PurpleForgeError
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


class SysmonParser:
    """Parse Sysmon XML logs."""

    # Event ID to event type mapping
    EVENT_TYPE_MAP = {
        1: "process_create",
        2: "file_creation_time_changed",
        3: "network_connection",
        5: "process_terminated",
        6: "driver_loaded",
        7: "image_loaded",
        8: "create_remote_thread",
        9: "raw_access_read",
        10: "process_access",
        11: "file_create",
        12: "registry_event_object_create_delete",
        13: "registry_value_set",
        14: "registry_key_rename",
        15: "file_create_stream_hash",
        17: "pipe_created",
        18: "pipe_connected",
        19: "wmi_event_filter",
        20: "wmi_event_consumer",
        21: "wmi_event_consumer_filter",
        22: "dns_query",
        23: "file_delete",
        24: "clipboard_change",
        25: "process_tampering",
        26: "file_delete_detected",
    }

    def parse(self, file_path: Path) -> List[BlueTeamEvent]:
        """
        Parse Sysmon XML log file.

        Args:
            file_path: Path to Sysmon XML log

        Returns:
            List of normalized BlueTeamEvent objects

        Raises:
            PurpleForgeError: If parsing fails
        """
        logger.info(f"Parsing Sysmon log: {file_path}")

        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            events = []
            for event_elem in root.findall(".//{*}Event"):
                try:
                    event = self._parse_event(event_elem)
                    if event:
                        events.append(event)
                except Exception as e:
                    logger.warning(f"Failed to parse Sysmon event: {e}")
                    continue

            logger.info(f"Parsed {len(events)} Sysmon events")
            return events

        except ET.ParseError as e:
            raise PurpleForgeError(
                f"Failed to parse Sysmon XML: {e}",
                hint="Ensure the file is valid XML format",
            )
        except Exception as e:
            raise PurpleForgeError(
                f"Error parsing Sysmon log: {e}",
                hint="Check file format and permissions",
            )

    def _parse_event(self, event_elem: ET.Element) -> BlueTeamEvent:
        """Parse individual Sysmon event."""
        # Extract system data
        system = event_elem.find("{*}System")
        if system is None:
            return None

        # Event ID
        event_id_elem = system.find("{*}EventID")
        if event_id_elem is None:
            return None
        event_id = int(event_id_elem.text)

        # Timestamp
        time_created = system.find("{*}TimeCreated")
        if time_created is None:
            return None
        timestamp = datetime.fromisoformat(
            time_created.get("SystemTime").replace("Z", "+00:00")
        )

        # Event data
        event_data = event_elem.find("{*}EventData")
        details = {}

        if event_data is not None:
            for data_elem in event_data.findall("{*}Data"):
                name = data_elem.get("Name")
                if name:
                    details[name] = data_elem.text

        # Determine severity based on event type
        severity = self._determine_severity(event_id, details)

        # Get event type name
        event_type = self.EVENT_TYPE_MAP.get(event_id, f"sysmon_event_{event_id}")

        return BlueTeamEvent(
            timestamp=timestamp,
            source="sysmon",
            event_type=event_type,
            severity=severity,
            details={"event_id": event_id, **details},
            raw_event=ET.tostring(event_elem, encoding="unicode"),
        )

    def _determine_severity(self, event_id: int, details: dict) -> str:
        """Determine event severity based on event ID and details."""
        # Process creation (Event ID 1)
        if event_id == 1:
            image = details.get("Image", "").lower()
            if any(
                susp in image
                for susp in ["powershell", "cmd", "wscript", "cscript", "rundll32"]
            ):
                return "medium"
            return "info"

        # Network connection (Event ID 3)
        elif event_id == 3:
            dest_port = details.get("DestinationPort", "")
            if dest_port in ["4444", "5555", "8888"]:  # Common C2 ports
                return "high"
            return "low"

        # Image loaded (Event ID 7)
        elif event_id == 7:
            return "low"

        # File create (Event ID 11)
        elif event_id == 11:
            target_filename = details.get("TargetFilename", "").lower()
            if any(ext in target_filename for ext in [".exe", ".dll", ".ps1", ".bat"]):
                return "medium"
            return "info"

        # Registry events (Event IDs 12, 13, 14)
        elif event_id in [12, 13, 14]:
            target_object = details.get("TargetObject", "").lower()
            if "\\run" in target_object or "\\services" in target_object:
                return "medium"
            return "low"

        # DNS query (Event ID 22)
        elif event_id == 22:
            query_name = details.get("QueryName", "").lower()
            if any(
                susp in query_name
                for susp in ["pastebin", "ngrok", "duckdns", "freeddns"]
            ):
                return "medium"
            return "info"

        # File delete (Event IDs 23, 26)
        elif event_id in [23, 26]:
            return "low"

        # Process tampering (Event ID 25)
        elif event_id == 25:
            return "high"

        # Default
        return "info"
