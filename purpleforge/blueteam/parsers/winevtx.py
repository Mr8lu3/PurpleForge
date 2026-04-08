"""Windows Event Log parser."""

from datetime import datetime
from pathlib import Path
from typing import List

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as views
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False

import defusedxml.ElementTree as ET  # XML hardened against XXE/billion-laughs

from purpleforge.blueteam.normalizer import BlueTeamEvent
from purpleforge.utils.exceptions import PurpleForgeError
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


class WinEvtxParser:
    """Parse Windows Event Logs (.evtx)."""

    # Security event ID mapping
    SECURITY_EVENT_MAP = {
        4624: ("logon_success", "info"),
        4625: ("logon_failure", "medium"),
        4648: ("explicit_credentials", "low"),
        4672: ("special_privileges_assigned", "medium"),
        4688: ("process_creation", "info"),
        4689: ("process_termination", "info"),
        4698: ("scheduled_task_created", "medium"),
        4699: ("scheduled_task_deleted", "low"),
        4700: ("scheduled_task_enabled", "medium"),
        4701: ("scheduled_task_disabled", "low"),
        4720: ("user_account_created", "high"),
        4722: ("user_account_enabled", "medium"),
        4724: ("password_reset_attempt", "high"),
        4725: ("user_account_disabled", "medium"),
        4726: ("user_account_deleted", "high"),
        4732: ("member_added_to_security_group", "high"),
        4733: ("member_removed_from_security_group", "medium"),
        4756: ("member_added_to_universal_group", "medium"),
        5140: ("network_share_accessed", "low"),
        5145: ("network_share_object_accessed", "low"),
    }

    def parse(self, file_path: Path) -> List[BlueTeamEvent]:
        """
        Parse Windows Event Log file.

        Args:
            file_path: Path to .evtx file

        Returns:
            List of normalized BlueTeamEvent objects

        Raises:
            PurpleForgeError: If parsing fails
        """
        if not EVTX_AVAILABLE:
            raise PurpleForgeError(
                "python-evtx library not installed",
                hint="Install with: pip install python-evtx",
            )

        logger.info(f"Parsing Windows Event Log: {file_path}")

        try:
            events = []
            with evtx.Evtx(str(file_path)) as log:
                for record in log.records():
                    try:
                        event = self._parse_record(record)
                        if event:
                            events.append(event)
                    except Exception as e:
                        logger.warning(f"Failed to parse event record: {e}")
                        continue

            logger.info(f"Parsed {len(events)} Windows events")
            return events

        except Exception as e:
            raise PurpleForgeError(
                f"Error parsing Windows Event Log: {e}",
                hint="Ensure the file is a valid .evtx file",
            )

    def _parse_record(self, record) -> BlueTeamEvent:
        """Parse individual event record."""
        try:
            xml_str = record.xml()
            root = ET.fromstring(xml_str)

            # Extract system data
            system = root.find("{*}System")
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

            # Computer name
            computer_elem = system.find("{*}Computer")
            computer = computer_elem.text if computer_elem is not None else "Unknown"

            # Event data
            event_data = root.find("{*}EventData")
            details = {"computer": computer}

            if event_data is not None:
                for data_elem in event_data.findall("{*}Data"):
                    name = data_elem.get("Name")
                    if name:
                        details[name] = data_elem.text if data_elem.text else ""

            # Get event type and severity
            event_info = self.SECURITY_EVENT_MAP.get(event_id)
            if event_info:
                event_type, severity = event_info
            else:
                event_type = f"windows_event_{event_id}"
                severity = "info"

            return BlueTeamEvent(
                timestamp=timestamp,
                source="winevtx",
                event_type=event_type,
                severity=severity,
                details={"event_id": event_id, **details},
                raw_event=xml_str,
            )

        except Exception as e:
            logger.warning(f"Error parsing event record: {e}")
            return None
