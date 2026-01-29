"""Web server log parser (Apache/Nginx combined format)."""

import re
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from purpleforge.blueteam.normalizer import BlueTeamEvent
from purpleforge.utils.exceptions import PurpleForgeError
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


class WebServerParser:
    """Parse Apache/Nginx combined log format."""

    # Combined log format regex
    # Format: IP - - [timestamp] "METHOD /path HTTP/1.1" status size "referer" "user-agent"
    LOG_PATTERN = re.compile(
        r'^(?P<ip>[\d\.]+) - - \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) HTTP/(?P<http_version>[\d\.]+)" '
        r'(?P<status>\d+) (?P<size>\S+)'
        r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
    )

    def parse(self, file_path: Path) -> List[BlueTeamEvent]:
        """
        Parse web server log file.

        Args:
            file_path: Path to web server log file

        Returns:
            List of normalized BlueTeamEvent objects

        Raises:
            PurpleForgeError: If parsing fails
        """
        logger.info(f"Parsing web server log: {file_path}")

        try:
            events = []
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        event = self._parse_line(line.strip())
                        if event:
                            events.append(event)
                    except Exception as e:
                        logger.warning(
                            f"Failed to parse line {line_num}: {e} | Line: {line[:100]}"
                        )
                        continue

            logger.info(f"Parsed {len(events)} web server log entries")
            return events

        except Exception as e:
            raise PurpleForgeError(
                f"Error parsing web server log: {e}",
                hint="Ensure the file is in Apache/Nginx combined log format",
            )

    def _parse_line(self, line: str) -> Optional[BlueTeamEvent]:
        """Parse individual log line."""
        if not line:
            return None

        match = self.LOG_PATTERN.match(line)
        if not match:
            return None

        data = match.groupdict()

        # Parse timestamp (format: 20/Jan/2026:12:34:56 +0000)
        try:
            timestamp = datetime.strptime(
                data["timestamp"], "%d/%b/%Y:%H:%M:%S %z"
            )
        except ValueError:
            # Fallback to current time if parsing fails
            timestamp = datetime.utcnow()

        # Determine severity
        severity = self._determine_severity(
            data["method"],
            data["path"],
            int(data["status"]),
            data.get("user_agent", ""),
        )

        details = {
            "ip": data["ip"],
            "method": data["method"],
            "path": data["path"],
            "http_version": data["http_version"],
            "status": int(data["status"]),
            "size": data["size"],
            "referer": data.get("referer", ""),
            "user_agent": data.get("user_agent", ""),
        }

        return BlueTeamEvent(
            timestamp=timestamp,
            source="webserver",
            event_type="http_request",
            severity=severity,
            details=details,
            raw_event=line,
        )

    def _determine_severity(
        self, method: str, path: str, status: int, user_agent: str
    ) -> str:
        """Determine severity based on request characteristics."""
        path_lower = path.lower()
        ua_lower = user_agent.lower()

        # Check for suspicious patterns
        suspicious_patterns = [
            "union", "select", "insert", "delete", "drop", "update",  # SQLi
            "../", "..\\",  # Path traversal
            "<script", "javascript:", "onerror",  # XSS
            "cmd=", "exec=", "command=",  # Command injection
            "/admin", "/wp-admin", "/phpmyadmin",  # Admin panels
            ".php", ".asp", ".jsp",  # Script files
            "/etc/passwd", "/windows/system32",  # File access
        ]

        for pattern in suspicious_patterns:
            if pattern in path_lower:
                return "high"

        # Check for scanner signatures
        scanner_signatures = [
            "nikto", "nmap", "sqlmap", "burp", "nessus", "acunetix",
            "masscan", "nuclei", "ffuf", "gobuster", "dirbuster",
        ]

        for sig in scanner_signatures:
            if sig in ua_lower:
                return "medium"

        # Status code based severity
        if status >= 500:
            return "medium"  # Server errors
        elif status == 403:
            return "low"  # Forbidden
        elif status == 401:
            return "low"  # Unauthorized
        elif status == 404:
            return "info"  # Not found

        # Non-GET requests to sensitive paths
        if method in ["POST", "PUT", "DELETE", "PATCH"]:
            if any(sensitive in path_lower for sensitive in ["/api/", "/admin/", "/upload"]):
                return "medium"

        return "info"
