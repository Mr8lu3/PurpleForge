"""JSON report exporter for machine-readable output."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


def export_json(
    report_data: Dict[str, Any],
    output_path: Path,
    pretty: bool = True,
) -> Path:
    """
    Export report as JSON.

    Args:
        report_data: Report data dictionary
        output_path: Path for JSON output
        pretty: Whether to format with indentation

    Returns:
        Path to created JSON file
    """
    # Add export metadata
    export_data = {
        "export_format": "json",
        "export_version": "1.0",
        "exported_at": datetime.utcnow().isoformat(),
        "data": report_data,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        if pretty:
            json.dump(export_data, f, indent=2, default=str)
        else:
            json.dump(export_data, f, default=str)

    logger.info(f"JSON report exported to {output_path}")
    return output_path
