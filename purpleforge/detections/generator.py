"""Detection rule generation coordinator."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from purpleforge.detections.elastic import ElasticGenerator
from purpleforge.detections.sigma import SigmaGenerator
from purpleforge.detections.snort import SnortGenerator
from purpleforge.detections.splunk import SplunkGenerator
from purpleforge.detections.yara import YaraGenerator
from purpleforge.utils.exceptions import PurpleForgeError
from purpleforge.utils.logging import get_logger

logger = get_logger(__name__)


class DetectionGenerator:
    """Generate detection rules from executed scenarios."""

    SUPPORTED_FORMATS = ["sigma", "splunk", "elastic", "yara", "snort"]

    def __init__(self, run_dir: Path):
        """
        Initialize detection generator.

        Args:
            run_dir: Run directory containing scenario data
        """
        self.run_dir = run_dir
        self.detections_dir = run_dir / "detections"
        self.detections_dir.mkdir(exist_ok=True)

        # Initialize format generators
        self.generators = {
            "sigma": SigmaGenerator(),
            "splunk": SplunkGenerator(),
            "elastic": ElasticGenerator(),
            "yara": YaraGenerator(),
            "snort": SnortGenerator(),
        }

    def generate(
        self, format: str, all_formats: bool = False
    ) -> Dict[str, Path]:
        """
        Generate detection rules.

        Args:
            format: Detection rule format (sigma, splunk, elastic, yara, snort)
            all_formats: Generate all supported formats

        Returns:
            Dictionary mapping format to output file path

        Raises:
            PurpleForgeError: If generation fails
        """
        if all_formats:
            formats = self.SUPPORTED_FORMATS
        else:
            if format not in self.SUPPORTED_FORMATS:
                raise PurpleForgeError(
                    f"Unsupported format: {format}",
                    hint=f"Supported formats: {', '.join(self.SUPPORTED_FORMATS)}",
                )
            formats = [format]

        logger.info(f"Generating detection rules for formats: {', '.join(formats)}")

        # Load scenario data
        scenario_data = self._load_scenario()
        telemetry_data = self._load_telemetry()
        correlation_data = self._load_correlation()

        results = {}
        for fmt in formats:
            try:
                output_path = self._generate_format(
                    fmt, scenario_data, telemetry_data, correlation_data
                )
                results[fmt] = output_path
                logger.info(f"Generated {fmt} rules: {output_path}")
            except Exception as e:
                logger.error(f"Failed to generate {fmt} rules: {e}")
                raise PurpleForgeError(
                    f"Failed to generate {fmt} rules: {e}",
                    hint="Check that scenario was executed successfully",
                )

        return results

    def _load_scenario(self) -> Dict[str, Any]:
        """Load scenario data."""
        scenario_path = self.run_dir / "scenario.yaml"
        if not scenario_path.exists():
            scenario_path = self.run_dir / "scenario.yml"

        if not scenario_path.exists():
            raise PurpleForgeError(
                "Scenario file not found in run directory",
                hint="Ensure the run completed successfully",
            )

        import yaml

        with open(scenario_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def _load_telemetry(self) -> List[Dict[str, Any]]:
        """Load telemetry data."""
        telemetry_files = list((self.run_dir / "telemetry" / "raw").glob("*.jsonl"))

        events = []
        for file_path in telemetry_files:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        events.append(json.loads(line))

        return events

    def _load_correlation(self) -> Dict[str, Any]:
        """Load correlation data."""
        timeline_path = self.run_dir / "correlation" / "timeline.json"
        coverage_path = self.run_dir / "correlation" / "coverage.json"

        data = {}

        if timeline_path.exists():
            with open(timeline_path, "r", encoding="utf-8") as f:
                data["timeline"] = json.load(f)

        if coverage_path.exists():
            with open(coverage_path, "r", encoding="utf-8") as f:
                data["coverage"] = json.load(f)

        return data

    def _generate_format(
        self,
        format: str,
        scenario: Dict[str, Any],
        telemetry: List[Dict[str, Any]],
        correlation: Dict[str, Any],
    ) -> Path:
        """Generate detection rules for specific format."""
        generator = self.generators[format]
        rules = generator.generate(scenario, telemetry, correlation)

        # Save rules
        output_path = self.detections_dir / f"detections.{generator.file_extension}"
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(rules)

        return output_path
