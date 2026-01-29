"""Report generation using Jinja2 templates."""

import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from purpleforge.scenarios.models import Scenario
from purpleforge.utils.exceptions import ReportError
from purpleforge.utils.logging import get_logger
from purpleforge.workspace.manager import WorkspaceManager, RunMetadata

logger = get_logger(__name__)


class ReportGenerator:
    """Generate Markdown and PDF reports."""

    def __init__(self, run_dir: Path):
        """
        Initialize report generator.

        Args:
            run_dir: Run directory containing data
        """
        self.run_dir = run_dir
        self.reports_dir = run_dir / "reports"

        # Setup Jinja2 environment
        template_dir = Path(__file__).parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate(self) -> Path:
        """
        Generate incident report.

        Returns:
            Path to generated Markdown report

        Raises:
            ReportError: If report generation fails
        """
        logger.info("Generating incident report")

        try:
            # Load data
            data = self._load_report_data()

            # Render template
            template = self.env.get_template("incident_report.md.j2")
            markdown_content = template.render(**data)

            # Write Markdown report
            markdown_path = self.reports_dir / "incident_report.md"
            with open(markdown_path, "w", encoding="utf-8") as f:
                f.write(markdown_content)

            logger.info(f"Markdown report generated: {markdown_path}")

            # Try to generate PDF if pandoc is available
            self._try_generate_pdf(markdown_path)

            return markdown_path

        except Exception as e:
            raise ReportError(
                f"Failed to generate report: {e}",
                hint="Check that all required data files exist in the run directory",
            )

    def get_report_data(self) -> Dict[str, Any]:
        """
        Get report data for export.

        Returns:
            Dictionary with all report data
        """
        return self._load_report_data()

    def _load_report_data(self) -> Dict[str, Any]:
        """Load all data needed for report generation."""
        # Load metadata
        workspace_manager = WorkspaceManager(self.run_dir.parent)
        metadata = workspace_manager.load_metadata(self.run_dir)

        # Load scenario
        scenario_path = self.run_dir / "scenario.yaml"
        if not scenario_path.exists():
            scenario_path = self.run_dir / "scenario.yml"

        scenario_data = None
        if scenario_path.exists():
            import yaml

            with open(scenario_path, "r", encoding="utf-8") as f:
                scenario_data = yaml.safe_load(f)

        # Load target metadata
        target_path = self.run_dir / "target.json"
        target_data = {}
        if target_path.exists():
            with open(target_path, "r", encoding="utf-8") as f:
                target_data = json.load(f)

        # Load coverage
        coverage_path = self.run_dir / "correlation" / "coverage.json"
        coverage_data = {}
        if coverage_path.exists():
            with open(coverage_path, "r", encoding="utf-8") as f:
                coverage_data = json.load(f)

        # Load timeline
        timeline_path = self.run_dir / "correlation" / "timeline.json"
        timeline_data = []
        if timeline_path.exists():
            with open(timeline_path, "r", encoding="utf-8") as f:
                timeline_data = json.load(f)

        return {
            "run_id": metadata.run_id,
            "tool_version": metadata.tool_version,
            "started_at": metadata.started_at,
            "completed_at": metadata.completed_at,
            "status": metadata.status,
            "platform": metadata.platform,
            "scenario": scenario_data,
            "target": target_data,
            "coverage": coverage_data,
            "timeline": timeline_data,
            "generated_at": datetime.utcnow(),
        }

    def _try_generate_pdf(self, markdown_path: Path) -> None:
        """
        Attempt to generate PDF using pandoc.

        Args:
            markdown_path: Path to Markdown file
        """
        try:
            pdf_path = markdown_path.with_suffix(".pdf")

            result = subprocess.run(
                [
                    "pandoc",
                    str(markdown_path),
                    "-o",
                    str(pdf_path),
                    "--pdf-engine=xelatex",
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode == 0:
                logger.info(f"PDF report generated: {pdf_path}")
            else:
                logger.warning(f"PDF generation failed: {result.stderr}")

        except FileNotFoundError:
            logger.info(
                "Pandoc not found - skipping PDF generation. "
                "Install pandoc to enable PDF reports."
            )
        except subprocess.TimeoutExpired:
            logger.warning("PDF generation timed out")
        except Exception as e:
            logger.warning(f"PDF generation error: {e}")
