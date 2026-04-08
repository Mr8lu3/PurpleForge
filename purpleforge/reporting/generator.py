"""Report generation using Jinja2 templates."""

import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from purpleforge.audit.redaction import Redactor
from purpleforge.scenarios.models import Scenario
from purpleforge.utils.exceptions import ReportError
from purpleforge.utils.logging import get_logger
from purpleforge.workspace.manager import WorkspaceManager, RunMetadata

logger = get_logger(__name__)


class ReportGenerator:
    """Generate Markdown and PDF reports."""

    def __init__(self, run_dir: Path, redaction_enabled: bool = True):
        """
        Initialize report generator.

        Args:
            run_dir: Run directory containing data
            redaction_enabled: Whether to redact PII/secrets from rendered report
        """
        self.run_dir = run_dir
        self.reports_dir = run_dir / "reports"
        self._redactor = Redactor(enabled=redaction_enabled)

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

            # Redact any PII / secrets that made it into the rendered output
            markdown_content = self._redactor.redact_text(markdown_content)

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

    def _load_campaign_data(self) -> Optional[Dict[str, Any]]:
        """
        Load campaign.json if this run_dir is a campaign directory.

        Returns None when the directory is a normal run dir.
        """
        campaign_json = self.run_dir / "campaign.json"
        if not campaign_json.exists():
            return None
        try:
            with open(campaign_json, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception as exc:
            logger.warning("Failed to load campaign.json: %s", exc)
            return None

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

        # Load binary findings if present
        binary_findings = None
        binary_findings_summary = None
        binary_findings_path = self.run_dir / "analysis" / "binary_findings.json"
        if binary_findings_path.exists():
            try:
                from purpleforge.analysis.findings_schema import load_findings, summarize
                findings = load_findings(binary_findings_path)
                # Sort by severity (high→medium→low) then confidence (high→medium→low)
                # so the template's top-N slice reflects true severity order, not
                # alphabetical string order.
                _SEV_RANK = {"high": 0, "medium": 1, "low": 2}
                findings_sorted = sorted(
                    findings,
                    key=lambda f: (
                        _SEV_RANK.get(f.severity, 99),
                        _SEV_RANK.get(f.confidence, 99),
                    ),
                )
                binary_findings = [f.model_dump() for f in findings_sorted]
                # Serialize datetime objects to ISO strings for template rendering
                for record in binary_findings:
                    if hasattr(record.get("created_at"), "isoformat"):
                        record["created_at"] = record["created_at"].isoformat()
                binary_findings_summary = summarize(findings_sorted)
            except Exception as e:
                logger.warning(f"Failed to load binary findings: {e}")

        # Load mirror findings if present (back-compat: missing file -> no section).
        mirror_findings = None
        mirror_findings_summary = None
        mirror_findings_path = self.run_dir / "mirror" / "mirror_findings.json"
        if mirror_findings_path.exists():
            try:
                from purpleforge.analysis.findings_schema import load_findings, summarize
                mf_list = load_findings(mirror_findings_path)
                _SEV_RANK = {"high": 0, "medium": 1, "low": 2}
                mf_sorted = sorted(
                    mf_list,
                    key=lambda f: (
                        _SEV_RANK.get(f.severity, 99),
                        _SEV_RANK.get(f.confidence, 99),
                    ),
                )
                mirror_findings = [f.model_dump() for f in mf_sorted]
                for record in mirror_findings:
                    if hasattr(record.get("created_at"), "isoformat"):
                        record["created_at"] = record["created_at"].isoformat()
                mirror_findings_summary = summarize(mf_sorted)
            except Exception as e:
                logger.warning(f"Failed to load mirror findings: {e}")

        # Load campaign data if present (campaign directory detection).
        campaign_data = self._load_campaign_data()

        # Build Mermaid block for campaign summary if available.
        campaign_mermaid: Optional[str] = None
        if campaign_data is not None:
            mmd_path = self.run_dir / "killchain.mmd"
            if mmd_path.exists():
                try:
                    campaign_mermaid = mmd_path.read_text(encoding="utf-8")
                except Exception:
                    pass

        # Load audit integrity data if available.
        audit_integrity: Optional[Dict[str, Any]] = None
        audit_log_path = self.run_dir / "audit" / "run_audit.log.jsonl"
        if audit_log_path.exists():
            try:
                from purpleforge.audit.hash_chain import verify_log, HashChainLog
                ok, first_bad = verify_log(audit_log_path)
                chain_length = 0
                first_ts: Optional[str] = None
                last_ts: Optional[str] = None
                chain_log = HashChainLog(audit_log_path)
                for entry in chain_log.entries():
                    chain_length += 1
                    ts = entry.get("ts", "")
                    if first_ts is None:
                        first_ts = ts
                    last_ts = ts
                audit_integrity = {
                    "intact": ok,
                    "chain_length": chain_length,
                    "first_bad_seq": first_bad,
                    "first_ts": first_ts,
                    "last_ts": last_ts,
                }
            except Exception as exc:
                logger.warning("Failed to load audit integrity data: %s", exc)

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
            "binary_findings": binary_findings,
            "binary_findings_summary": binary_findings_summary,
            "campaign": campaign_data,
            "campaign_mermaid": campaign_mermaid,
            "mirror_findings": mirror_findings,
            "mirror_findings_summary": mirror_findings_summary,
            "audit_integrity": audit_integrity,
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
