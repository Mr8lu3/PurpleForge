"""Main CLI entry point using Typer."""

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from purpleforge import __version__, __tool_name__
from purpleforge.cli import commands

app = typer.Typer(
    name="purpleforge",
    help="CLI-driven purple team training and evaluation platform with strict ethical guardrails",
    add_completion=True,
)

console = Console()


@app.command()
def init(
    workspace_dir: Optional[Path] = typer.Option(
        None,
        "--workspace",
        "-w",
        help="Workspace directory for runs (default: ./runs)",
    ),
    scenarios_dir: Optional[Path] = typer.Option(
        None,
        "--scenarios",
        "-s",
        help="Directory for scenario files (default: ./scenarios)",
    ),
) -> None:
    """
    Initialize PurpleForge configuration and workspace.

    Creates configuration file, target allowlist, and local directories.
    """
    commands.init_command(workspace_dir, scenarios_dir)


@app.command()
def validate(
    scenario_path: Path = typer.Argument(
        ...,
        help="Path to scenario YAML file",
        exists=True,
    ),
) -> None:
    """
    Validate a scenario file against the schema.

    Checks YAML syntax and validates against Pydantic models.
    """
    commands.validate_command(scenario_path)


@app.command()
def verify(
    base_url: str = typer.Option(
        ...,
        "--base-url",
        "-u",
        help="Target base URL to verify",
    ),
    description: Optional[str] = typer.Option(
        None,
        "--description",
        "-d",
        help="Optional description for this target",
    ),
    token: Optional[str] = typer.Option(
        None,
        "--token",
        help="Pre-specified token for automated verification",
    ),
    skip_prompt: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip confirmation prompt",
    ),
) -> None:
    """
    Verify ownership of a target and add to allowlist.

    Generates a verification token and instructs user to place it at:
    {base_url}/.well-known/purpleforge-verify.txt

    Once verified, the target is added to the allowlist.
    """
    commands.verify_command(base_url, description, token=token, skip_prompt=skip_prompt)


@app.command()
def run(
    scenario_path: Path = typer.Argument(
        ...,
        help="Path to scenario YAML file",
        exists=True,
    ),
    target: str = typer.Option(
        ...,
        "--target",
        "-t",
        help="Target base URL",
    ),
    acknowledge_controlled: bool = typer.Option(
        False,
        "--acknowledge-controlled",
        help="Acknowledge execution of controlled mode scenario",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip confirmation prompts",
    ),
) -> None:
    """
    Execute a security assessment scenario.

    Requires target to be verified in allowlist (for web scenarios).
    Creates a run directory with full telemetry and generates reports.
    """
    commands.run_command(scenario_path, target, acknowledge_controlled, yes)


@app.command()
def report(
    run_id: str = typer.Argument(
        ...,
        help="Run ID to generate report for",
    ),
    workspace_dir: Optional[Path] = typer.Option(
        None,
        "--workspace",
        "-w",
        help="Workspace directory (default: from config)",
    ),
) -> None:
    """
    Generate incident report for a completed run.

    Creates Markdown report and attempts PDF generation if pandoc is available.
    """
    commands.report_command(run_id, workspace_dir)


@app.command()
def list_runs(
    workspace_dir: Optional[Path] = typer.Option(
        None,
        "--workspace",
        "-w",
        help="Workspace directory (default: from config)",
    ),
    limit: int = typer.Option(
        10,
        "--limit",
        "-n",
        help="Maximum number of runs to display",
    ),
) -> None:
    """
    List recent runs in workspace.

    Shows run IDs, timestamps, and status.
    """
    commands.list_runs_command(workspace_dir, limit)


@app.command()
def version() -> None:
    """Display PurpleForge version information."""
    console.print(
        Panel(
            f"[bold cyan]{__tool_name__}[/bold cyan]\n"
            f"Version: [bold]{__version__}[/bold]\n\n"
            f"CLI-driven purple team training and evaluation platform",
            title="About",
            border_style="cyan",
        )
    )


# ==================== Blue Team Commands ====================

@app.command()
def ingest(
    source: str = typer.Option(
        ...,
        "--source",
        "-s",
        help="Log source type (sysmon, winevtx, webserver, csv)",
    ),
    file: Path = typer.Option(
        ...,
        "--file",
        "-f",
        help="Path to log file",
        exists=True,
    ),
    run_id: Optional[str] = typer.Option(
        None,
        "--run",
        "-r",
        help="Run ID to associate logs with",
    ),
) -> None:
    """
    Ingest blue team logs for correlation.

    Supported sources: sysmon, winevtx, webserver, csv
    """
    commands.ingest_command(source, file, run_id)


@app.command()
def correlate(
    run_id: str = typer.Argument(
        ...,
        help="Run ID to correlate",
    ),
    time_window: int = typer.Option(
        60,
        "--window",
        "-w",
        help="Time window in seconds for correlation",
    ),
) -> None:
    """
    Correlate red team actions with blue team detections.

    Shows which attack steps were visible in defensive logs.
    """
    commands.correlate_command(run_id, time_window)


# ==================== Detection Commands ====================

@app.command(name="generate-detections")
def generate_detections(
    run_id: str = typer.Argument(
        ...,
        help="Run ID to generate detections for",
    ),
    format: str = typer.Option(
        "sigma",
        "--format",
        "-f",
        help="Detection format (sigma, splunk, elastic, yara, snort)",
    ),
    all_formats: bool = typer.Option(
        False,
        "--all",
        "-a",
        help="Generate all detection formats",
    ),
) -> None:
    """
    Generate detection rules from scenario execution.

    Outputs detection rules based on the executed steps.
    """
    commands.generate_detections_command(run_id, format, all_formats)


# ==================== ATT&CK Commands ====================

attack_app = typer.Typer(help="ATT&CK framework commands")
app.add_typer(attack_app, name="attack")


@attack_app.command(name="lookup")
def attack_lookup(
    technique_id: str = typer.Argument(
        ...,
        help="ATT&CK technique ID (e.g., T1190)",
    ),
) -> None:
    """
    Look up ATT&CK technique details.

    Shows description, mitigations, and data sources.
    """
    commands.attack_lookup_command(technique_id)


@attack_app.command(name="export-navigator")
def attack_export_navigator(
    run_id: str = typer.Argument(
        ...,
        help="Run ID to export Navigator layer for",
    ),
) -> None:
    """
    Export ATT&CK Navigator layer for a run.

    Creates a JSON file that can be imported into ATT&CK Navigator.
    """
    commands.attack_export_navigator_command(run_id)


# ==================== Artifact Commands ====================

artifact_app = typer.Typer(help="Artifact management commands")
app.add_typer(artifact_app, name="artifact")


@artifact_app.command(name="add")
def artifact_add(
    file: Path = typer.Argument(
        ...,
        help="Path to artifact file",
        exists=True,
    ),
    run_id: str = typer.Option(
        ...,
        "--run",
        "-r",
        help="Run ID to associate artifact with",
    ),
    tags: Optional[str] = typer.Option(
        None,
        "--tags",
        "-t",
        help="Comma-separated tags",
    ),
) -> None:
    """
    Add an artifact to a run for analysis.

    Calculates hashes and stores the artifact.
    """
    tag_list = tags.split(",") if tags else None
    commands.artifact_add_command(file, run_id, tag_list)


@artifact_app.command(name="analyze")
def artifact_analyze(
    artifact_id: str = typer.Argument(
        ...,
        help="Artifact ID to analyze",
    ),
    run_id: str = typer.Option(
        ...,
        "--run",
        "-r",
        help="Run ID containing the artifact",
    ),
    use_ghidra: bool = typer.Option(
        False,
        "--ghidra",
        "-g",
        help="Use Ghidra for deep analysis (requires GHIDRA_HOME)",
    ),
) -> None:
    """
    Analyze an artifact.

    Performs static analysis including PE/ELF parsing, string extraction,
    and optionally Ghidra analysis.
    """
    commands.artifact_analyze_command(artifact_id, run_id, use_ghidra)


@artifact_app.command(name="list")
def artifact_list(
    run_id: str = typer.Option(
        ...,
        "--run",
        "-r",
        help="Run ID to list artifacts for",
    ),
) -> None:
    """
    List artifacts in a run.

    Shows artifact IDs, filenames, types, and analysis status.
    """
    commands.artifact_list_command(run_id)


# ==================== Export Commands ====================

@app.command(name="export")
def export_report(
    run_id: str = typer.Argument(
        ...,
        help="Run ID to export report for",
    ),
    format: str = typer.Option(
        "html",
        "--format",
        "-f",
        help="Export format (html, pdf, docx, json, all)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output path (default: run reports directory)",
    ),
) -> None:
    """
    Export report in various formats.

    Formats: html (styled), pdf (requires weasyprint/pandoc),
    docx (Word), json (machine-readable), all (all formats).
    """
    commands.export_report_command(run_id, format, output)


def main() -> None:
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
