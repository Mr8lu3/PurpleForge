"""CLI command implementations."""

import hashlib
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from purpleforge import __version__
from purpleforge.config import Config, TargetEntry, load_config, save_config, load_targets, save_targets
from purpleforge.config.loader import get_config_path, get_targets_path
from purpleforge.correlation import CorrelationEngine
from purpleforge.reporting import ReportGenerator
from purpleforge.runners import WebRunner
from purpleforge.scenarios import load_scenario, validate_scenario
from purpleforge.scenarios.models import ScenarioMode, TargetType
from purpleforge.utils.exceptions import PurpleForgeError, VerificationError, AnalysisError, MirrorError
from purpleforge.utils.logging import setup_logging, console, error_console
from purpleforge.utils.platform import get_user_config_dir
from purpleforge.verification import (
    VerificationStatus,
    generate_verification_token,
    verify_target_ownership,
    hash_token,
)
from purpleforge.workspace import WorkspaceManager, RunMetadata
from purpleforge.workspace.manager import RunStatus, VerificationMetadata

# Rich console for output
output_console = Console()


def init_command(
    workspace_dir: Optional[Path],
    scenarios_dir: Optional[Path],
) -> None:
    """Initialize PurpleForge configuration."""
    try:
        config_dir = get_user_config_dir()
        config_path = get_config_path()
        targets_path = get_targets_path()

        # Create config directory
        config_dir.mkdir(parents=True, exist_ok=True)

        # Create or load config
        if config_path.exists():
            config = load_config()
            output_console.print(
                f"[yellow]Configuration already exists at {config_path}[/yellow]"
            )
        else:
            config = Config()
            if workspace_dir:
                config.workspace_dir = workspace_dir.resolve()
            if scenarios_dir:
                config.scenarios_dir = scenarios_dir.resolve()

            save_config(config)
            output_console.print(
                f"[green]Created configuration at {config_path}[/green]"
            )

        # Create targets file if not exists
        if not targets_path.exists():
            save_targets(load_targets())
            output_console.print(
                f"[green]Created targets allowlist at {targets_path}[/green]"
            )

        # Create local directories
        config.workspace_dir.mkdir(parents=True, exist_ok=True)
        output_console.print(
            f"[green]Created workspace directory: {config.workspace_dir}[/green]"
        )

        config.scenarios_dir.mkdir(parents=True, exist_ok=True)
        output_console.print(
            f"[green]Created scenarios directory: {config.scenarios_dir}[/green]"
        )

        # Display next steps
        output_console.print(
            Panel(
                "[bold cyan]Next Steps:[/bold cyan]\n\n"
                "1. Create a scenario YAML file in the scenarios directory\n"
                "2. Verify target ownership: [bold]purpleforge verify --base-url <url>[/bold]\n"
                "3. Run a scenario: [bold]purpleforge run <scenario.yml> --target <url>[/bold]\n"
                "4. Generate report: [bold]purpleforge report <run_id>[/bold]",
                title="PurpleForge Initialized",
                border_style="green",
            )
        )

    except Exception as e:
        error_console.print(f"[bold red]Initialization failed:[/bold red] {e}")
        raise typer.Exit(code=1)


def validate_command(scenario_path: Path) -> None:
    """Validate a scenario file."""
    try:
        output_console.print(f"[cyan]Validating scenario:[/cyan] {scenario_path}")

        is_valid, errors, scenario = validate_scenario(scenario_path)

        if is_valid and scenario:
            output_console.print("[bold green]Scenario is valid![/bold green]")

            # Display scenario summary
            table = Table(title="Scenario Summary")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="white")

            table.add_row("Name", scenario.name)
            table.add_row("Category", scenario.category.value)
            table.add_row("Mode", scenario.mode.value)
            table.add_row("Steps", str(len(scenario.steps)))
            table.add_row(
                "Ownership Verification",
                "Required" if scenario.ownership_verification else "Not Required",
            )

            output_console.print(table)

            # Display steps
            if scenario.steps:
                steps_table = Table(title="Steps")
                steps_table.add_column("ID", style="cyan")
                steps_table.add_column("Type", style="yellow")
                steps_table.add_column("Description", style="white")

                for step in scenario.steps:
                    steps_table.add_row(
                        step.id,
                        step.type,
                        step.description[:60] + "..." if len(step.description) > 60 else step.description,
                    )

                output_console.print(steps_table)

        else:
            error_console.print("[bold red]Scenario validation failed:[/bold red]")
            for error in errors:
                error_console.print(f"  {error}")
            raise typer.Exit(code=1)

    except PurpleForgeError as e:
        error_console.print(f"[bold red]Error:[/bold red] {e}")
        if e.hint:
            error_console.print(f"[yellow]Hint:[/yellow] {e.hint}")
        raise typer.Exit(code=1)


def verify_command(
    base_url: str,
    description: Optional[str],
    token: Optional[str] = None,
    skip_prompt: bool = False,
) -> None:
    """Verify target ownership."""
    try:
        # Use provided token or generate new one
        if token is None:
            token = generate_verification_token()
        token_hash_value = hash_token(token)

        output_console.print(
            Panel(
                f"[bold cyan]Target Verification[/bold cyan]\n\n"
                f"To verify ownership of [bold]{base_url}[/bold], place the following token at:\n\n"
                f"[bold yellow]{base_url}/.well-known/purpleforge-verify.txt[/bold yellow]\n\n"
                f"Token: [bold green]{token}[/bold green]\n\n"
                f"The file should contain only the token (no extra whitespace or newlines).",
                border_style="cyan",
            )
        )

        # Wait for user confirmation unless skip_prompt is set
        if skip_prompt:
            ready = True
        else:
            ready = Confirm.ask("Have you placed the verification file?")

        if not ready:
            output_console.print("[yellow]Verification cancelled[/yellow]")
            raise typer.Exit(code=0)

        # Attempt verification
        output_console.print("[cyan]Verifying target...[/cyan]")

        result = verify_target_ownership(base_url, token, timeout=10)

        if result.status == VerificationStatus.VERIFIED:
            output_console.print("[bold green]Verification successful![/bold green]")

            # Add to allowlist
            allowlist = load_targets()
            allowlist.targets[base_url] = TargetEntry(
                base_url=base_url,
                verified_at=result.checked_at,
                token_hash=token_hash_value,
                description=description,
            )
            save_targets(allowlist)

            output_console.print(
                f"[green]Target added to allowlist at {get_targets_path()}[/green]"
            )

        elif result.status == VerificationStatus.FAILED:
            error_console.print(
                f"[bold red]Verification failed:[/bold red] {result.message}"
            )
            error_console.print(
                "[yellow]Make sure the token is correctly placed and accessible[/yellow]"
            )
            raise typer.Exit(code=1)

        elif result.status == VerificationStatus.TIMEOUT:
            error_console.print("[bold red]Verification timed out[/bold red]")
            error_console.print(
                "[yellow]Check that the target is accessible and try again[/yellow]"
            )
            raise typer.Exit(code=1)

        else:
            error_console.print(
                f"[bold red]Verification error:[/bold red] {result.message}"
            )
            raise typer.Exit(code=1)

    except PurpleForgeError as e:
        error_console.print(f"[bold red]Error:[/bold red] {e}")
        if e.hint:
            error_console.print(f"[yellow]Hint:[/yellow] {e.hint}")
        raise typer.Exit(code=1)


def run_command(
    scenario_path: Path,
    target: str,
    acknowledge_controlled: bool,
    yes: bool,
) -> None:
    """Execute a scenario."""
    try:
        # Load configuration
        config = load_config()
        setup_logging(level=config.log_level)

        # Load scenario
        output_console.print(f"[cyan]Loading scenario:[/cyan] {scenario_path}")
        scenario = load_scenario(scenario_path)

        output_console.print(f"[green]Loaded scenario:[/green] {scenario.name}")

        # Check if controlled mode
        if scenario.mode == ScenarioMode.CONTROLLED:
            if not acknowledge_controlled:
                error_console.print(
                    "[bold red]This scenario requires controlled mode acknowledgement[/bold red]"
                )
                error_console.print(
                    "[yellow]Use --acknowledge-controlled flag to proceed[/yellow]"
                )
                raise typer.Exit(code=1)

            if not yes:
                proceed = Confirm.ask(
                    "[yellow]This is a CONTROLLED mode scenario. "
                    "Ensure target is in an isolated lab environment. Proceed?[/yellow]"
                )
                if not proceed:
                    output_console.print("[yellow]Execution cancelled[/yellow]")
                    raise typer.Exit(code=0)

        # Check ownership verification requirement
        verification_result = None
        if scenario.ownership_verification and scenario.target.type == TargetType.WEB:
            output_console.print("[cyan]Checking target verification...[/cyan]")

            allowlist = load_targets()

            if target not in allowlist.targets:
                error_console.print(
                    f"[bold red]Target not verified:[/bold red] {target}"
                )
                error_console.print(
                    "[yellow]Run 'purpleforge verify --base-url <url>' first[/yellow]"
                )
                raise typer.Exit(code=1)

            target_entry = allowlist.targets[target]
            output_console.print(
                f"[green]Target verified on {target_entry.verified_at}[/green]"
            )

            # Re-verify ownership
            temp_token = generate_verification_token()
            verification_result = verify_target_ownership(target, temp_token, timeout=10)

            # Note: In production, you'd want to check if the stored token is still valid
            # For MVP, we just verify connectivity

        # Create run workspace
        workspace_manager = WorkspaceManager(config.workspace_dir)

        acknowledgements = []
        if acknowledge_controlled:
            acknowledgements.append("controlled_mode")

        run_id, run_dir = workspace_manager.create_run(
            scenario_name=scenario.name,
            acknowledgements=acknowledgements,
        )

        output_console.print(f"[green]Created run:[/green] {run_id}")
        output_console.print(f"[green]Run directory:[/green] {run_dir}")

        # Copy scenario to run directory
        scenario_copy_path = run_dir / "scenario.yaml"
        shutil.copy(scenario_path, scenario_copy_path)

        # Save target metadata
        target_metadata = {
            "base_url": target,
            "verification_status": verification_result.status.value if verification_result else "skipped",
            "verified_at": datetime.utcnow().isoformat(),
        }
        with open(run_dir / "target.json", "w", encoding="utf-8") as f:
            json.dump(target_metadata, f, indent=2)

        # Update metadata with verification info
        metadata = workspace_manager.load_metadata(run_dir)
        if verification_result:
            metadata.target_verification = VerificationMetadata(
                status=verification_result.status.value,
                checked_at=verification_result.checked_at,
                method=verification_result.method,
            )

        # Calculate scenario hash
        with open(scenario_path, "rb") as f:
            metadata.scenario_hash = hashlib.sha256(f.read()).hexdigest()

        workspace_manager.save_metadata(run_dir, metadata)

        # Execute scenario
        output_console.print(
            Panel(
                f"[bold cyan]Executing Scenario[/bold cyan]\n\n"
                f"Name: {scenario.name}\n"
                f"Target: {target}\n"
                f"Steps: {len(scenario.steps)}",
                border_style="cyan",
            )
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=output_console,
        ) as progress:
            task = progress.add_task("Running scenario...", total=None)

            if scenario.target.type == TargetType.WEB:
                with WebRunner(
                    scenario=scenario,
                    run_dir=run_dir,
                    base_url=target,
                    timeout=config.default_timeout,
                    max_response_log_size=config.max_response_log_size,
                ) as runner:
                    results = runner.execute()
            else:
                error_console.print(
                    f"[bold red]Unsupported target type:[/bold red] {scenario.target.type}"
                )
                raise typer.Exit(code=1)

            progress.update(task, completed=True)

        # Update run status
        workspace_manager.update_status(
            run_dir,
            RunStatus.COMPLETED,
            completed_at=datetime.utcnow(),
        )

        # Display results
        output_console.print(
            Panel(
                f"[bold green]Scenario Execution Complete[/bold green]\n\n"
                f"Successful Steps: {results['successful_steps']}/{results['total_steps']}\n"
                f"Failed Steps: {results['failed_steps']}\n\n"
                f"Run ID: [bold]{run_id}[/bold]",
                border_style="green",
            )
        )

        # Run correlation
        output_console.print("[cyan]Running correlation analysis...[/cyan]")
        correlation_engine = CorrelationEngine(run_dir)
        correlation_results = correlation_engine.correlate()

        output_console.print(
            f"[green]Coverage: {correlation_results['coverage']['coverage_percentage']:.1f}%[/green]"
        )

        # Generate report
        output_console.print("[cyan]Generating report...[/cyan]")
        report_generator = ReportGenerator(run_dir)
        report_path = report_generator.generate()

        output_console.print(f"[green]Report generated:[/green] {report_path}")

        output_console.print(
            Panel(
                f"[bold cyan]Next Steps[/bold cyan]\n\n"
                f"View report: [bold]cat {report_path}[/bold]\n"
                f"Generate report again: [bold]purpleforge report {run_id}[/bold]\n"
                f"List all runs: [bold]purpleforge list-runs[/bold]",
                border_style="cyan",
            )
        )

    except PurpleForgeError as e:
        error_console.print(f"[bold red]Error:[/bold red] {e}")
        if e.hint:
            error_console.print(f"[yellow]Hint:[/yellow] {e.hint}")
        raise typer.Exit(code=1)
    except Exception as e:
        error_console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        raise typer.Exit(code=1)


def report_command(run_id: str, workspace_dir: Optional[Path]) -> None:
    """Generate report for a run."""
    try:
        # Load configuration
        config = load_config()

        if workspace_dir:
            workspace_root = workspace_dir.resolve()
        else:
            workspace_root = config.workspace_dir

        # Get run directory
        workspace_manager = WorkspaceManager(workspace_root)
        run_dir = workspace_manager.get_run_dir(run_id)

        output_console.print(f"[cyan]Generating report for run:[/cyan] {run_id}")

        # Generate report
        report_generator = ReportGenerator(run_dir)
        report_path = report_generator.generate()

        output_console.print(
            Panel(
                f"[bold green]Report Generated[/bold green]\n\n"
                f"Markdown: {report_path}\n"
                f"PDF: {report_path.with_suffix('.pdf')} (if pandoc available)",
                border_style="green",
            )
        )

    except PurpleForgeError as e:
        error_console.print(f"[bold red]Error:[/bold red] {e}")
        if e.hint:
            error_console.print(f"[yellow]Hint:[/yellow] {e.hint}")
        raise typer.Exit(code=1)


def list_runs_command(workspace_dir: Optional[Path], limit: int) -> None:
    """List recent runs."""
    try:
        # Load configuration
        config = load_config()

        if workspace_dir:
            workspace_root = workspace_dir.resolve()
        else:
            workspace_root = config.workspace_dir

        workspace_manager = WorkspaceManager(workspace_root)
        runs = workspace_manager.list_runs()

        if not runs:
            output_console.print("[yellow]No runs found in workspace[/yellow]")
            return

        # Display runs table
        table = Table(title=f"Recent Runs (showing {min(limit, len(runs))} of {len(runs)})")
        table.add_column("Run ID", style="cyan")
        table.add_column("Started", style="white")
        table.add_column("Status", style="yellow")
        table.add_column("Version", style="white")

        for run_id, metadata in runs[:limit]:
            table.add_row(
                run_id[:8] + "...",
                metadata.started_at.strftime("%Y-%m-%d %H:%M:%S"),
                metadata.status,
                metadata.tool_version,
            )

        output_console.print(table)

    except PurpleForgeError as e:
        error_console.print(f"[bold red]Error:[/bold red] {e}")
        if e.hint:
            error_console.print(f"[yellow]Hint:[/yellow] {e.hint}")
        raise typer.Exit(code=1)


# ==================== Blue Team Commands ====================

def ingest_command(source: str, file: Path, run_id: Optional[str]) -> None:
    """Ingest blue team logs."""
    try:
        from purpleforge.blueteam import BlueTeamIngester
        from purpleforge.config import load_config

        config = load_config()

        if run_id:
            run_dir = config.workspace_dir / run_id
            if not run_dir.exists():
                error_console.print(f"[bold red]Run not found:[/bold red] {run_id}")
                raise typer.Exit(code=1)
        else:
            # Use current working directory
            run_dir = Path.cwd()

        output_console.print(f"[cyan]Ingesting {source} logs from {file}...[/cyan]")

        ingester = BlueTeamIngester(run_dir)
        count = ingester.ingest(source, file, run_id)

        output_console.print(f"[bold green]Successfully ingested {count} events[/bold green]")

        stats = ingester.get_event_statistics()
        if stats["total_events"] > 0:
            output_console.print(f"Total events: {stats['total_events']}")
            output_console.print(f"By source: {stats['by_source']}")

    except PurpleForgeError as e:
        error_console.print(f"[bold red]Error:[/bold red] {e}")
        if e.hint:
            error_console.print(f"[yellow]Hint:[/yellow] {e.hint}")
        raise typer.Exit(code=1)


def correlate_command(run_id: str, time_window: int) -> None:
    """Correlate red and blue team events."""
    try:
        from purpleforge.blueteam import RedBlueCorrelator
        from purpleforge.config import load_config

        config = load_config()
        run_dir = config.workspace_dir / run_id

        if not run_dir.exists():
            error_console.print(f"[bold red]Run not found:[/bold red] {run_id}")
            raise typer.Exit(code=1)

        output_console.print(f"[cyan]Correlating events for run {run_id[:8]}...[/cyan]")

        correlator = RedBlueCorrelator(run_dir, time_window)
        result = correlator.correlate()
        correlator.save_results(result)

        output_console.print(
            Panel(
                f"[bold]Correlation Results[/bold]\n\n"
                f"Red Team Steps: {result.total_red_team_steps}\n"
                f"Blue Team Events: {result.total_blue_team_events}\n"
                f"Steps Detected: {result.matched_steps}\n"
                f"[bold green]Detection Coverage: {result.detection_coverage}%[/bold green]\n\n"
                f"Undetected Steps: {', '.join(result.unmatched_steps) if result.unmatched_steps else 'None'}",
                title="Purple Team Correlation",
                border_style="magenta",
            )
        )

    except PurpleForgeError as e:
        error_console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)


# ==================== Detection Commands ====================

def generate_detections_command(run_id: str, format: str, all_formats: bool) -> None:
    """Generate detection rules."""
    try:
        from purpleforge.detections import DetectionGenerator
        from purpleforge.config import load_config

        config = load_config()
        run_dir = config.workspace_dir / run_id

        if not run_dir.exists():
            error_console.print(f"[bold red]Run not found:[/bold red] {run_id}")
            raise typer.Exit(code=1)

        generator = DetectionGenerator(run_dir)

        formats_to_generate = ["sigma", "splunk", "elastic", "yara", "snort"] if all_formats else [format]

        for fmt in formats_to_generate:
            output_console.print(f"[cyan]Generating {fmt} detections...[/cyan]")
            output_path = generator.generate(fmt)
            if output_path:
                output_console.print(f"[green]Created: {output_path}[/green]")

        output_console.print(f"[bold green]Detection rules saved to {run_dir}/detections/[/bold green]")

    except PurpleForgeError as e:
        error_console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        error_console.print(f"[bold red]Error generating detections:[/bold red] {e}")
        raise typer.Exit(code=1)


# ==================== ATT&CK Commands ====================

def attack_lookup_command(technique_id: str) -> None:
    """Look up ATT&CK technique."""
    try:
        from purpleforge.attack import AttackTechniqueDatabase

        db = AttackTechniqueDatabase()
        tech = db.lookup(technique_id)

        if not tech:
            error_console.print(f"[bold red]Technique not found:[/bold red] {technique_id}")
            error_console.print("[yellow]Try a valid ID like T1190, T1059, T1059.007[/yellow]")
            raise typer.Exit(code=1)

        output_console.print(
            Panel(
                f"[bold cyan]{tech.id} - {tech.name}[/bold cyan]\n\n"
                f"[bold]Tactic:[/bold] {tech.tactic}\n"
                f"[bold]Platforms:[/bold] {', '.join(tech.platforms)}\n\n"
                f"[bold]Description:[/bold]\n{tech.description[:500]}{'...' if len(tech.description) > 500 else ''}\n\n"
                f"[bold]Detection:[/bold]\n{tech.detection[:300]}{'...' if len(tech.detection) > 300 else ''}\n\n"
                f"[bold]URL:[/bold] {tech.url}",
                title="ATT&CK Technique",
                border_style="cyan",
            )
        )

        if tech.mitigations:
            output_console.print("\n[bold]Mitigations:[/bold]")
            table = Table()
            table.add_column("ID", style="cyan")
            table.add_column("Name", style="white")
            table.add_column("Description", style="dim")
            for m in tech.mitigations[:10]:
                table.add_row(m.id, m.name, m.description[:60] + "...")
            output_console.print(table)

    except typer.Exit:
        raise
    except Exception as e:
        error_console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)


def attack_export_navigator_command(run_id: str) -> None:
    """Export ATT&CK Navigator layer."""
    try:
        from purpleforge.attack import export_run_navigator_layer
        from purpleforge.config import load_config

        config = load_config()
        run_dir = config.workspace_dir / run_id

        if not run_dir.exists():
            error_console.print(f"[bold red]Run not found:[/bold red] {run_id}")
            raise typer.Exit(code=1)

        output_path = export_run_navigator_layer(run_dir)
        output_console.print(f"[bold green]Navigator layer exported to:[/bold green] {output_path}")
        output_console.print("[cyan]Import this file at https://mitre-attack.github.io/attack-navigator/[/cyan]")

    except Exception as e:
        error_console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)


# ==================== Artifact Commands ====================

def artifact_add_command(file: Path, run_id: str, tags: Optional[List[str]]) -> None:
    """Add artifact to run."""
    try:
        from purpleforge.analysis import ArtifactManager
        from purpleforge.config import load_config

        config = load_config()
        run_dir = config.workspace_dir / run_id

        if not run_dir.exists():
            error_console.print(f"[bold red]Run not found:[/bold red] {run_id}")
            raise typer.Exit(code=1)

        manager = ArtifactManager(run_dir)
        metadata = manager.add_artifact(file, tags=tags)

        output_console.print(
            Panel(
                f"[bold green]Artifact Added[/bold green]\n\n"
                f"[bold]ID:[/bold] {metadata.artifact_id}\n"
                f"[bold]File:[/bold] {metadata.original_filename}\n"
                f"[bold]Type:[/bold] {metadata.file_type}\n"
                f"[bold]Size:[/bold] {metadata.file_size:,} bytes\n"
                f"[bold]SHA256:[/bold] {metadata.hashes.sha256}",
                border_style="green",
            )
        )

    except Exception as e:
        error_console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)


def artifact_analyze_command(artifact_id: str, run_id: str, use_ghidra: bool) -> None:
    """Analyze artifact."""
    try:
        from purpleforge.analysis import ArtifactManager, analyze_pe, get_ghidra_analyzer
        from purpleforge.config import load_config

        config = load_config()
        run_dir = config.workspace_dir / run_id

        if not run_dir.exists():
            error_console.print(f"[bold red]Run not found:[/bold red] {run_id}")
            raise typer.Exit(code=1)

        manager = ArtifactManager(run_dir)
        metadata = manager.get_artifact(artifact_id)

        if not metadata:
            error_console.print(f"[bold red]Artifact not found:[/bold red] {artifact_id}")
            raise typer.Exit(code=1)

        artifact_path = manager.get_artifact_path(artifact_id)
        output_console.print(f"[cyan]Analyzing {metadata.original_filename}...[/cyan]")

        results = {}

        # Basic analysis based on file type
        if metadata.file_type == "PE":
            output_console.print("[cyan]Running PE analysis...[/cyan]")
            results["pe_analysis"] = analyze_pe(artifact_path)

        # Ghidra analysis if requested
        if use_ghidra:
            ghidra = get_ghidra_analyzer()
            if ghidra:
                output_console.print("[cyan]Running Ghidra analysis...[/cyan]")
                ghidra_results = ghidra.analyze(artifact_path, run_dir / "artifacts")
                if ghidra_results:
                    results["ghidra_analysis"] = ghidra_results
            else:
                output_console.print("[yellow]Ghidra not available (set GHIDRA_HOME)[/yellow]")

        # Update artifact with results
        manager.update_analysis_results(artifact_id, results, status="analyzed")

        output_console.print("[bold green]Analysis complete![/bold green]")

        # Show summary
        if "pe_analysis" in results:
            pe = results["pe_analysis"]
            output_console.print(f"Entropy: {pe.get('entropy', 'N/A')}")
            output_console.print(f"Sections: {len(pe.get('sections', []))}")
            output_console.print(f"Imports: {len(pe.get('imports', []))}")
            if pe.get("indicators"):
                output_console.print(f"[yellow]Suspicious indicators: {len(pe['indicators'])}[/yellow]")

    except Exception as e:
        error_console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)


def artifact_list_command(run_id: str) -> None:
    """List artifacts in run."""
    try:
        from purpleforge.analysis import ArtifactManager
        from purpleforge.config import load_config

        config = load_config()
        run_dir = config.workspace_dir / run_id

        if not run_dir.exists():
            error_console.print(f"[bold red]Run not found:[/bold red] {run_id}")
            raise typer.Exit(code=1)

        manager = ArtifactManager(run_dir)
        artifacts = manager.list_artifacts()

        if not artifacts:
            output_console.print("[yellow]No artifacts in this run[/yellow]")
            return

        table = Table(title=f"Artifacts in {run_id[:8]}...")
        table.add_column("ID", style="cyan")
        table.add_column("Filename", style="white")
        table.add_column("Type", style="yellow")
        table.add_column("Size", style="white")
        table.add_column("Status", style="green")

        for artifact in artifacts:
            table.add_row(
                artifact.artifact_id[:8] + "...",
                artifact.original_filename,
                artifact.file_type,
                f"{artifact.file_size:,}",
                artifact.analysis_status,
            )

        output_console.print(table)

    except Exception as e:
        error_console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)


# ==================== Export Commands ====================

def export_report_command(run_id: str, format: str, output: Optional[Path]) -> None:
    """Export report in various formats."""
    try:
        from purpleforge.reporting.exporters import export_html, export_pdf, export_docx, export_json
        from purpleforge.config import load_config
        from purpleforge.reporting import ReportGenerator
        from purpleforge.attack import AttackTechniqueDatabase

        config = load_config()
        run_dir = config.workspace_dir / run_id

        if not run_dir.exists():
            error_console.print(f"[bold red]Run not found:[/bold red] {run_id}")
            raise typer.Exit(code=1)

        # Generate report data
        generator = ReportGenerator(run_dir)
        raw_data = generator.get_report_data()

        # Transform to exporter format
        scenario = raw_data.get("scenario", {}) or {}
        coverage = raw_data.get("coverage", {}) or {}
        target = raw_data.get("target", {}) or {}

        # Get ATT&CK technique details
        attack_techniques = []
        attack_db = AttackTechniqueDatabase()
        for tech_id in scenario.get("att_ck_techniques", []):
            tech = attack_db.lookup(tech_id)
            if tech:
                attack_techniques.append({
                    "id": tech.id,
                    "name": tech.name,
                    "tactic": tech.tactic,
                    "description": tech.description,
                    "url": tech.url,
                    "mitigations": [{"id": m.id, "name": m.name} for m in tech.mitigations],
                })

        # Build steps list for exporters
        steps = []
        step_coverage = {s["step_id"]: s for s in coverage.get("step_coverage", [])}
        for step in scenario.get("steps", []):
            step_id = step.get("id", "")
            cov = step_coverage.get(step_id, {})
            steps.append({
                "id": step_id,
                "type": step.get("type", ""),
                "description": step.get("description", ""),
                "has_evidence": cov.get("has_evidence", False),
                "evidence_count": cov.get("evidence_count", 0),
            })

        report_data = {
            "run_id": raw_data.get("run_id", ""),
            "tool_version": raw_data.get("tool_version", "0.1.0"),
            "status": raw_data.get("status", "completed"),
            "started_at": str(raw_data.get("started_at", "")),
            "completed_at": str(raw_data.get("completed_at", "")),
            "scenario_name": scenario.get("name", "Security Assessment"),
            "category": scenario.get("category", "web"),
            "mode": scenario.get("mode", "assess"),
            "target_url": target.get("base_url", "N/A"),
            "verification_status": target.get("verification_status", "unknown"),
            "total_steps": coverage.get("total_steps", 0),
            "steps_with_evidence": coverage.get("steps_with_evidence", 0),
            "coverage": coverage.get("coverage_percentage", 0),
            "steps": steps,
            "timeline": raw_data.get("timeline", []),
            "attack_techniques": attack_techniques,
            "detection_recommendations": "See Markdown report for detailed recommendations.",
        }

        # Default output directory
        if output:
            output_dir = output if output.is_dir() else output.parent
        else:
            output_dir = run_dir / "reports"
        output_dir.mkdir(parents=True, exist_ok=True)

        formats_to_export = ["html", "pdf", "docx", "json"] if format == "all" else [format]

        for fmt in formats_to_export:
            output_console.print(f"[cyan]Exporting {fmt.upper()} report...[/cyan]")

            if fmt == "html":
                path = export_html(report_data, output_dir / f"incident_report.html")
                output_console.print(f"[green]Created: {path}[/green]")

            elif fmt == "pdf":
                md_path = run_dir / "reports" / "incident_report.md"
                path = export_pdf(report_data, output_dir / f"incident_report.pdf", md_path)
                if path:
                    output_console.print(f"[green]Created: {path}[/green]")
                else:
                    output_console.print("[yellow]PDF export unavailable (install weasyprint or pandoc)[/yellow]")

            elif fmt == "docx":
                path = export_docx(report_data, output_dir / f"incident_report.docx")
                if path:
                    output_console.print(f"[green]Created: {path}[/green]")
                else:
                    output_console.print("[yellow]DOCX export unavailable (install python-docx)[/yellow]")

            elif fmt == "json":
                path = export_json(report_data, output_dir / f"incident_report.json")
                output_console.print(f"[green]Created: {path}[/green]")

        output_console.print(f"[bold green]Reports exported to {output_dir}[/bold green]")

    except Exception as e:
        error_console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)


def analyze_binary_command(
    binary_path: Path,
    run_id: Optional[str],
    output: Optional[Path],
    timeout: int,
) -> None:
    """
    Static binary analysis using Ghidra (defensive only).

    Authorized binaries only. Produces normalized findings for inclusion in reports.
    Output location precedence: --run-id > --output > ./analysis_output/<timestamp>/
    """
    from purpleforge.analysis.binary_analyzer import BinaryAnalyzer
    from purpleforge.analysis.findings_schema import summarize

    # Resolve output directory
    if run_id is not None:
        try:
            config = load_config()
            run_dir = config.workspace_dir / run_id
        except Exception:
            run_dir = Path("runs") / run_id

        if not run_dir.exists():
            error_console.print(
                f"[bold red]Error:[/bold red] Run directory not found: {run_dir}"
            )
            error_console.print(
                "[yellow]Hint:[/yellow] Run 'purpleforge list-runs' to see available run IDs."
            )
            raise typer.Exit(code=1)

        resolved_output = run_dir / "analysis"
    elif output is not None:
        resolved_output = output.resolve()
    else:
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        resolved_output = Path("./analysis_output") / timestamp

    analyzer = BinaryAnalyzer()

    output_console.print(
        f"[cyan]Analyzing binary (defensive static analysis, authorized use only):[/cyan] {binary_path}"
    )
    output_console.print(f"[cyan]Output directory:[/cyan] {resolved_output}")

    try:
        findings = analyzer.analyze(binary_path, resolved_output, timeout=timeout)
    except AnalysisError as e:
        error_console.print(
            Panel(
                f"[bold red]{e.message}[/bold red]",
                title="Analysis Error",
                border_style="red",
            )
        )
        if e.hint:
            error_console.print(f"[yellow]Hint:[/yellow] {e.hint}")
        raise typer.Exit(code=1)

    summary = summarize(findings)

    # Severity summary table
    sev_table = Table(title="Findings by Severity")
    sev_table.add_column("Severity", style="cyan")
    sev_table.add_column("Count", style="white", justify="right")
    by_sev = summary.get("by_severity", {})
    sev_table.add_row("[red]high[/red]", str(by_sev.get("high", 0)))
    sev_table.add_row("[yellow]medium[/yellow]", str(by_sev.get("medium", 0)))
    sev_table.add_row("[green]low[/green]", str(by_sev.get("low", 0)))
    sev_table.add_row("[bold]TOTAL[/bold]", str(summary.get("total", 0)))
    output_console.print(sev_table)

    # Category summary table
    by_cat = summary.get("by_category", {})
    if by_cat:
        cat_table = Table(title="Findings by Category")
        cat_table.add_column("Category", style="cyan")
        cat_table.add_column("Count", style="white", justify="right")
        for cat, count in sorted(by_cat.items(), key=lambda x: -x[1]):
            cat_table.add_row(cat, str(count))
        output_console.print(cat_table)

    output_console.print(
        f"[bold green]Analysis complete.[/bold green] "
        f"{summary.get('total', 0)} finding(s) written to "
        f"[cyan]{resolved_output / 'binary_findings.json'}[/cyan]"
    )


def evaluate_command(
    dataset_path: Path,
    runs: int,
    workspace_dir: Optional[Path],
    output_dir: Optional[Path],
) -> None:
    """
    Evaluate scenarios against an authorized labelled dataset.

    Evaluates scenarios against authorized labelled datasets only; defensive
    evaluation. Produces precision, recall, F1, MTTD, reproducibility
    variance, and false-positive-rate metrics.
    """
    from datetime import timezone

    from purpleforge.evaluation.dataset import load_dataset
    from purpleforge.evaluation.runner import EvaluationRunner
    from purpleforge.evaluation.report import EvaluationReport
    from purpleforge.utils.exceptions import EvaluationError

    try:
        # Resolve workspace
        config = load_config()
        workspace_root = (workspace_dir or config.workspace_dir).resolve()
        workspace_root.mkdir(parents=True, exist_ok=True)

        # Resolve output directory
        if output_dir is None:
            ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            output_dir = Path("evaluation_output") / ts
        output_dir = output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        # Load dataset
        output_console.print(f"[cyan]Loading dataset:[/cyan] {dataset_path}")
        dataset = load_dataset(dataset_path.resolve())
        output_console.print(
            f"[green]Dataset loaded:[/green] {dataset.name} "
            f"({len(dataset.items)} item(s))"
        )

        # Run evaluation
        output_console.print(
            f"[cyan]Running evaluation:[/cyan] {runs} run(s) per item "
            f"({len(dataset.items) * runs} total scenario executions)"
        )
        runner = EvaluationRunner(
            dataset=dataset,
            workspace_dir=workspace_root,
            runs_per_item=runs,
        )
        observations = runner.execute()
        output_console.print(
            f"[green]Collected {len(observations)} observations[/green]"
        )

        # Generate report
        report = EvaluationReport(observations=observations, dataset=dataset)
        metrics = report.compute_all()

        json_path = output_dir / "metrics.json"
        tex_path = output_dir / "metrics.tex"
        md_path = output_dir / "metrics.md"

        report.to_json(json_path)
        report.to_latex_table(tex_path)
        report.to_markdown(md_path)

        output_console.print(
            f"[green]Metrics written to:[/green] {output_dir}"
        )

        # Display headline metrics in a Rich table.
        overall = metrics["overall"]
        mttd = metrics["mttd"]
        repro = metrics["reproducibility"]
        fpr = metrics["false_positive_rate"]

        headline_table = Table(title="PurpleForge Evaluation — Headline Metrics")
        headline_table.add_column("Metric", style="cyan")
        headline_table.add_column("Value", style="bold white", justify="right")

        headline_table.add_row("Precision", f"{overall['precision']:.4f}")
        headline_table.add_row("Recall", f"{overall['recall']:.4f}")
        headline_table.add_row("F1 Score", f"{overall['f1']:.4f}")
        headline_table.add_row("MTTD p50 (s)", f"{mttd['p50']:.2f}")
        headline_table.add_row("MTTD p95 (s)", f"{mttd['p95']:.2f}")
        headline_table.add_row("False Positive Rate", f"{fpr:.4f}")
        headline_table.add_row(
            "Detection Variance (mean)", f"{repro['detection_variance_mean']:.4f}"
        )
        headline_table.add_row(
            "TP / FP / TN / FN",
            f"{overall['confusion_matrix']['tp']} / "
            f"{overall['confusion_matrix']['fp']} / "
            f"{overall['confusion_matrix']['tn']} / "
            f"{overall['confusion_matrix']['fn']}",
        )

        output_console.print(headline_table)

        output_console.print(
            Panel(
                f"[bold cyan]Output Files[/bold cyan]\n\n"
                f"JSON:     [bold]{json_path}[/bold]\n"
                f"LaTeX:    [bold]{tex_path}[/bold]\n"
                f"Markdown: [bold]{md_path}[/bold]",
                title="Evaluation Complete",
                border_style="green",
            )
        )

    except EvaluationError as e:
        error_console.print(f"[bold red]Evaluation error:[/bold red] {e.message}")
        if e.hint:
            error_console.print(f"[yellow]Hint:[/yellow] {e.hint}")
        raise typer.Exit(code=1)
    except PurpleForgeError as e:
        error_console.print(f"[bold red]Error:[/bold red] {e.message}")
        if e.hint:
            error_console.print(f"[yellow]Hint:[/yellow] {e.hint}")
        raise typer.Exit(code=1)
    except Exception as e:
        error_console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        raise typer.Exit(code=1)


def campaign_command(
    campaign_path: Path,
    workspace_dir: Optional[Path],
) -> None:
    """
    Execute a multi-stage campaign against authorized targets.

    Authorized targets only; stages share context for defensive assessment
    only. No exploitation payloads are generated or executed.
    """
    try:
        from purpleforge.campaign.loader import load_campaign
        from purpleforge.campaign.runner import CampaignRunner
        from purpleforge.campaign.killchain import write_diagrams
        from purpleforge.utils.exceptions import CampaignError

        config = load_config()
        ws_dir = workspace_dir.resolve() if workspace_dir else config.workspace_dir

        output_console.print(f"[cyan]Loading campaign:[/cyan] {campaign_path}")
        campaign = load_campaign(campaign_path)
        output_console.print(
            f"[green]Campaign loaded:[/green] {campaign.name} "
            f"({len(campaign.stages)} stages)"
        )

        runner = CampaignRunner(
            campaign=campaign,
            workspace_dir=ws_dir,
            base_dir=campaign_path.parent.resolve(),
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task(f"Running campaign: {campaign.name}", total=None)
            result = runner.execute()
            progress.remove_task(task)

        # Write kill-chain diagrams into the campaign dir.
        write_diagrams(runner.campaign_dir, campaign, result)

        # Print summary table.
        table = Table(title=f"Campaign: {campaign.name}", show_header=True)
        table.add_column("Stage", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Run ID", style="dim")
        table.add_column("Error", style="red")

        for sr in result.stages:
            if sr.status == "success":
                status_str = "[green]success[/green]"
            elif sr.status == "failed":
                status_str = "[red]failed[/red]"
            else:
                status_str = "[dim]skipped[/dim]"
            table.add_row(
                sr.stage_id,
                status_str,
                sr.run_id or "-",
                sr.error or sr.skip_reason or "-",
            )

        output_console.print(table)
        output_console.print(
            Panel(
                f"[bold cyan]Campaign artifacts:[/bold cyan] {runner.campaign_dir}\n"
                f"Kill-chain diagram (Mermaid): {runner.campaign_dir / 'killchain.mmd'}\n"
                f"Kill-chain diagram (DOT):     {runner.campaign_dir / 'killchain.dot'}\n\n"
                f"[bold]Overall status:[/bold] {result.overall_status}\n\n"
                "[dim]Authorized targets only; stages share context; "
                "defensive assessment only.[/dim]",
                title="Campaign Complete",
                border_style="green" if result.overall_status == "success" else "yellow",
            )
        )

        if result.overall_status in ("failed", "aborted"):
            raise typer.Exit(code=1)

    except CampaignError as e:
        error_console.print(f"[bold red]Campaign error:[/bold red] {e.message}")
        if e.hint:
            error_console.print(f"[yellow]Hint:[/yellow] {e.hint}")
        raise typer.Exit(code=1)
    except PurpleForgeError as e:
        error_console.print(f"[bold red]Error:[/bold red] {e.message}")
        if e.hint:
            error_console.print(f"[yellow]Hint:[/yellow] {e.hint}")
        raise typer.Exit(code=1)
    except Exception as e:
        error_console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        raise typer.Exit(code=1)


# ==================== Mirror Commands ====================
# Authorized, verified targets only.  Polite crawl.  Defensive static analysis.
# No exploitation, no form submission, no JS execution, no authenticated crawling.
# Manual review required for all findings.

def mirror_command(
    url: str,
    output: Optional[Path],
    max_depth: int,
    max_pages: int,
    rate_limit: float,
) -> None:
    """
    Mirror a verified target and immediately run static analysis.

    Authorized, verified targets only; polite crawl (robots.txt respected,
    rate-limited, depth-capped, same-origin only); defensive static analysis
    only; no exploitation; manual review required.
    """
    from purpleforge.mirror.crawler import PoliteCrawler
    from purpleforge.mirror.static_analysis import run_static_analysis
    from purpleforge.analysis.findings_schema import summarize
    from datetime import timezone

    try:
        allowlist = load_targets()
        verified_netlocs = list(allowlist.targets.keys())

        if output is None:
            ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            output = Path("mirror_output") / ts
        output = output.resolve()

        output_console.print(
            f"[cyan]Starting polite mirror of:[/cyan] {url}\n"
            "[dim]Authorized, verified targets only; polite crawl; "
            "defensive static analysis; no exploitation.[/dim]"
        )

        crawler = PoliteCrawler(
            base_url=url,
            out_dir=output,
            rate_limit_sec=rate_limit,
            max_depth=max_depth,
            max_pages=max_pages,
            verified_targets=verified_netlocs,
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("Crawling...", total=None)
            manifest = crawler.crawl()
            progress.remove_task(task)

        pages_table = Table(title="Crawl Summary")
        pages_table.add_column("Metric", style="cyan")
        pages_table.add_column("Value", style="white", justify="right")
        pages_table.add_row("Pages crawled", str(len(manifest.pages)))
        pages_table.add_row("User-Agent", manifest.user_agent)
        pages_table.add_row("Output dir", str(output))
        output_console.print(pages_table)

        output_console.print("[cyan]Running static analysis...[/cyan]")
        findings_path = output / "mirror_findings.json"
        findings = run_static_analysis(output, manifest, out_path=findings_path)
        summary = summarize(findings)

        sev_table = Table(title="Static Analysis Findings")
        sev_table.add_column("Severity", style="cyan")
        sev_table.add_column("Count", style="white", justify="right")
        by_sev = summary.get("by_severity", {})
        sev_table.add_row("[red]high[/red]", str(by_sev.get("high", 0)))
        sev_table.add_row("[yellow]medium[/yellow]", str(by_sev.get("medium", 0)))
        sev_table.add_row("[green]low[/green]", str(by_sev.get("low", 0)))
        sev_table.add_row("[bold]TOTAL[/bold]", str(summary.get("total", 0)))
        output_console.print(sev_table)

        output_console.print(
            Panel(
                f"[bold green]Mirror complete[/bold green]\n\n"
                f"Pages:    {len(manifest.pages)}\n"
                f"Findings: {summary.get('total', 0)}\n"
                f"Output:   {output}\n"
                f"Manifest: {output / 'manifest.json'}\n"
                f"Findings: {findings_path}\n\n"
                "[dim]Authorized verified targets only; polite crawl; "
                "defensive static analysis; no exploitation; "
                "manual review required.[/dim]",
                border_style="green",
            )
        )

    except MirrorError as e:
        error_console.print(f"[bold red]Mirror error:[/bold red] {e.message}")
        if e.hint:
            error_console.print(f"[yellow]Hint:[/yellow] {e.hint}")
        raise typer.Exit(code=1)
    except PurpleForgeError as e:
        error_console.print(f"[bold red]Error:[/bold red] {e.message}")
        if e.hint:
            error_console.print(f"[yellow]Hint:[/yellow] {e.hint}")
        raise typer.Exit(code=1)
    except Exception as e:
        error_console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        raise typer.Exit(code=1)


def mirror_scan_command(mirror_dir: Path, output: Optional[Path]) -> None:
    """
    Run static analysis on an existing mirror directory.

    Authorized, verified targets only; defensive static analysis only;
    no exploitation; manual review required.
    """
    import json as _json
    from purpleforge.mirror.crawler import CrawlManifest
    from purpleforge.mirror.static_analysis import run_static_analysis
    from purpleforge.analysis.findings_schema import summarize

    try:
        manifest_path = mirror_dir / "manifest.json"
        if not manifest_path.exists():
            raise MirrorError(
                f"No manifest.json found in {mirror_dir}.",
                hint="Run `purpleforge mirror <url>` to create a mirror first.",
            )

        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest_data = _json.load(fh)
        manifest = CrawlManifest.from_dict(manifest_data)

        findings_path = output.resolve() if output else mirror_dir / "mirror_findings.json"

        output_console.print(
            f"[cyan]Running static analysis on mirror:[/cyan] {mirror_dir}\n"
            "[dim]Defensive static analysis only; no exploitation; "
            "manual review required.[/dim]"
        )

        findings = run_static_analysis(mirror_dir, manifest, out_path=findings_path)
        summary = summarize(findings)

        sev_table = Table(title="Static Analysis Findings")
        sev_table.add_column("Severity", style="cyan")
        sev_table.add_column("Count", style="white", justify="right")
        by_sev = summary.get("by_severity", {})
        sev_table.add_row("[red]high[/red]", str(by_sev.get("high", 0)))
        sev_table.add_row("[yellow]medium[/yellow]", str(by_sev.get("medium", 0)))
        sev_table.add_row("[green]low[/green]", str(by_sev.get("low", 0)))
        sev_table.add_row("[bold]TOTAL[/bold]", str(summary.get("total", 0)))
        output_console.print(sev_table)

        output_console.print(
            f"[bold green]Scan complete.[/bold green] "
            f"{summary.get('total', 0)} finding(s) written to {findings_path}"
        )

    except MirrorError as e:
        error_console.print(f"[bold red]Mirror error:[/bold red] {e.message}")
        if e.hint:
            error_console.print(f"[yellow]Hint:[/yellow] {e.hint}")
        raise typer.Exit(code=1)
    except Exception as e:
        error_console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        raise typer.Exit(code=1)


def mirror_diff_command(
    old_manifest: Path,
    new_manifest: Path,
    output: Optional[Path],
) -> None:
    """
    Diff two mirror manifests and emit informational findings.

    Authorized, verified targets only; defensive static analysis only;
    no exploitation; manual review required.
    """
    from purpleforge.mirror.differential import MirrorDiff
    from purpleforge.analysis.findings_schema import dump_findings

    try:
        output_console.print(
            f"[cyan]Diffing manifests:[/cyan]\n  old: {old_manifest}\n  new: {new_manifest}"
        )

        differ = MirrorDiff()
        diff = differ.diff(old_manifest, new_manifest)
        findings = differ.to_findings(diff)

        out_dir = output.resolve() if output else new_manifest.parent
        out_dir.mkdir(parents=True, exist_ok=True)

        differ.write_diff(out_dir, diff)
        findings_path = out_dir / "mirror_diff_findings.json"
        dump_findings(findings, findings_path)

        diff_table = Table(title="Mirror Diff Summary")
        diff_table.add_column("Change Type", style="cyan")
        diff_table.add_column("Count", style="white", justify="right")
        diff_table.add_row("Pages added", str(len(diff.added_pages)))
        diff_table.add_row("Pages removed", str(len(diff.removed_pages)))
        diff_table.add_row("Pages changed", str(len(diff.changed_pages)))
        diff_table.add_row("Scripts added", str(len(diff.added_scripts)))
        diff_table.add_row("Scripts removed", str(len(diff.removed_scripts)))
        diff_table.add_row("Header changes", str(len(diff.header_changes)))
        diff_table.add_row("[bold]Findings total[/bold]", str(len(findings)))
        output_console.print(diff_table)

        output_console.print(
            f"[bold green]Diff complete.[/bold green] Results in {out_dir}"
        )

    except MirrorError as e:
        error_console.print(f"[bold red]Mirror error:[/bold red] {e.message}")
        if e.hint:
            error_console.print(f"[yellow]Hint:[/yellow] {e.hint}")
        raise typer.Exit(code=1)
    except Exception as e:
        error_console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        raise typer.Exit(code=1)


def audit_verify_command(run_id: str, workspace_dir: Optional[Path]) -> None:
    """
    Verify the tamper-evident audit chain for a run.

    Forensic integrity check: re-walks the hash chain of
    <run_dir>/audit/run_audit.log.jsonl and reports whether all entries
    are intact.

    Exit codes:
        0 -- chain intact
        1 -- log file missing or unreadable (friendly error, no traceback)
        2 -- chain tampered (first bad sequence number reported)
    """
    from purpleforge.audit.hash_chain import verify_log, HashChainLog

    try:
        config = load_config()
        workspace_root = workspace_dir.resolve() if workspace_dir else config.workspace_dir
        workspace_manager = WorkspaceManager(workspace_root)

        try:
            run_dir = workspace_manager.get_run_dir(run_id)
        except Exception:
            error_console.print(
                f"[bold red]Run not found:[/bold red] {run_id}"
            )
            error_console.print(
                "[yellow]Hint:[/yellow] Use 'purpleforge list-runs' to see available run IDs."
            )
            raise typer.Exit(code=1)

        log_path = run_dir / "audit" / "run_audit.log.jsonl"

        if not log_path.exists():
            error_console.print(
                f"[bold red]Audit log not found:[/bold red] {log_path}"
            )
            error_console.print(
                "[yellow]Hint:[/yellow] Audit log is written by WebRunner when "
                "audit_log_enabled=True (default). "
                "Older runs or runs created without audit logging will not have this file."
            )
            raise typer.Exit(code=1)

        # Count entries and gather timestamps.
        chain_length = 0
        first_ts: Optional[str] = None
        last_ts: Optional[str] = None
        try:
            chain_log = HashChainLog(log_path)
            for entry in chain_log.entries():
                chain_length += 1
                ts = entry.get("ts", "")
                if first_ts is None:
                    first_ts = ts
                last_ts = ts
        except Exception as exc:
            error_console.print(
                f"[bold red]Failed to read audit log:[/bold red] {exc}"
            )
            raise typer.Exit(code=1)

        ok, first_bad = verify_log(log_path)

        # Display results.
        table = Table(title=f"Audit Chain - run {run_id}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Chain length", str(chain_length))
        table.add_row("First event", first_ts or "N/A")
        table.add_row("Last event", last_ts or "N/A")
        if ok:
            table.add_row("Status", "[bold green]INTACT[/bold green]")
        else:
            table.add_row(
                "Status",
                f"[bold red]TAMPERED (first bad seq: {first_bad})[/bold red]",
            )

        output_console.print(table)

        if ok:
            output_console.print("[bold green]Chain INTACT[/bold green] -- all entries verified.")
            raise typer.Exit(code=0)
        else:
            error_console.print(
                f"[bold red]Chain TAMPERED[/bold red] -- integrity failure at seq {first_bad}."
            )
            raise typer.Exit(code=2)

    except typer.Exit:
        raise
    except Exception as e:
        error_console.print(f"[bold red]Audit verify error:[/bold red] {e}")
        raise typer.Exit(code=1)
