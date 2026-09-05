"""``promptstrike finding`` — promote probe runs into findings and manage them."""

from __future__ import annotations

import typer
import yaml

from promptstrike.config import get_settings
from promptstrike.cvss import Severity
from promptstrike.finding import promote as promote_finding
from promptstrike.models import Platform
from promptstrike.scope import ProgramStore
from promptstrike.storage import FindingStore, RunStore

# Sub-app for every `promptstrike finding <verb>` command below.
finding_app = typer.Typer(help="Promote probe runs into findings and manage them.", no_args_is_help=True)


@finding_app.command("promote")
def promote(
    run_id: str,
    title: str | None = typer.Option(None, "--title"),
    cvss: str = typer.Option("", "--cvss", help="CVSS v3.1 vector; sets score + severity"),
    platform: Platform | None = typer.Option(None, "--platform"),
    severity: Severity | None = typer.Option(None, "--severity", help="Manual severity if no CVSS"),
) -> None:
    """Promote a saved probe run into a draft finding."""
    # Load configuration and make sure the data directories exist.
    settings = get_settings()
    settings.ensure_dirs()
    # Fetch the saved evidence for the run being promoted.
    run = RunStore(settings.evidence_dir).get(run_id)
    if run is None:
        typer.secho(f"unknown run '{run_id}'", fg="red")
        raise typer.Exit(code=1)
    # The run's originating program, so the finding can inherit its platform/context.
    program = ProgramStore(settings.programs_dir).get(run.program)
    # Build the draft finding from the run's evidence plus the operator-supplied overrides.
    finding = promote_finding(
        run,
        program=program,
        title=title,
        cvss_v31_vector=cvss or "",
        platform=platform,
        severity=severity,
    )
    # Persist the new finding and capture its assigned id.
    with FindingStore(settings.db_path) as store:
        fid = store.add(finding)
    typer.secho(f"created finding #{fid}: [{finding.severity.value}] {finding.title}", fg="green")


@finding_app.command("list")
def list_() -> None:
    """List findings."""
    settings = get_settings()
    settings.ensure_dirs()
    # Every finding currently stored in the findings database.
    with FindingStore(settings.db_path) as store:
        findings = store.list()
    if not findings:
        typer.echo("(no findings yet)")
        return
    for finding in findings:
        # One aligned summary row per finding: id, severity, category, program, status, title.
        typer.echo(
            f"#{finding.id:<3} [{finding.severity.value:8}] {finding.category.value:6} "
            f"{finding.program:14} {finding.status.value:9} {finding.title}"
        )


@finding_app.command("show")
def show(finding_id: int) -> None:
    """Print a finding's full detail."""
    settings = get_settings()
    settings.ensure_dirs()
    # Look up the finding by its numeric id.
    with FindingStore(settings.db_path) as store:
        finding = store.get(finding_id)
    if finding is None:
        typer.secho(f"unknown finding #{finding_id}", fg="red")
        raise typer.Exit(code=1)
    # Dump the whole record as YAML, in declaration order, for a human to read or diff.
    typer.echo(yaml.safe_dump(finding.model_dump(mode="json"), sort_keys=False))
