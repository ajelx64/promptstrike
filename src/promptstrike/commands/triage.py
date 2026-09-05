"""``promptstrike triage`` — dedup a finding vs local history + lint against a platform checklist."""

from __future__ import annotations

import typer

from promptstrike.config import get_settings
from promptstrike.report.profiles import get_profile
from promptstrike.storage import FindingStore
from promptstrike.triage import dedupe, lint


def triage(
    finding_id: int = typer.Option(..., "--finding", help="Finding id"),
    platform: str | None = typer.Option(None, "--platform", help="Profile key (defaults to finding's)"),
) -> None:
    """Check a finding for local duplicates and platform-submission gaps before you submit."""
    settings = get_settings()
    settings.ensure_dirs()
    with FindingStore(settings.db_path) as store:
        finding = store.get(finding_id)
        if finding is None:
            typer.secho(f"unknown finding #{finding_id}", fg="red")
            raise typer.Exit(code=1)
        others = store.list()

    result = dedupe(finding, others)
    if result.duplicates:
        typer.secho(
            f"  DUPLICATE of finding(s) {result.duplicates} — same category + target.", fg="red"
        )
    if result.variants:
        typer.secho(
            f"  Possible variant of finding(s) {result.variants} — same category, same host.",
            fg="yellow",
        )
    if not result.duplicates and not result.variants:
        typer.secho("  No local duplicates found.", fg="green")

    profile = get_profile(platform or finding.platform.value)
    gaps = lint(finding, profile)
    if gaps:
        typer.secho(f"  {profile.display_name} checklist gaps:", fg="yellow")
        for g in gaps:
            typer.secho(f"   - {g}", fg="yellow")
    else:
        typer.secho(f"  {profile.display_name} checklist: complete.", fg="green")
