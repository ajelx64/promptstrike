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
        # Load the finding under review.
        finding = store.get(finding_id)
        if finding is None:
            typer.secho(f"unknown finding #{finding_id}", fg="red")
            raise typer.Exit(code=1)
        # Every other stored finding, to check the current one against for duplicates/variants.
        others = store.list()

    # Compare this finding's category/target/host against every other stored finding.
    result = dedupe(finding, others)
    if result.duplicates:
        # Exact duplicate: same category and same target — almost certainly the same bug.
        typer.secho(
            f"  DUPLICATE of finding(s) {result.duplicates} — same category + target.", fg="red"
        )
    if result.variants:
        # Weaker match: same category and host, but a different target — worth a manual look.
        typer.secho(
            f"  Possible variant of finding(s) {result.variants} — same category, same host.",
            fg="yellow",
        )
    if not result.duplicates and not result.variants:
        typer.secho("  No local duplicates found.", fg="green")

    # Resolve the platform-specific submission checklist (defaults to the finding's own platform).
    profile = get_profile(platform or finding.platform.value)
    # Which checklist items this finding is still missing for that platform.
    gaps = lint(finding, profile)
    if gaps:
        typer.secho(f"  {profile.display_name} checklist gaps:", fg="yellow")
        for gap in gaps:
            typer.secho(f"   - {gap}", fg="yellow")
    else:
        typer.secho(f"  {profile.display_name} checklist: complete.", fg="green")
