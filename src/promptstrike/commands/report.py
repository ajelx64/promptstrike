"""``promptstrike report`` — generate platform-native reports from findings (draft -> final)."""

from __future__ import annotations

from pathlib import Path

import typer

from promptstrike.config import get_settings
from promptstrike.llm.draft import apply_narrative, claude_drafter
from promptstrike.models import Finding, FindingStatus
from promptstrike.report.generator import ReportGenerator
from promptstrike.report.profiles import Profile, get_profile
from promptstrike.storage import FindingStore

report_app = typer.Typer(help="Generate platform-native reports from findings.", no_args_is_help=True)


def _emit(finding: Finding, profile: Profile, fmt: str, out_dir: Path) -> Path:
    gen = ReportGenerator()
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"finding-{finding.id}-{profile.key}"
    if fmt == "md":
        path = out_dir / f"{stem}.md"
        path.write_text(gen.render_markdown(finding, profile), encoding="utf-8")
    elif fmt == "html":
        path = out_dir / f"{stem}.html"
        path.write_text(gen.render_html(finding, profile), encoding="utf-8")
    elif fmt == "pdf":
        pdf = gen.render_pdf(finding, profile)
        if pdf is None:  # soft-fail to HTML
            path = out_dir / f"{stem}.html"
            path.write_text(gen.render_html(finding, profile), encoding="utf-8")
            typer.secho("  WeasyPrint unavailable — wrote HTML instead of PDF.", fg="yellow")
        else:
            path = out_dir / f"{stem}.pdf"
            path.write_bytes(pdf)
    else:
        raise typer.BadParameter("format must be one of: md, html, pdf")
    return path


def _draft_with_ai(finding: Finding, store: FindingStore) -> None:
    """Draft narrative fields with Claude, then ask before persisting them.

    The drafted text is derived from target output, which is attacker-influenced, so writing it
    straight to the findings database would let a hostile target edit the operator's own record.
    The TUI already takes this stance - it suggests remediation and never writes it - and this
    path now matches. The draft is always applied IN MEMORY so the rendered report shows it;
    only the durable write is gated.
    """
    try:
        # Ask the model for narrative fields, then apply them to the in-memory finding.
        apply_narrative(finding, claude_drafter(finding))
    except Exception as exc:  # anthropic missing, no key, API error — never fatal
        typer.secho(f"  AI drafting skipped: {exc}", fg="yellow")
        return

    # Show what was generated, so the decision below is informed rather than blind.
    typer.secho("  AI-drafted summary / impact / remediation:", fg="cyan")
    for field_name in ("summary", "impact", "remediation"):
        # Read the drafted value off the finding.
        value = getattr(finding, field_name, "") or ""
        # Keep the preview short; the full text is in the rendered report.
        preview = " ".join(value.split())[:200]
        typer.echo(f"    {field_name}: {preview}{'...' if len(value) > 200 else ''}")

    # Persist only on an explicit yes. A non-interactive run (no TTY) takes the default of NO,
    # which fails closed: the report still contains the draft, the stored finding is untouched.
    if typer.confirm("  Persist this AI-drafted narrative to the stored finding?", default=False):
        store.update(finding)
        typer.secho("  Saved to the finding.", fg="green")
    else:
        typer.secho(
            "  Not saved. The rendered report includes the draft; the stored finding is unchanged.",
            fg="yellow",
        )


@report_app.command("draft")
def draft(
    finding_id: int = typer.Option(..., "--finding", help="Finding id"),
    platform: str | None = typer.Option(None, "--platform", help="Profile key (defaults to finding's)"),
    fmt: str = typer.Option("md", "--format", help="md | html | pdf"),
    ai: bool = typer.Option(False, "--ai/--no-ai", help="AI-draft narrative via Claude"),
) -> None:
    """Generate a draft report for a finding."""
    settings = get_settings()
    settings.ensure_dirs()
    store = FindingStore(settings.db_path)
    try:
        finding = store.get(finding_id)
        if finding is None:
            typer.secho(f"unknown finding #{finding_id}", fg="red")
            raise typer.Exit(code=1)
        profile = get_profile(platform or finding.platform.value)
        if ai:
            _draft_with_ai(finding, store)
        path = _emit(finding, profile, fmt, settings.reports_dir)
    finally:
        store.close()
    typer.secho(f"draft written: {path}", fg="green")


@report_app.command("final")
def final(
    finding_id: int = typer.Option(..., "--finding", help="Finding id"),
    platform: str | None = typer.Option(None, "--platform"),
    fmt: str = typer.Option("md", "--format", help="md | html | pdf"),
    ai: bool = typer.Option(False, "--ai/--no-ai"),
) -> None:
    """Generate a final report; warns on incomplete fields and marks the finding ready when clean."""
    settings = get_settings()
    settings.ensure_dirs()
    store = FindingStore(settings.db_path)
    try:
        finding = store.get(finding_id)
        if finding is None:
            typer.secho(f"unknown finding #{finding_id}", fg="red")
            raise typer.Exit(code=1)
        profile = get_profile(platform or finding.platform.value)
        if ai:
            _draft_with_ai(finding, store)
        missing = profile.missing(finding)
        if missing:
            typer.secho(f"  Incomplete for a {profile.display_name} final report:", fg="yellow")
            for m in missing:
                typer.secho(f"   - {m}", fg="yellow")
        else:
            finding.status = FindingStatus.ready
            store.update(finding)
            typer.secho("  All submission-checklist items satisfied; marked ready.", fg="green")
        path = _emit(finding, profile, fmt, settings.reports_dir)
    finally:
        store.close()
    typer.secho(f"final written: {path}", fg="green")
