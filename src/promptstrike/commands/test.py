"""``promptstrike test`` — run LLM probes against an authorized program's target(s).

Dry run by default (renders + records, sends nothing). ``--live`` fires real, rate-limited requests
at in-scope targets only; out-of-scope targets are skipped by the scope spine.
"""

from __future__ import annotations

import asyncio

import typer

from promptstrike.config import get_settings
from promptstrike.llm.target import AuthLog, RateLimiter, TargetClient
from promptstrike.models import AssetType
from promptstrike.probes.engine import builtin_pack_dir, load_pack, run_probe
from promptstrike.scope import ProgramStore, ScopeError
from promptstrike.storage import RunStore


# The four CLI-facing flags: which authorized program, which probe(s), an optional target
# override, and whether to actually fire live traffic (dry run is the safety default).
def test(
    program: str = typer.Option(..., "--program", "-p", help="Authorized program name"),
    probe: str = typer.Option("all", "--probe", help="Probe id, or 'all'"),
    target: str | None = typer.Option(
        None, "--target", "-t", help="Override target endpoint (still scope-checked)"
    ),
    live: bool = typer.Option(
        False, "--live/--dry-run", help="Actually send to the target (default: dry run)"
    ),
) -> None:
    """Run probes; dry run by default. Evidence is saved for promotion into a finding."""
    # Load configuration (paths, dry-run flag, rate limit) from the environment / .env file.
    settings = get_settings()
    # Create the programs/evidence/data directories if this is a fresh install.
    settings.ensure_dirs()

    # Fast-fail before any setup work so the operator gets one clear line instead of a traceback
    # from deeper in the run. This is a convenience: the authoritative gate is in
    # TargetClient.send, which every prompt passes through no matter which caller reached it.
    if live and settings.dry_run:
        # Print the refusal in bold red so it reads as a hard stop, not a warning to scroll past.
        typer.secho(
            "REFUSING --live: PROMPTSTRIKE_DRY_RUN is true (the safety default). "
            "Set PROMPTSTRIKE_DRY_RUN=false in the environment or your env file to permit "
            "live traffic.",
            fg="red",
            bold=True,
        )
        # Exit code 2 (distinct from the "unknown X" 1s below) marks a refused-by-policy exit.
        raise typer.Exit(code=2)

    # Look up the authorized program record (scope, rate limit, AI-testing consent) by name.
    program_record = ProgramStore(settings.programs_dir).get(program)
    if program_record is None:
        typer.secho(f"unknown program '{program}'", fg="red")
        raise typer.Exit(code=1)

    # Load the built-in probe pack shipped with the tool.
    probes = load_pack(builtin_pack_dir())
    # Either run every probe, or narrow to the single probe id the operator asked for.
    selected = probes if probe == "all" else [
        candidate for candidate in probes if candidate.id == probe
    ]
    if not selected:
        # List the valid ids so a typo'd --probe value is self-correcting.
        available = ", ".join(candidate.id for candidate in probes)
        typer.secho(f"unknown probe '{probe}'. Available: {available}", fg="red")
        raise typer.Exit(code=1)

    # An explicit --target overrides scope discovery; otherwise use every registered endpoint.
    in_scope_endpoints = [
        asset.value for asset in program_record.in_scope if asset.type == AssetType.endpoint
    ]
    targets = [target] if target else in_scope_endpoints
    if not targets:
        typer.secho(
            "no endpoint target: pass --target or add an endpoint asset to the program", fg="red"
        )
        raise typer.Exit(code=1)

    # Per-program rate limit wins if set; otherwise fall back to the global default.
    rate_limit_rps = program_record.rate_limit_rps or settings.rate_limit_rps
    # Build the one client every probe in this run shares, so the rate limiter and auth log
    # (and the dry-run gate below) apply uniformly regardless of which probe or target is next.
    client = TargetClient(
        program_record,
        rate_limiter=RateLimiter(rate_limit_rps),
        auth_log=AuthLog(settings.data_dir / "authlog.jsonl"),
        # The global switch reaches the chokepoint here; dry_run=True means never send.
        allow_live=not settings.dry_run,
    )
    # Where each probe's result gets persisted for later promotion into a finding.
    runs = RunStore(settings.evidence_dir)

    if live:
        # Loud banner: the operator is about to send real traffic.
        typer.secho(
            "LIVE MODE: sending real, rate-limited requests to in-scope targets.", fg="red", bold=True
        )
    else:
        # Quiet banner: nothing leaves the process this run.
        typer.secho("DRY RUN: rendering probes only, nothing is sent. Use --live to fire.", fg="yellow")

    # Run ids saved this session, for the closing summary line.
    saved: list[str] = []
    # How many probes actually triggered (found something), also for the summary.
    triggered_count = 0

    # Runs every selected probe against every target; defined as a nested coroutine so the whole
    # sweep can be driven by a single asyncio.run() call below.
    async def _run_all() -> None:
        nonlocal triggered_count
        # Outer loop: every in-scope (or overridden) target endpoint.
        for tgt in targets:
            # Inner loop: every probe selected above, against the current target.
            for pr in selected:
                try:
                    # Send (or render, if dry-run) the probe and await its result.
                    result = await run_probe(client, pr, tgt, live=live)
                except ScopeError as exc:
                    # The scope spine rejected this target; skip it rather than aborting the run.
                    typer.secho(f"  SKIP {pr.id} @ {tgt}: {exc}", fg="red")
                    continue
                # Persist the evidence regardless of outcome, so nothing observed is lost.
                runs.save(result)
                saved.append(result.run_id)
                if result.triggered:
                    # A hit: count it and print in red so it stands out in scrolling output.
                    triggered_count += 1
                    typer.secho(
                        f"  [TRIGGERED] {pr.id} @ {tgt}  run={result.run_id} :: {result.detail}",
                        fg="red",
                    )
                elif not live:
                    # No hit, and this was only a dry-run render — not a real negative result.
                    typer.secho(f"  [dry] {pr.id} @ {tgt}  run={result.run_id}", fg="yellow")
                else:
                    # No hit on a live send: a genuine clean result for this probe/target pair.
                    typer.secho(f"  [clean] {pr.id} @ {tgt}  run={result.run_id}", fg="green")

    # Drive the whole async sweep from this synchronous Typer command.
    asyncio.run(_run_all())
    # Final tally: how much evidence was saved and how many probes triggered.
    typer.echo(f"\n{len(saved)} run(s) saved to {settings.evidence_dir}; {triggered_count} triggered.")
    if triggered_count and live:
        # Point the operator at the next real step rather than leaving them to guess it.
        typer.echo("Next: review evidence, then `promptstrike finding promote <run-id>`.")
