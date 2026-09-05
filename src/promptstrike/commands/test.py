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
    settings = get_settings()
    settings.ensure_dirs()

    # Fast-fail before any setup work so the operator gets one clear line instead of a traceback
    # from deeper in the run. This is a convenience: the authoritative gate is in
    # TargetClient.send, which every prompt passes through no matter which caller reached it.
    if live and settings.dry_run:
        typer.secho(
            "REFUSING --live: PROMPTSTRIKE_DRY_RUN is true (the safety default). "
            "Set PROMPTSTRIKE_DRY_RUN=false in the environment or your env file to permit "
            "live traffic.",
            fg="red",
            bold=True,
        )
        raise typer.Exit(code=2)

    prog = ProgramStore(settings.programs_dir).get(program)
    if prog is None:
        typer.secho(f"unknown program '{program}'", fg="red")
        raise typer.Exit(code=1)

    probes = load_pack(builtin_pack_dir())
    selected = probes if probe == "all" else [p for p in probes if p.id == probe]
    if not selected:
        available = ", ".join(p.id for p in probes)
        typer.secho(f"unknown probe '{probe}'. Available: {available}", fg="red")
        raise typer.Exit(code=1)

    targets = [target] if target else [a.value for a in prog.in_scope if a.type == AssetType.endpoint]
    if not targets:
        typer.secho(
            "no endpoint target: pass --target or add an endpoint asset to the program", fg="red"
        )
        raise typer.Exit(code=1)

    rps = prog.rate_limit_rps or settings.rate_limit_rps
    client = TargetClient(
        prog,
        rate_limiter=RateLimiter(rps),
        auth_log=AuthLog(settings.data_dir / "authlog.jsonl"),
        # The global switch reaches the chokepoint here; dry_run=True means never send.
        allow_live=not settings.dry_run,
    )
    runs = RunStore(settings.evidence_dir)

    if live:
        typer.secho(
            "LIVE MODE: sending real, rate-limited requests to in-scope targets.", fg="red", bold=True
        )
    else:
        typer.secho("DRY RUN: rendering probes only, nothing is sent. Use --live to fire.", fg="yellow")

    saved: list[str] = []
    triggered_count = 0

    async def _run_all() -> None:
        nonlocal triggered_count
        for tgt in targets:
            for pr in selected:
                try:
                    result = await run_probe(client, pr, tgt, live=live)
                except ScopeError as exc:
                    typer.secho(f"  SKIP {pr.id} @ {tgt}: {exc}", fg="red")
                    continue
                runs.save(result)
                saved.append(result.run_id)
                if result.triggered:
                    triggered_count += 1
                    typer.secho(
                        f"  [TRIGGERED] {pr.id} @ {tgt}  run={result.run_id} :: {result.detail}",
                        fg="red",
                    )
                elif not live:
                    typer.secho(f"  [dry] {pr.id} @ {tgt}  run={result.run_id}", fg="yellow")
                else:
                    typer.secho(f"  [clean] {pr.id} @ {tgt}  run={result.run_id}", fg="green")

    asyncio.run(_run_all())
    typer.echo(f"\n{len(saved)} run(s) saved to {settings.evidence_dir}; {triggered_count} triggered.")
    if triggered_count and live:
        typer.echo("Next: review evidence, then `promptstrike finding promote <run-id>`.")
