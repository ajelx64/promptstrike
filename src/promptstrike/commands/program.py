"""``promptstrike program`` — manage authorized programs and their scope."""

from __future__ import annotations

from pathlib import Path

import typer
import yaml

from promptstrike.config import get_settings
from promptstrike.models import AssetType, Platform, Program, ScopeAsset
from promptstrike.scope import ProgramStore, check

program_app = typer.Typer(
    help="Manage authorized programs and their scope.", no_args_is_help=True
)


def _store() -> ProgramStore:
    settings = get_settings()
    settings.ensure_dirs()
    return ProgramStore(settings.programs_dir)


@program_app.command("add")
def add(
    file: Path | None = typer.Option(None, "--file", "-f", help="YAML program definition to import"),
    name: str | None = typer.Option(None, "--name", help="Program slug (when not using --file)"),
    platform: Platform = typer.Option(Platform.other, "--platform"),
    in_scope: list[str] = typer.Option(None, "--in-scope", help="In-scope endpoint (repeatable)"),
    allows_ai_testing: bool = typer.Option(
        False, "--allows-ai-testing/--no-ai-testing", help="You confirm this program permits AI testing"
    ),
    overwrite: bool = typer.Option(False, "--overwrite"),
) -> None:
    """Register a program from a YAML file, or a minimal one from flags."""
    store = _store()
    if file:
        program = ProgramStore.load_yaml(file)
    elif name:
        program = Program(
            name=name,
            platform=platform,
            allows_ai_testing=allows_ai_testing,
            in_scope=[ScopeAsset(value=v, type=AssetType.endpoint) for v in (in_scope or [])],
        )
    else:
        raise typer.BadParameter("provide --file or --name")

    path = store.add(program, overwrite=overwrite)
    typer.echo(f"added program '{program.name}' -> {path}")
    if not program.allows_ai_testing:
        typer.secho(
            "  note: allows_ai_testing is FALSE — probes stay blocked until you authorize it.",
            fg="yellow",
        )


@program_app.command("list")
def list_() -> None:
    """List registered programs."""
    programs = _store().list()
    if not programs:
        typer.echo("(no programs registered)")
        return
    for p in programs:
        flag = "AI-OK" if p.allows_ai_testing else "no-AI"
        typer.echo(f"{p.name:20} {p.platform.value:15} {flag:6} in_scope={len(p.in_scope)}")


@program_app.command("show")
def show(name: str) -> None:
    """Print a program's full definition."""
    p = _store().get(name)
    if not p:
        typer.secho(f"unknown program '{name}'", fg="red")
        raise typer.Exit(code=1)
    typer.echo(yaml.safe_dump(p.model_dump(mode="json"), sort_keys=False))


@program_app.command("scope-check")
def scope_check(
    target: str,
    program: str = typer.Option(..., "--program", "-p", help="Program name to check against"),
) -> None:
    """Check whether TARGET is in scope for a program (exit 0 allow, 2 deny)."""
    p = _store().get(program)
    if not p:
        typer.secho(f"unknown program '{program}'", fg="red")
        raise typer.Exit(code=1)
    decision = check(p, target)
    verdict = "ALLOW" if decision.allowed else "DENY"
    typer.secho(f"{verdict}: {decision.reason}", fg="green" if decision.allowed else "red")
    raise typer.Exit(code=0 if decision.allowed else 2)
