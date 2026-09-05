"""``promptstrike program`` — manage authorized programs and their scope."""

from __future__ import annotations

from pathlib import Path

import typer
import yaml

from promptstrike.config import get_settings
from promptstrike.models import AssetType, Platform, Program, ScopeAsset
from promptstrike.scope import ProgramStore, check

# Sub-app for every `promptstrike program <verb>` command below.
program_app = typer.Typer(
    help="Manage authorized programs and their scope.", no_args_is_help=True
)


def _store() -> ProgramStore:
    # Load settings so the store knows where program YAML files live on disk.
    settings = get_settings()
    # Make sure the programs directory exists before anything tries to read/write into it.
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
        # A full YAML definition takes precedence over the individual flags.
        program = ProgramStore.load_yaml(file)
    elif name:
        # Build a minimal Program record straight from the CLI flags.
        program = Program(
            name=name,
            platform=platform,
            allows_ai_testing=allows_ai_testing,
            in_scope=[
                ScopeAsset(value=asset_value, type=AssetType.endpoint)
                for asset_value in (in_scope or [])
            ],
        )
    else:
        # Neither a file nor a name was given — there is nothing to register.
        raise typer.BadParameter("provide --file or --name")

    # Write the program definition to disk, refusing to clobber an existing one unless asked.
    path = store.add(program, overwrite=overwrite)
    typer.echo(f"added program '{program.name}' -> {path}")
    if not program.allows_ai_testing:
        # Warn loudly: this is the hard gate that keeps probes from firing without consent.
        typer.secho(
            "  note: allows_ai_testing is FALSE — probes stay blocked until you authorize it.",
            fg="yellow",
        )


@program_app.command("list")
def list_() -> None:
    """List registered programs."""
    # Every program currently registered on disk.
    programs = _store().list()
    if not programs:
        typer.echo("(no programs registered)")
        return
    for program in programs:
        # AI-OK/no-AI mirrors the allows_ai_testing gate so it is visible at a glance.
        flag = "AI-OK" if program.allows_ai_testing else "no-AI"
        typer.echo(
            f"{program.name:20} {program.platform.value:15} {flag:6} in_scope={len(program.in_scope)}"
        )


@program_app.command("show")
def show(name: str) -> None:
    """Print a program's full definition."""
    # Look up the program record by its slug.
    program = _store().get(name)
    if not program:
        typer.secho(f"unknown program '{name}'", fg="red")
        raise typer.Exit(code=1)
    # Dump the whole record as YAML, in declaration order, for a human to read or diff.
    typer.echo(yaml.safe_dump(program.model_dump(mode="json"), sort_keys=False))


@program_app.command("scope-check")
def scope_check(
    target: str,
    program: str = typer.Option(..., "--program", "-p", help="Program name to check against"),
) -> None:
    """Check whether TARGET is in scope for a program (exit 0 allow, 2 deny)."""
    # Resolve the named program before asking whether TARGET is in its scope.
    program_record = _store().get(program)
    if not program_record:
        typer.secho(f"unknown program '{program}'", fg="red")
        raise typer.Exit(code=1)
    # Run the actual scope decision through the shared scope spine.
    decision = check(program_record, target)
    verdict = "ALLOW" if decision.allowed else "DENY"
    typer.secho(f"{verdict}: {decision.reason}", fg="green" if decision.allowed else "red")
    # Exit code doubles as a scriptable allow/deny signal (0 = allow, 2 = deny).
    raise typer.Exit(code=0 if decision.allowed else 2)
