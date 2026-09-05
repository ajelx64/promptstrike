"""``promptstrike tui`` — launch the triage & report workbench.

Textual is an OPTIONAL extra. The import is deferred and its absence produces an actionable message
rather than breaking the CLI, mirroring how ``report.generator`` treats WeasyPrint: a missing
presentation-layer dependency must never take the core tool down.
"""

from __future__ import annotations

from pathlib import Path

import typer


def tui(
    db: Path | None = typer.Option(
        None, "--db", help="Findings database to open (defaults to the configured data dir)"
    ),
) -> None:
    """Open the interactive triage & report workbench."""
    try:
        from promptstrike.tui.app import run
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised by the guard test
        if exc.name and exc.name.split(".")[0] == "textual":
            typer.echo(
                "The TUI needs the optional 'textual' dependency.\n"
                "  pip install 'promptstrike[tui]'   (or: pip install textual)\n"
                "Every workbench action is also available on the CLI.",
                err=True,
            )
            raise typer.Exit(code=3) from None
        raise
    run(db_path=db)
