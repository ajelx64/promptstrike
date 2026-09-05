"""promptstrike CLI entry point.

Subcommand groups (``program``, ``test``, ``finding``, ``report``, ``triage``) are attached by their
own modules as they are built, keeping this file a thin composition root.
"""

from __future__ import annotations

import typer

# The version string and every command group this composition root wires together.
from promptstrike import __version__
from promptstrike.commands.finding import finding_app
from promptstrike.commands.knowledge import knowledge_app
from promptstrike.commands.program import program_app
from promptstrike.commands.report import report_app
from promptstrike.commands.test import test as _test_cmd
from promptstrike.commands.triage import triage as _triage_cmd
from promptstrike.commands.tui import tui as _tui_cmd

# The root Typer app; every subcommand group below attaches to this single object.
app = typer.Typer(
    name="promptstrike",
    help="AI/LLM bug-bounty testing & reporting assistant (authorized security testing only).",
    no_args_is_help=True,
    add_completion=False,
)

# Mount each command-group's own Typer sub-app under its top-level name.
app.add_typer(program_app, name="program")
app.add_typer(finding_app, name="finding")
app.add_typer(report_app, name="report")
app.add_typer(knowledge_app, name="knowledge")
# These three are single functions rather than sub-apps, so they attach as plain commands.
app.command("test")(_test_cmd)
app.command("triage")(_triage_cmd)
app.command("tui")(_tui_cmd)


# Standalone version command, kept here since it has no natural home in commands/.
@app.command()
def version() -> None:
    """Print the promptstrike version."""
    # Echo rather than print so Typer's output handling (encoding, streams) stays consistent.
    typer.echo(f"promptstrike {__version__}")


# Only run the app when this module is executed directly (e.g. `python -m promptstrike.cli`).
if __name__ == "__main__":
    app()
