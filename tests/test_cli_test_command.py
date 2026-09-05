"""CLI-level tests for the ``promptstrike test`` command.

The command layer had no coverage, which is how a documented safety switch could sit unread in
it. These drive the real Typer app rather than the library underneath.
"""

from __future__ import annotations

from typer.testing import CliRunner

from promptstrike.cli import app
from promptstrike.config import get_settings

# ---------------------------------------------------------------------------------------------
# CLI-level guard. commands/ had no test coverage at all, which is precisely why a dead safety
# switch could sit in this command undetected - no test ever invoked it.
# ---------------------------------------------------------------------------------------------


def test_cli_refuses_live_while_global_dry_run_is_active(tmp_path, monkeypatch) -> None:
    """`test --live` must exit 2 with an explanatory message while the switch is on."""
    # Point all state at a temp dir so the operator's real data is untouched.
    monkeypatch.setenv("PROMPTSTRIKE_DATA_DIR", str(tmp_path / "data"))
    # Turn the global switch on explicitly, which is also the default.
    monkeypatch.setenv("PROMPTSTRIKE_DRY_RUN", "true")
    # Settings are process-cached; clear it or the test asserts against a stale object.
    get_settings.cache_clear()
    # Invoke the real CLI the way an operator would.
    result = CliRunner().invoke(app, ["test", "--program", "whatever", "--live"])
    # Exit code 2 distinguishes "refused by policy" from a generic error (1).
    assert result.exit_code == 2
    # The message must name the variable to change.
    assert "PROMPTSTRIKE_DRY_RUN" in result.output
    # It must refuse BEFORE resolving the program, or the message would be "unknown program"
    # and the operator would fix the wrong thing.
    assert "unknown program" not in result.output


def test_cli_reports_unknown_program_when_not_asking_for_live(tmp_path, monkeypatch) -> None:
    """Positive control: the guard must not swallow ordinary errors on the dry-run path."""
    # Isolated state again.
    monkeypatch.setenv("PROMPTSTRIKE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PROMPTSTRIKE_DRY_RUN", "true")
    get_settings.cache_clear()
    # No --live, so the guard must not fire and the normal error path should run.
    result = CliRunner().invoke(app, ["test", "--program", "nosuchprogram"])
    # Exit 1 is the ordinary failure, distinct from the policy refusal above.
    assert result.exit_code == 1
    assert "unknown program" in result.output
