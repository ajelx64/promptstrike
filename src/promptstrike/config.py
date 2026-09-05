"""Settings for promptstrike.

Safety-critical default: ``dry_run`` is ``True`` unless explicitly overridden, so the tool never
sends live target traffic by accident. Secrets are resolved from an env file *outside* the repo.
"""

from __future__ import annotations

import os
import warnings
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_env_file() -> str | None:
    """Resolve the env file: explicit file -> secrets dir -> home fallback -> None.

    Secrets live OUTSIDE the repo, so the path has to come from somewhere. The three tiers:

    1. ``PROMPTSTRIKE_ENV_FILE`` — an exact file. Returned even when absent, so the operator's
       explicit choice is never silently overridden by a lower tier — but a WARNING is emitted,
       because pydantic-settings ignores a missing dotenv path without complaint. Without that
       warning a typo means the tool runs on defaults with no signal at all, and since
       ``PROMPTSTRIKE_TARGET_API_KEY`` would then be unset, a ``--live`` run would send requests
       with no Authorization header.
    2. ``PROMPTSTRIKE_SECRETS_DIR`` — a directory holding a ``.env``. Configured rather than
       hardcoded on purpose: this is a public repo, so baking in a maintainer-specific absolute
       path would publish one machine's directory layout while meaning nothing to anyone else.
       **Must be absolute.** A relative value resolves against the current working directory, so
       the same command run from two places would read different secrets — a footgun rather than
       a convenience, so it is refused with a warning instead of being resolved.
    3. ``~/.promptstrike/.env`` — the portable default.

    Returns ``None`` when none apply; pydantic-settings then reads env vars only.
    """
    # Tier 1: the operator's explicit file choice, if they made one.
    override = os.environ.get("PROMPTSTRIKE_ENV_FILE")
    # An explicit choice short-circuits the lower tiers even when the file turns out to be missing.
    if override:
        # expanduser so "~/..." works; a missing file is warned about but still honoured.
        if not Path(override).expanduser().exists():
            # pydantic-settings ignores a missing dotenv path silently, so this warning is the
            # only signal the operator gets that a typo left the tool running on bare defaults.
            warnings.warn(
                f"PROMPTSTRIKE_ENV_FILE points at {override!r}, which does not exist. "
                "Settings will fall back to process environment variables only.",
                UserWarning,
                stacklevel=2,
            )
        # Return the operator's raw value, missing or not - never silently fall through to tier 2.
        return override
    # Tier 2: a secrets DIRECTORY expected to contain a ".env".
    secrets_dir = os.environ.get("PROMPTSTRIKE_SECRETS_DIR")
    # Only consulted when tier 1 was unset.
    if secrets_dir:
        # expanduser first so "~/secrets" counts as absolute once the home dir is substituted.
        directory = Path(secrets_dir).expanduser()
        # A relative secrets dir would resolve differently depending on the shell's cwd, so the
        # same command could read different credentials from different places. Refuse it.
        if not directory.is_absolute():
            warnings.warn(
                f"PROMPTSTRIKE_SECRETS_DIR={secrets_dir!r} must be an absolute path; a relative "
                "one resolves against the current directory, so the same command would read "
                "different secrets from different places. Ignoring it.",
                UserWarning,
                stacklevel=2,
            )
        else:
            # The directory is a container, so the env file is always its ".env".
            candidate = directory / ".env"
            # Unlike tier 1 this tier is a convention, not an explicit choice, so a missing file
            # falls through to tier 3 rather than warning.
            if candidate.exists():
                return str(candidate)
    # Tier 3: the portable default location, used when nothing was configured.
    home = Path.home() / ".promptstrike" / ".env"
    # None means "no dotenv" - pydantic-settings then reads process env vars only.
    return str(home) if home.exists() else None


def _default_data_dir() -> Path:
    # Local state (programs, evidence, findings DB, reports) lives under the user's home, NOT in
    # the repo: it can contain target details and working PoCs, and data/ is gitignored for it.
    return Path.home() / ".promptstrike" / "data"


class Settings(BaseSettings):
    """Runtime configuration, populated from PROMPTSTRIKE_* env vars / the resolved env file."""

    # Note the env file is resolved at CLASS DEFINITION time, i.e. once per process on import -
    # changing PROMPTSTRIKE_ENV_FILE later in the same process has no effect.
    model_config = SettingsConfigDict(
        # Each field below is read from PROMPTSTRIKE_<FIELD>: dry_run is PROMPTSTRIKE_DRY_RUN.
        env_prefix="PROMPTSTRIKE_",
        env_file=_default_env_file(),
        env_file_encoding="utf-8",
        # Unknown PROMPTSTRIKE_* vars (e.g. TARGET_API_KEY, read directly by the transport) are
        # ignored rather than rejected, so an env file may hold more than this model declares.
        extra="ignore",
    )

    # Safety invariant: default True. Live traffic requires an explicit override AND --live at the CLI.
    dry_run: bool = True
    # No-DoS guard: requests/sec cap applied to all target traffic.
    rate_limit_rps: float = 1.0
    # Root of all local state, overridable via PROMPTSTRIKE_DATA_DIR. default_factory (rather than
    # a plain default) so Path.home() is read per instance instead of being frozen at import time.
    data_dir: Path = Field(default_factory=_default_data_dir)

    def ensure_dirs(self) -> Path:
        """Create the data dir and its programs/evidence/reports subdirs if missing.

        Callers run this once at startup so every store can assume its directory already
        exists rather than each re-implementing the same ``mkdir(parents=True, exist_ok=True)``.
        """
        # The data root plus every subdirectory a store writes into.
        for directory in (self.data_dir, self.programs_dir, self.evidence_dir, self.reports_dir):
            # exist_ok makes this idempotent, so calling it on every startup is safe.
            directory.mkdir(parents=True, exist_ok=True)
        # Hand back the root for callers that want to show the operator where state lives.
        return self.data_dir

    @property
    def db_path(self) -> Path:
        """Path to the findings SQLite database, under the data dir."""
        # Derived, not stored, so a data_dir override moves the DB with it automatically.
        return self.data_dir / "promptstrike.db"

    @property
    def programs_dir(self) -> Path:
        """Path to the registered-program YAML directory, under the data dir."""
        # ProgramStore reads authorization records from here; this is the scope registry's home.
        return self.data_dir / "programs"

    @property
    def evidence_dir(self) -> Path:
        """Path to the per-run JSON evidence directory, under the data dir."""
        # Holds captured request/response transcripts - target details and working PoCs, which is
        # why this lives outside the repo and is never committed.
        return self.data_dir / "evidence"

    @property
    def reports_dir(self) -> Path:
        """Path to the generated-report output directory, under the data dir."""
        # Where drafted Markdown/HTML/PDF reports land for the operator to submit BY HAND.
        return self.data_dir / "reports"


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide cached ``Settings`` instance, resolving env vars once."""
    # lru_cache makes this a singleton: every caller sees the same dry_run/rate-limit values, so
    # the safety switches cannot differ between two parts of the same run.
    return Settings()
