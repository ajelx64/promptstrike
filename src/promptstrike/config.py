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
    override = os.environ.get("PROMPTSTRIKE_ENV_FILE")
    if override:
        if not Path(override).expanduser().exists():
            warnings.warn(
                f"PROMPTSTRIKE_ENV_FILE points at {override!r}, which does not exist. "
                "Settings will fall back to process environment variables only.",
                UserWarning,
                stacklevel=2,
            )
        return override
    secrets_dir = os.environ.get("PROMPTSTRIKE_SECRETS_DIR")
    if secrets_dir:
        directory = Path(secrets_dir).expanduser()
        if not directory.is_absolute():
            warnings.warn(
                f"PROMPTSTRIKE_SECRETS_DIR={secrets_dir!r} must be an absolute path; a relative "
                "one resolves against the current directory, so the same command would read "
                "different secrets from different places. Ignoring it.",
                UserWarning,
                stacklevel=2,
            )
        else:
            candidate = directory / ".env"
            if candidate.exists():
                return str(candidate)
    home = Path.home() / ".promptstrike" / ".env"
    return str(home) if home.exists() else None


def _default_data_dir() -> Path:
    return Path.home() / ".promptstrike" / "data"


class Settings(BaseSettings):
    """Runtime configuration, populated from PROMPTSTRIKE_* env vars / the resolved env file."""

    model_config = SettingsConfigDict(
        env_prefix="PROMPTSTRIKE_",
        env_file=_default_env_file(),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Safety invariant: default True. Live traffic requires an explicit override AND --live at the CLI.
    dry_run: bool = True
    # No-DoS guard: requests/sec cap applied to all target traffic.
    rate_limit_rps: float = 1.0
    data_dir: Path = Field(default_factory=_default_data_dir)

    def ensure_dirs(self) -> Path:
        """Create the data dir and its programs/evidence/reports subdirs if missing.

        Callers run this once at startup so every store can assume its directory already
        exists rather than each re-implementing the same ``mkdir(parents=True, exist_ok=True)``.
        """
        for d in (self.data_dir, self.programs_dir, self.evidence_dir, self.reports_dir):
            d.mkdir(parents=True, exist_ok=True)
        return self.data_dir

    @property
    def db_path(self) -> Path:
        """Path to the findings SQLite database, under the data dir."""
        return self.data_dir / "promptstrike.db"

    @property
    def programs_dir(self) -> Path:
        """Path to the registered-program YAML directory, under the data dir."""
        return self.data_dir / "programs"

    @property
    def evidence_dir(self) -> Path:
        """Path to the per-run JSON evidence directory, under the data dir."""
        return self.data_dir / "evidence"

    @property
    def reports_dir(self) -> Path:
        """Path to the generated-report output directory, under the data dir."""
        return self.data_dir / "reports"


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide cached ``Settings`` instance, resolving env vars once."""
    return Settings()
