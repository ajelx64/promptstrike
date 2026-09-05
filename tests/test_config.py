"""Tests for env-file and data-dir resolution.

``_default_env_file`` decides which file secrets are read from, so its precedence is
worth pinning: a silent change there means the tool reads a different env file than the
operator thinks it does.
"""

from __future__ import annotations

import pathlib
import re
import warnings

import pytest

from promptstrike import config


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    """Every test starts with no promptstrike env vars set."""
    monkeypatch.delenv("PROMPTSTRIKE_ENV_FILE", raising=False)
    monkeypatch.delenv("PROMPTSTRIKE_SECRETS_DIR", raising=False)


def test_explicit_env_file_wins(tmp_path, monkeypatch):
    """PROMPTSTRIKE_ENV_FILE is the highest-precedence tier."""
    explicit = tmp_path / "explicit.env"
    explicit.write_text("X=1", encoding="utf-8")
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / ".env").write_text("X=2", encoding="utf-8")

    monkeypatch.setenv("PROMPTSTRIKE_ENV_FILE", str(explicit))
    monkeypatch.setenv("PROMPTSTRIKE_SECRETS_DIR", str(secrets))

    assert config._default_env_file() == str(explicit)


def test_secrets_dir_used_when_it_holds_an_env_file(tmp_path, monkeypatch):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    env = secrets / ".env"
    env.write_text("X=1", encoding="utf-8")

    monkeypatch.setenv("PROMPTSTRIKE_SECRETS_DIR", str(secrets))
    assert config._default_env_file() == str(env)


def test_secrets_dir_without_env_file_falls_through(tmp_path, monkeypatch):
    """A configured-but-empty secrets dir must not shadow the home fallback."""
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    home = tmp_path / "home"
    (home / ".promptstrike").mkdir(parents=True)
    home_env = home / ".promptstrike" / ".env"
    home_env.write_text("X=1", encoding="utf-8")

    monkeypatch.setenv("PROMPTSTRIKE_SECRETS_DIR", str(secrets))
    monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: home))

    assert config._default_env_file() == str(home_env)


def test_returns_none_when_nothing_is_configured(tmp_path, monkeypatch):
    monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: tmp_path))
    assert config._default_env_file() is None


# Machine-specific path shapes. Deliberately matched against RAW SOURCE, not only quoted
# string literals: an earlier version of this guard checked quotes alone and sailed past the
# same path sitting in a docstring two lines below it.
_MACHINE_PATH_PATTERNS = (
    # Lookbehind so a URL scheme is not read as a drive letter: without it "https://"
    # matches as "s:/", and this security-named test would fail on an innocent docs link.
    r"(?<![A-Za-z])[A-Za-z]:[/\\]",   # C:/... or C:\...
    r"\\\\[A-Za-z0-9_.-]+\\",       # UNC \\server\share
    r"/home/[A-Za-z0-9._-]+",
    r"/Users/[A-Za-z0-9._-]+",
    r"/mnt/[a-z]/",
)


def test_no_machine_specific_absolute_path_in_source():
    """config.py must not carry any operator-specific absolute path, anywhere in the file.

    This repo is public. A baked-in path under one maintainer's drive publishes their directory
    layout and is meaningless to everyone else, which is the entire reason
    PROMPTSTRIKE_SECRETS_DIR exists. Scope note: this checks config.py only, because that is
    where the regression would recur; it is not a repo-wide scan.
    """
    src = pathlib.Path(config.__file__).read_text(encoding="utf-8")
    hits = [m for pat in _MACHINE_PATH_PATTERNS for m in re.findall(pat, src)]
    assert not hits, f"machine-specific path shape(s) present in config.py: {hits}"


def test_guard_does_not_fire_on_urls():
    """A docs link is not a machine path.

    The drive-letter pattern would otherwise match any URL scheme ("https://" -> "s:/"), so
    adding a reference link to config.py would fail a security-named test with a misleading
    message. This is the regression guard for the regression guard.
    """
    for sample in (
        '"""See https://docs.pydantic.dev/latest/concepts/pydantic_settings/"""',
        "# http://example.com/x",
        'url = "ftp://host/path"',
    ):
        hits = [m for pat in _MACHINE_PATH_PATTERNS for m in re.findall(pat, sample)]
        assert not hits, f"guard wrongly fired on {sample!r}: {hits}"


def test_the_regression_guard_actually_catches_each_shape():
    """The guard is only worth having if it fires — prove it against each shape it claims."""
    for sample in (
        'Path("D:/some/private/dir/.env")',
        "Path('C:\\\\Users\\\\someone\\\\.env')",
        r'Path("\\server\share\.env")',  # UNC
        'Path("/home/someone/.env")',
        'Path("/Users/someone/.env")',
        'Path("/mnt/c/dev/.env")',
        '# a path in a comment: D:/some/private/dir/.env',
    ):
        assert any(re.search(pat, sample) for pat in _MACHINE_PATH_PATTERNS), (
            f"guard failed to catch: {sample}"
        )


def test_missing_explicit_env_file_warns(tmp_path, monkeypatch):
    """A named-but-absent env file must be loud.

    pydantic-settings silently ignores a dotenv path that does not exist, so without this
    warning a typo'd PROMPTSTRIKE_ENV_FILE means the tool runs on defaults with no signal —
    and since PROMPTSTRIKE_TARGET_API_KEY then goes unset, a --live run would proceed with no
    Authorization header. Fail-safe, but silent, which is the part worth fixing.
    """
    missing = tmp_path / "typo.env"
    monkeypatch.setenv("PROMPTSTRIKE_ENV_FILE", str(missing))
    with pytest.warns(UserWarning, match="does not exist"):
        resolved = config._default_env_file()
    assert resolved == str(missing)  # precedence unchanged: the operator's choice still wins


def test_existing_explicit_env_file_does_not_warn(tmp_path, monkeypatch):
    present = tmp_path / "real.env"
    present.write_text("X=1", encoding="utf-8")
    monkeypatch.setenv("PROMPTSTRIKE_ENV_FILE", str(present))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert config._default_env_file() == str(present)


def test_relative_secrets_dir_is_refused(tmp_path, monkeypatch):
    """A relative PROMPTSTRIKE_SECRETS_DIR resolves against the CWD.

    That means the same command run from two directories would read different secrets. For a
    secrets path that is a footgun, not a convenience, so a relative value is warned about and
    skipped rather than silently resolved.
    """
    nested = tmp_path / "secrets"
    nested.mkdir()
    (nested / ".env").write_text("X=1", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PROMPTSTRIKE_SECRETS_DIR", "secrets")
    monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: tmp_path / "nohome"))

    with pytest.warns(UserWarning, match="must be an absolute path"):
        assert config._default_env_file() is None


def test_secrets_dir_expands_user(tmp_path, monkeypatch):
    home = tmp_path / "home"
    secrets = home / "s"
    secrets.mkdir(parents=True)
    env = secrets / ".env"
    env.write_text("X=1", encoding="utf-8")
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PROMPTSTRIKE_SECRETS_DIR", "~/s")
    assert config._default_env_file() == str(env)
