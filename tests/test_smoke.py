"""Scaffold smoke tests."""

from __future__ import annotations


def test_package_version() -> None:
    import promptstrike

    assert promptstrike.__version__ == "0.1.0"


def test_settings_default_dry_run(monkeypatch) -> None:
    # The DRY_RUN safety invariant must default to True with no env overrides.
    monkeypatch.delenv("PROMPTSTRIKE_DRY_RUN", raising=False)
    from promptstrike.config import Settings

    s = Settings(_env_file=None)
    assert s.dry_run is True
    assert s.rate_limit_rps > 0
