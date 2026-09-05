"""Scope enforcement (the safety spine) + program store tests."""

from __future__ import annotations

import pytest

from promptstrike.models import AssetType, Platform, Program, ScopeAsset
from promptstrike.scope import ProgramStore, ScopeError, check, enforce


def _program(**kw) -> Program:
    base = dict(
        name="example",
        platform=Platform.google_ai_vrp,
        allows_ai_testing=True,
        in_scope=[
            ScopeAsset(value="https://api.example.com/v1", type=AssetType.endpoint),
            ScopeAsset(value="example.com", type=AssetType.domain),
            ScopeAsset(value="gpt-x", type=AssetType.model),
        ],
        out_of_scope=[ScopeAsset(value="https://api.example.com/v1/admin", type=AssetType.endpoint)],
    )
    base.update(kw)
    return Program(**base)


def test_denies_when_ai_testing_not_authorized() -> None:
    p = _program(allows_ai_testing=False)
    d = check(p, "https://api.example.com/v1/chat")
    assert d.allowed is False
    assert "does not authorize" in d.reason


def test_allows_in_scope_endpoint_prefix() -> None:
    d = check(_program(), "https://api.example.com/v1/chat/completions")
    assert d.allowed is True
    assert d.matched == "https://api.example.com/v1"


def test_out_of_scope_beats_in_scope() -> None:
    # /v1/admin is out-of-scope even though /v1 is in-scope; out-of-scope must win.
    d = check(_program(), "https://api.example.com/v1/admin/keys")
    assert d.allowed is False
    assert "OUT-OF-SCOPE" in d.reason


def test_domain_matches_subdomain_but_is_boundary_safe() -> None:
    assert check(_program(), "https://chat.example.com/").allowed is True
    # look-alike domain must NOT match example.com
    assert check(_program(), "https://example.com.evil.net/").allowed is False


def test_model_asset_match() -> None:
    assert check(_program(), "gpt-x").allowed is True
    assert check(_program(), "model:gpt-x").allowed is True
    assert check(_program(), "gpt-y").allowed is False


def test_default_deny_for_unlisted_target() -> None:
    assert check(_program(), "https://unrelated.org/").allowed is False


def test_in_scope_endpoint_matches_with_query_string() -> None:
    # An in-scope endpoint stays in scope when invoked with query params (e.g. Azure ?api-version=).
    d = check(_program(), "https://api.example.com/v1/chat?api-version=2026-01-01")
    assert d.allowed is True


def test_enforce_raises_on_denied() -> None:
    with pytest.raises(ScopeError):
        enforce(_program(), "https://unrelated.org/")
    # allowed target returns a decision, no raise
    assert enforce(_program(), "https://api.example.com/v1/x").allowed is True


def test_program_store_round_trip(data_dir) -> None:
    store = ProgramStore(data_dir / "programs")
    store.add(_program())
    assert store.exists("example")
    loaded = store.get("example")
    assert loaded is not None
    assert loaded.allows_ai_testing is True
    assert len(loaded.in_scope) == 3
    assert [p.name for p in store.list()] == ["example"]


def test_program_store_no_overwrite_by_default(data_dir) -> None:
    store = ProgramStore(data_dir / "programs")
    store.add(_program())
    with pytest.raises(FileExistsError):
        store.add(_program())
    # overwrite=True succeeds
    store.add(_program(display_name="Example v2"), overwrite=True)
    assert store.get("example").display_name == "Example v2"
