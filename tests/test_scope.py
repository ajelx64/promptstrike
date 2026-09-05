"""Scope enforcement (the safety spine) + program store tests."""

from __future__ import annotations

import pathlib
import tempfile

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


# ---------------------------------------------------------------------------------------------
# Normalization-evasion tests.
#
# The transport (httpx) canonicalizes a URL before it goes on the wire: it resolves dot-segments,
# collapses duplicate slashes, decodes percent-escapes and drops the default port. If the scope
# gate compares the RAW string while the transport sends the CANONICAL one, the two disagree and
# an out-of-scope carve-out can be walked around. Every case below sends a byte-identical request
# to the resource `test_out_of_scope_beats_in_scope` above asserts is refused.
# ---------------------------------------------------------------------------------------------

# Each entry is one spelling of the out-of-scope resource https://api.example.com/v1/admin/keys.
OUT_OF_SCOPE_EVASIONS = [
    "https://api.example.com/v1/x/../admin/keys",      # parent-segment traversal
    "https://api.example.com/v1/./admin/keys",         # current-segment noise
    "https://api.example.com/v1//admin/keys",          # duplicate slash
    "https://api.example.com/v1/%61dmin/keys",         # percent-encoded 'a' in "admin"
    "https://api.example.com/v1/%61%64%6d%69%6e/keys",  # fully percent-encoded "admin"
    "https://api.example.com/v1/admin;sid=1/keys",     # RFC 3986 path parameter
    "https://api.example.com:443/v1/admin/keys",       # explicit default port for https
    "https://api.example.com/v1/ADMIN/keys",           # upper-case path
    "https://api.example.com/v1/admin/keys/",          # trailing slash
    "https://user:secret@api.example.com/v1/admin/keys",  # userinfo prefix
]


@pytest.mark.parametrize("evasive_target", OUT_OF_SCOPE_EVASIONS)
def test_out_of_scope_survives_url_normalization(evasive_target: str) -> None:
    """Every spelling of an out-of-scope resource must still be denied.

    A miss here is fail-OPEN on the one list a bug-bounty program says do not touch, and the
    authorization log would record the request as authorized — so this is the highest-severity
    failure the scope gate has.
    """
    # Evaluate the evasive spelling against the standard fixture program.
    decision = check(_program(), evasive_target)
    # The gate must refuse it exactly as it refuses the plain spelling.
    assert decision.allowed is False, f"scope bypass: {evasive_target} was allowed"
    # And it must refuse it for the right reason - matching the carve-out, not merely falling
    # through to default-deny, which would mean the in-scope prefix also stopped matching.
    assert "OUT-OF-SCOPE" in decision.reason


def test_canonicalization_does_not_over_deny_a_sibling_path() -> None:
    """Boundary safety must survive canonicalization: /v1/administrator is not /v1/admin."""
    # "administrator" merely starts with the carve-out's text; it is a different path segment.
    decision = check(_program(), "https://api.example.com/v1/administrator/status")
    # It is under the in-scope /v1 prefix and outside the /v1/admin carve-out, so it is allowed.
    assert decision.allowed is True
    # And it matched via the in-scope endpoint rather than by accident.
    assert decision.matched == "https://api.example.com/v1"


def test_canonicalization_keeps_ordinary_targets_allowed() -> None:
    """Positive control: the normal happy path must not regress while closing the bypass."""
    # A plain in-scope call with a query string, the shape the tool is used with every day.
    decision = check(_program(), "https://api.example.com/v1/chat?api-version=2026-01-01")
    # Still allowed - query strings are deliberately ignored for the comparison.
    assert decision.allowed is True


def test_traversal_above_the_asset_root_is_denied() -> None:
    """Traversal out of the in-scope prefix must not be rescued by prefix confusion.

    Scoped to an endpoint-only program on purpose: the shared fixture also carries a bare
    ``example.com`` domain asset, which legitimately covers this host, so a denial there would
    prove nothing about the endpoint comparison.
    """
    # A program whose only in-scope asset is the endpoint prefix under test.
    program = _program(
        in_scope=[ScopeAsset(value="https://api.example.com/v1", type=AssetType.endpoint)],
        out_of_scope=[],
    )
    # After resolution this is api.example.com/other, which is outside the /v1 prefix.
    decision = check(program, "https://api.example.com/v1/../other")
    # Nothing matches, so default-deny applies.
    assert decision.allowed is False


def test_wildcard_domain_does_not_match_the_apex() -> None:
    """``*.example.com`` means subdomains, not the apex.

    Bug-bounty scope grammars treat the apex as its own asset, frequently excluded. Matching it
    from a ``*.`` wildcard silently widens scope inside the deny-by-default control.
    """
    # A program whose only domain asset is an explicit wildcard.
    program = _program(
        in_scope=[ScopeAsset(value="*.example.com", type=AssetType.domain)],
        out_of_scope=[],
    )
    # A subdomain is in scope - this is what the wildcard is for.
    assert check(program, "https://chat.example.com/").allowed is True
    # The apex is NOT covered by the wildcard and must fall through to default-deny.
    assert check(program, "https://example.com/").allowed is False


def test_bare_domain_asset_still_matches_its_apex() -> None:
    """A domain written WITHOUT ``*.`` keeps covering both the apex and its subdomains."""
    # The fixture's "example.com" asset is written bare, so apex coverage is intended.
    program = _program(
        in_scope=[ScopeAsset(value="example.com", type=AssetType.domain)],
        out_of_scope=[],
    )
    # Apex matches.
    assert check(program, "https://example.com/").allowed is True
    # And so does a subdomain.
    assert check(program, "https://chat.example.com/").allowed is True


def test_program_name_cannot_escape_the_registry_directory() -> None:
    """A program name becomes a filename, so raw operator input must be validated.

    ``Program.name`` is slug-validated by pydantic, but ``get``/``exists`` take the string
    straight from ``--program``. Low severity on a single-user CLI, but a security tool should
    not build a filesystem path out of unvalidated input.
    """
    # A store rooted at a throwaway directory.
    store = ProgramStore(pathlib.Path(tempfile.mkdtemp()))
    # Each of these would resolve outside the registry directory if joined unchecked.
    for hostile_name in ("../../etc/passwd", "..", "a/b", "/abs", "C:/abs", "name with space"):
        # The store must refuse rather than resolve it.
        with pytest.raises(ValueError):
            store.exists(hostile_name)


def test_ordinary_program_names_still_work() -> None:
    """Positive control: the validator must not reject legitimate slugs."""
    # A store rooted at a throwaway directory.
    store = ProgramStore(pathlib.Path(tempfile.mkdtemp()))
    # Normal names are accepted; the file simply does not exist yet.
    assert store.exists("example") is False
    assert store.exists("google-ai-vrp-2026") is False


# Port spellings that httpx resolves to the https default, and so to the same wire request.
# A string comparison against "443" missed every one of these, which let a target walk past an
# out-of-scope carve-out and match a broader in-scope asset instead.
DEFAULT_PORT_SPELLINGS = ["", ":", ":443", ":0443", ":00443"]


@pytest.mark.parametrize("port_spelling", DEFAULT_PORT_SPELLINGS)
def test_default_port_spellings_cannot_evade_a_carve_out(port_spelling: str) -> None:
    """Every spelling of the default port must resolve to the same scope decision."""
    # The out-of-scope resource, written with this spelling of the port.
    target = f"https://api.example.com{port_spelling}/v1/admin/keys"
    # It must be denied regardless of how the port is written.
    decision = check(_program(), target)
    assert decision.allowed is False, f"scope bypass via port spelling {port_spelling!r}"
    # And denied by the carve-out, not merely by falling through to default-deny.
    assert "OUT-OF-SCOPE" in decision.reason


def test_non_default_port_is_still_significant() -> None:
    """Normalizing the default port must not erase a genuinely different one."""
    # Port 8443 is not the https default, so this is a different origin than the in-scope asset.
    decision = check(_program(), "https://api.example.com:8443/v1/chat")
    # It matches no endpoint asset; the domain asset still covers the host, which is correct.
    assert decision.matched != "https://api.example.com/v1"
