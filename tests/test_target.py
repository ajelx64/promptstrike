"""Target client tests — scope enforcement, dry-run, rate-limiting, auth logging."""

from __future__ import annotations

import json

import pytest

from promptstrike.llm.target import (
    AuthLog,
    DryRunError,
    RateLimiter,
    TargetClient,
    redact_target,
)
from promptstrike.models import AssetType, Platform, Program, ScopeAsset
from promptstrike.scope import ScopeError


def _program() -> Program:
    return Program(
        name="example",
        platform=Platform.google_ai_vrp,
        allows_ai_testing=True,
        in_scope=[ScopeAsset(value="https://api.example.com/v1", type=AssetType.endpoint)],
    )


class SpyTransport:
    def __init__(self, response: str = "ok") -> None:
        self.calls: list[tuple[str, str]] = []
        self.response = response

    async def __call__(self, prompt, target, program):
        self.calls.append((prompt, target))
        return self.response, {"model": "fake-model", "status_code": 200}


class SpyLimiter(RateLimiter):
    def __init__(self) -> None:
        super().__init__(rps=0)  # no real waiting
        self.acquired = 0

    async def acquire(self) -> None:
        self.acquired += 1


def _client(tmp_path, transport, limiter=None, allow_live=True):
    """Build a client for tests.

    ``allow_live`` defaults to True here - the opposite of the production default - because most
    tests in this file exercise the live path deliberately. The production default is False and
    is covered explicitly by the dry-run-switch tests below.
    """
    return TargetClient(
        _program(),
        rate_limiter=limiter or SpyLimiter(),
        auth_log=AuthLog(tmp_path / "auth.jsonl"),
        transport=transport,
        allow_live=allow_live,
    )


async def test_dry_run_never_calls_transport(tmp_path) -> None:
    spy = SpyTransport()
    client = _client(tmp_path, spy)
    ev = await client.send("hello", "https://api.example.com/v1/chat", live=False)
    assert spy.calls == []  # transport untouched
    assert ev.response == ""
    assert ev.metadata["dry_run"] is True


async def test_out_of_scope_raises_and_does_not_send(tmp_path) -> None:
    spy = SpyTransport()
    client = _client(tmp_path, spy)
    with pytest.raises(ScopeError):
        await client.send("payload", "https://evil.test/", live=True)
    assert spy.calls == []  # never reached the transport
    # the denied attempt was logged
    lines = (tmp_path / "auth.jsonl").read_text(encoding="utf-8").strip().splitlines()
    entry = json.loads(lines[-1])
    assert entry["allowed"] is False and entry["live"] is False


async def test_live_send_invokes_transport_and_rate_limiter(tmp_path) -> None:
    spy = SpyTransport(response="model replied")
    limiter = SpyLimiter()
    client = _client(tmp_path, spy, limiter=limiter)
    ev = await client.send("attack", "https://api.example.com/v1/chat", live=True)
    assert spy.calls == [("attack", "https://api.example.com/v1/chat")]
    assert ev.response == "model replied"
    assert ev.model == "fake-model"
    assert ev.metadata["dry_run"] is False
    assert limiter.acquired == 1  # rate limiter applied before send


async def test_auth_log_records_allowed_live_attempt(tmp_path) -> None:
    client = _client(tmp_path, SpyTransport())
    await client.send("x", "https://api.example.com/v1/chat", live=True)
    entry = json.loads((tmp_path / "auth.jsonl").read_text(encoding="utf-8").strip().splitlines()[-1])
    assert entry["allowed"] is True
    assert entry["live"] is True
    assert entry["program"] == "example"
    assert "prompt_sha256" in entry and entry["prompt_len"] == 1


async def test_rate_limiter_sleeps_to_maintain_interval() -> None:
    sleeps: list[float] = []
    now = {"t": 0.0}

    async def fake_sleep(d: float) -> None:
        sleeps.append(d)

    limiter = RateLimiter(rps=1.0, sleep=fake_sleep, clock=lambda: now["t"])
    await limiter.acquire()  # first call: no wait
    await limiter.acquire()  # second call, no time elapsed: must wait ~1s
    assert sleeps == [1.0]


async def test_auth_log_records_requested_live_on_denied(tmp_path) -> None:
    # A blocked --live attempt must still be auditable as "live was requested".
    client = _client(tmp_path, SpyTransport())
    with pytest.raises(ScopeError):
        await client.send("x", "https://evil.test/", live=True)
    entry = json.loads((tmp_path / "auth.jsonl").read_text(encoding="utf-8").strip().splitlines()[-1])
    assert entry["requested_live"] is True  # operator asked to fire...
    assert entry["live"] is False  # ...but scope blocked it
    assert entry["allowed"] is False


# ---------------------------------------------------------------------------------------------
# The global dry-run kill-switch.
#
# PROMPTSTRIKE_DRY_RUN was documented as a "global safety switch" while nothing read it. The gate
# now lives on TargetClient, which is the single point every prompt passes through, so the TUI,
# a future command and any library consumer inherit it rather than each re-implementing it.
# ---------------------------------------------------------------------------------------------


async def test_global_dry_run_refuses_live_and_does_not_send(tmp_path) -> None:
    """With the switch active, a live send is refused before the transport is touched."""
    # A transport that records any call, so "was it invoked" is directly observable.
    spy = SpyTransport()
    # Build a client in the PRODUCTION default state - live traffic not permitted.
    client = _client(tmp_path, spy, allow_live=False)
    # Asking for live must raise rather than silently downgrading to a dry run.
    with pytest.raises(DryRunError) as raised:
        await client.send("hello", "https://api.example.com/v1/chat", live=True)
    # The message must name the variable the operator has to change, not just say "refused".
    assert "PROMPTSTRIKE_DRY_RUN" in str(raised.value)
    # And nothing may have reached the network.
    assert spy.calls == []


async def test_global_dry_run_refusal_is_logged(tmp_path) -> None:
    """A refused attempt is still an authorization-log entry - that is the artifact's value."""
    # Fixed log path so the file can be read back and asserted on.
    log_path = tmp_path / "auth.jsonl"
    # Client in the refusing state, writing to that log.
    client = TargetClient(
        _program(),
        rate_limiter=SpyLimiter(),
        auth_log=AuthLog(log_path),
        transport=SpyTransport(),
        allow_live=False,
    )
    # Trigger the refusal; the exception itself is not what this test is about.
    with pytest.raises(DryRunError):
        await client.send("hello", "https://api.example.com/v1/chat", live=True)
    # Exactly one entry should have been appended.
    entries = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert len(entries) == 1
    # It records what the operator ASKED for...
    assert entries[0]["requested_live"] is True
    # ...what actually happened, which is nothing...
    assert entries[0]["live"] is False
    # ...that it was refused...
    assert entries[0]["allowed"] is False
    # ...and why, so the log explains itself without the reader knowing the code.
    assert "dry-run" in entries[0]["reason"]


async def test_global_dry_run_still_allows_a_dry_run(tmp_path) -> None:
    """The switch blocks live traffic only; rendering probes must still work."""
    # Transport that would record a call if one happened.
    spy = SpyTransport()
    # Refusing client, as in production defaults.
    client = _client(tmp_path, spy, allow_live=False)
    # A dry run is not live traffic, so it proceeds normally.
    evidence = await client.send("hello", "https://api.example.com/v1/chat", live=False)
    # Nothing was sent...
    assert spy.calls == []
    # ...and the caller still gets the render-only Evidence it expects.
    assert evidence.metadata["dry_run"] is True


# ---------------------------------------------------------------------------------------------
# Credential redaction. The prompt is hashed so the authorization log can be handed to a program
# owner - but the target sits beside it, and an endpoint carrying userinfo or an api_key would
# put the operator's OWN credentials in that same shareable file.
# ---------------------------------------------------------------------------------------------


def test_redact_target_strips_userinfo_and_secret_query_values() -> None:
    """Credentials must not survive into anything durable."""
    # A target written the way a careless copy-paste produces one.
    raw = "https://svc:SuperSecret123@api.example.com/v1/chat?api_key=AKIAREAL&model=gpt-4o"
    # Redact it the way the log and Evidence metadata now do.
    redacted = redact_target(raw)
    # The password must be gone.
    assert "SuperSecret123" not in redacted
    # So must the key value.
    assert "AKIAREAL" not in redacted
    # The host and path must survive, or the log stops being useful as an audit record.
    assert "api.example.com/v1/chat" in redacted
    # Non-secret parameters are untouched, so the record still shows what was requested.
    assert "model=gpt-4o" in redacted
    # And the redaction is visible rather than silent - that a credential WAS present is itself
    # worth knowing when reading an audit trail.
    assert "REDACTED" in redacted


def test_redact_target_leaves_ordinary_targets_alone() -> None:
    """Positive control: a clean URL must pass through byte-identical."""
    # Nothing here is credential-bearing.
    clean = "https://api.example.com/v1/chat?api-version=2026-01-01"
    # So redaction must be a no-op.
    assert redact_target(clean) == clean


def test_redact_target_passes_through_non_urls() -> None:
    """A bare host or model token has no userinfo or query, and must not be mangled."""
    # Model assets are plain tokens, not URLs.
    assert redact_target("gpt-4o-mini") == "gpt-4o-mini"


async def test_credentials_never_reach_the_authorization_log(tmp_path) -> None:
    """End-to-end: a live send with credentials in the URL must not log them."""
    # A program whose in-scope asset is the credential-bearing endpoint.
    program = Program(
        name="example",
        platform=Platform.google_ai_vrp,
        allows_ai_testing=True,
        in_scope=[ScopeAsset(value="https://api.example.com/v1", type=AssetType.endpoint)],
    )
    # Fixed log path so it can be read back.
    log_path = tmp_path / "auth.jsonl"
    # A client permitted to send, with a spy transport standing in for the network.
    client = TargetClient(
        program,
        rate_limiter=SpyLimiter(),
        auth_log=AuthLog(log_path),
        transport=SpyTransport(),
        allow_live=True,
    )
    # Send to the in-scope endpoint, spelled with embedded credentials.
    await client.send(
        "hello",
        "https://svc:SuperSecret123@api.example.com/v1/chat",
        live=True,
    )
    # The whole log file, as text.
    logged = log_path.read_text(encoding="utf-8")
    # The credential must appear nowhere in it.
    assert "SuperSecret123" not in logged
    # And the entry must still identify the target host, or the audit trail is useless.
    assert "api.example.com" in logged
