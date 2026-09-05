"""Target client tests — scope enforcement, dry-run, rate-limiting, auth logging."""

from __future__ import annotations

import json

import pytest

from promptstrike.llm.target import AuthLog, RateLimiter, TargetClient
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


def _client(tmp_path, transport, limiter=None):
    return TargetClient(
        _program(),
        rate_limiter=limiter or SpyLimiter(),
        auth_log=AuthLog(tmp_path / "auth.jsonl"),
        transport=transport,
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
