"""Scope-locked, rate-limited client for sending prompts to an authorized target endpoint.

Invariants (all covered by tests):
  1. Scope is enforced on EVERY call, before any network use — an out-of-scope target raises
     ``ScopeError`` and the transport is never invoked.
  2. Nothing is sent unless ``live=True`` — the default is render-only (dry run).
  3. The rate limiter is applied before every live send (no-DoS guard).
  4. Every attempt (allowed or denied, live or dry) is appended to the authorization log.

The HTTP transport is injectable so tests never touch the network; the default transport speaks the
OpenAI-compatible chat-completions shape.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path

from promptstrike.models import Evidence, Program
from promptstrike.scope import ScopeError, check

# transport(prompt, target, program) -> (response_text, metadata)
Transport = Callable[[str, str, Program], Awaitable[tuple[str, dict]]]


class RateLimiter:
    """Minimum-interval limiter. ``sleep``/``clock`` are injectable for deterministic tests."""

    def __init__(
        self,
        rps: float,
        *,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.min_interval = (1.0 / rps) if rps and rps > 0 else 0.0
        self._sleep = sleep
        self._clock = clock
        self._last: float | None = None

    async def acquire(self) -> None:
        """Block until the caller may send again, honouring the configured minimum interval.

        A non-positive rps disables limiting and returns immediately — so the no-DoS guard is only
        as real as the rate the caller configured. :meth:`TargetClient.send` acquires before every
        live send; that call site is what makes the guard unconditional in practice.
        """
        if self.min_interval <= 0:
            return
        now = self._clock()
        if self._last is not None:
            wait = self.min_interval - (now - self._last)
            if wait > 0:
                await self._sleep(wait)
        self._last = self._clock()


class AuthLog:
    """Append-only JSONL authorization log — a compliance/safe-harbor artifact per run."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def record(
        self,
        *,
        program: str,
        target: str,
        prompt: str,
        live: bool,
        allowed: bool,
        reason: str = "",
        requested_live: bool = False,
    ) -> dict:
        """Append one authorization decision to the JSONL log and return the entry.

        Denied attempts are logged too — the log's worth as a safe-harbor artifact comes from
        showing what was *refused*, not only what was sent.

        The prompt is recorded as a truncated SHA-256 plus its length rather than verbatim, so the
        log can be handed over as evidence of authorization without republishing working exploit
        text. ``requested_live`` is what the operator asked for and ``live`` is what actually
        happened; the two differ exactly when a ``--live`` attempt failed the scope check.
        """
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "program": program,
            "target": target,
            "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16],
            "prompt_len": len(prompt),
            "requested_live": requested_live,  # what the operator asked for
            "live": live,  # what actually happened (a denied --live attempt logs live=false)
            "allowed": allowed,
            "reason": reason,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        return entry


async def openai_chat_transport(prompt: str, target: str, program: Program) -> tuple[str, dict]:
    """Default transport: POST an OpenAI-compatible chat completion to ``target``.

    Reads ``PROMPTSTRIKE_TARGET_API_KEY`` / ``PROMPTSTRIKE_TARGET_MODEL`` from the environment.
    Imported lazily so httpx is only required when actually firing live.
    """
    import httpx

    model = os.environ.get("PROMPTSTRIKE_TARGET_MODEL", "gpt-4o-mini")
    headers = {"Content-Type": "application/json"}
    api_key = os.environ.get("PROMPTSTRIKE_TARGET_API_KEY")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    payload = {"model": model, "messages": [{"role": "user", "content": prompt}]}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(target, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
    text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    return text, {"model": data.get("model", model), "status_code": resp.status_code}


class TargetClient:
    """Sends prompts to an authorized target, enforcing scope + rate-limit + logging on every call."""

    def __init__(
        self,
        program: Program,
        *,
        rate_limiter: RateLimiter,
        auth_log: AuthLog,
        transport: Transport | None = None,
        model: str = "",
    ) -> None:
        self.program = program
        self.rate_limiter = rate_limiter
        self.auth_log = auth_log
        self.transport = transport or openai_chat_transport
        self.model = model

    async def send(self, prompt: str, target: str, *, live: bool = False) -> Evidence:
        """Send one prompt to ``target`` and capture the exchange as Evidence.

        **This is the safety chokepoint.** Every prompt in the tool reaches the network through this
        method, which is why the order below is the enforcement rather than a convenience:

        1. Evaluate scope FIRST, before any transport work happens.
        2. Log the attempt — allowed or denied.
        3. Raise :class:`ScopeError` if denied; the transport is never invoked.
        4. If ``live`` is false, return render-only Evidence with an empty response — no network.
        5. Only then acquire the rate limiter and call the transport.

        Both defaults fail closed: ``live=False`` means a caller that forgets the flag sends
        nothing, and a target absent from the program's in-scope list is denied rather than
        allowed. New probes inherit all of this for free by going through here — which is the
        reason they must never construct a transport themselves.
        """
        decision = check(self.program, target)
        # Log the attempt (denied attempts are logged too, for audit).
        self.auth_log.record(
            program=self.program.name,
            target=target,
            prompt=prompt,
            requested_live=live,
            live=live and decision.allowed,
            allowed=decision.allowed,
            reason=decision.reason,
        )
        if not decision.allowed:
            raise ScopeError(decision.reason)

        if not live:
            # Render-only: never touch the network.
            return Evidence(
                prompt=prompt,
                response="",
                model=self.model,
                metadata={"dry_run": True, "target": target},
            )

        await self.rate_limiter.acquire()
        start = time.monotonic()
        text, meta = await self.transport(prompt, target, self.program)
        latency_ms = int((time.monotonic() - start) * 1000)
        return Evidence(
            prompt=prompt,
            response=text,
            model=str(meta.get("model", self.model)),
            model_version=str(meta.get("model_version", "")),
            latency_ms=latency_ms,
            metadata={**meta, "dry_run": False, "target": target},
        )
