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
import re
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

from promptstrike.models import Evidence, Program
from promptstrike.scope import ScopeError, check

# transport(prompt, target, program) -> (response_text, metadata)
Transport = Callable[[str, str, Program], Awaitable[tuple[str, dict]]]


class DryRunError(Exception):
    """Raised when live traffic is requested while the global dry-run switch is active.

    Distinct from :class:`~promptstrike.scope.ScopeError`: that one means "this target is not
    authorized", this one means "no target may be contacted at all right now". Keeping them
    separate matters because the operator's fix differs - one is a scope registration, the other
    is an environment setting.
    """


class RateLimiter:
    """Minimum-interval limiter. ``sleep``/``clock`` are injectable for deterministic tests."""

    def __init__(
        self,
        rps: float,
        *,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        # Seconds that must elapse between sends. A zero/negative/None rps means "no limiting",
        # which is stored as an interval of 0 rather than raising - see acquire()'s docstring.
        self.min_interval = (1.0 / rps) if rps and rps > 0 else 0.0
        # Injected sleep, so tests can advance time without actually waiting.
        self._sleep = sleep
        # Injected monotonic clock; monotonic (not wall time) so an NTP step cannot skip the wait.
        self._clock = clock
        # Timestamp of the previous acquire, or None before the first send.
        self._last: float | None = None

    async def acquire(self) -> None:
        """Block until the caller may send again, honouring the configured minimum interval.

        A non-positive rps disables limiting and returns immediately — so the no-DoS guard is only
        as real as the rate the caller configured. :meth:`TargetClient.send` acquires before every
        live send; that call site is what makes the guard unconditional in practice.
        """
        # Limiting disabled: return immediately without recording a timestamp.
        if self.min_interval <= 0:
            return
        # Read the clock once so the gap calculation is against a single consistent instant.
        now = self._clock()
        # Nothing to wait for on the very first send.
        if self._last is not None:
            # How much of the minimum interval has not yet elapsed since the previous send.
            remaining_wait = self.min_interval - (now - self._last)
            # Only sleep when the interval has not already passed on its own.
            if remaining_wait > 0:
                # Yield to the event loop for the remainder - this is the no-DoS pacing.
                await self._sleep(remaining_wait)
        # Stamp AFTER sleeping, so the next interval is measured from when this send was released.
        self._last = self._clock()


# Query parameters whose VALUE is a credential rather than a routing detail. Matched as a
# substring on the lower-cased key, so "x-api-key" and "apiKey" are both caught.
_SECRET_QUERY_KEYS = (
    "key", "token", "secret", "password", "passwd", "pwd", "sig", "signature",
    # Added after review: OAuth and session-bearing names that the original list missed.
    "auth", "bearer", "session", "credential", "code", "access", "refresh",
)

# Prefixes that identify a credential no matter where it appears, including inside a path
# segment. Deliberately a fixed list of well-known issuer formats rather than an entropy
# heuristic: entropy would redact legitimate high-entropy path segments such as a run id or a
# UUID endpoint, which would quietly destroy the audit trail this log exists to be.
_SECRET_VALUE_PREFIXES = (
    "sk-", "sk_", "pk_", "rk_",                             # OpenAI / Stripe style
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",  # GitHub
    "xoxb-", "xoxp-", "xoxa-", "xoxs-", "xapp-",            # Slack (incl. app-level tokens)
    "akia", "asia", "agpa", "aida", "aroa", "anpa",         # AWS key ids (compared lower-cased)
    "glpat-",                                               # GitLab
    "aiza",                                                 # Google AI Studio / Gemini
    "hf_",                                                  # HuggingFace
    "shpat_", "shpss_",                                     # Shopify
    "dop_v1_",                                              # DigitalOcean
    "npm_",                                                 # npm
    "eyj",                                                  # a JWT's base64 "{"a..." header
)


# Percent-decoding passes, matching the scope canonicalizer. One pass was not enough: a
# double-encoded "%2573k-" decodes to "%73k-" and only then to "sk-", so a single decode left
# the prefix check comparing a string the server would resolve differently.
_MAX_DECODE_PASSES = 3


def _fully_decode(value: str) -> str:
    """Percent-decode until the value stops changing, bounded by the pass cap."""
    # Track across passes so we can stop as soon as decoding is a no-op.
    decoded = value
    for _ in range(_MAX_DECODE_PASSES):
        once = unquote(decoded)
        if once == decoded:
            break
        decoded = once
    return decoded


def _looks_like_secret(value: str) -> bool:
    """True when a value carries a recognisable credential prefix.

    Decodes first: the query half was decoded before matching while the path half was not, so a
    percent-encoded "sk-" in a path segment sailed straight through a check that would have
    caught the identical plain value.
    """
    # Compare lower-cased so AKIA/akia and eyJ/eyj both match.
    lowered = _fully_decode(value).lower()
    # Any known issuer prefix is treated as a credential wherever it appears.
    return any(lowered.startswith(prefix) for prefix in _SECRET_VALUE_PREFIXES)

# What a redacted value is replaced with. A fixed marker rather than deletion, so the log still
# shows that a credential WAS present - which is itself worth knowing when reading an audit trail.
_REDACTED = "REDACTED"


def redact_target(target: str) -> str:
    """Strip credentials from a target before it is written anywhere durable.

    The prompt is deliberately stored as a truncated hash so the authorization log can be handed
    to a program owner as a safe-harbor artifact - but the target sits beside it, and an endpoint
    written as ``https://user:secret@host/v1?api_key=...`` would put the operator's OWN
    credentials into that file, the evidence transcripts, the findings database, and the report
    submitted to a third party.

    Removes userinfo, secret-bearing query and fragment values, and path segments carrying a
    recognised credential prefix. Redaction is visible rather than silent - a fixed marker
    records that a credential WAS present, which is itself worth knowing in an audit trail.

    Two design notes, both learned from getting this wrong:

    * **Nothing short-circuits.** An earlier version returned a scheme-less target untouched,
      which leaked completely - and a bare ``host/path`` is a first-class supported target form
      here, not an edge case. Everything is parsed.
    * **The prefix list is a maintained asset, not a completeness claim.** A bespoke credential
      format with no recognisable prefix, sitting in an opaque path segment, is undetectable by
      this design. That is a deliberate trade: an entropy heuristic would redact legitimate
      high-entropy segments such as a run id, quietly destroying the audit trail this exists to
      be. Callers must not treat a redacted target as *proven* free of secrets.
    """
    # Parse unconditionally. urlsplit needs a scheme to recognise an authority, so a scheme-less
    # target gets a placeholder that is removed again before returning - the alternative, an
    # early return, is what leaked.
    had_scheme = "://" in target
    parseable = target if had_scheme else "placeholder://" + target
    parts = urlsplit(parseable)
    # Userinfo is credentials by definition. netloc keeps the host and any port.
    netloc = parts.netloc
    if "@" in netloc:
        # Split on the LAST "@" since userinfo may itself contain one.
        netloc = _REDACTED + "@" + netloc.rsplit("@", 1)[1]
    # Redact any path segment carrying a recognised credential prefix (a key pasted into a path).
    path = "/".join(
        _REDACTED if _looks_like_secret(segment) else segment
        for segment in parts.path.split("/")
    )
    # Query and fragment are both key=value bags in practice - OAuth implicit flow returns tokens
    # in the fragment - so the same redaction applies to each.
    query = _redact_parameter_bag(parts.query)
    fragment = _redact_parameter_bag(parts.fragment)
    # Reassemble, then drop the placeholder scheme if we added one.
    rebuilt = urlunsplit((parts.scheme, netloc, path, query, fragment))
    # urlunsplit omits the "//" when the netloc is empty, so a target with no authority
    # ("/v1/chat") came back as "placeholder:/v1/chat" - a fabricated scheme written into the
    # safe-harbor log. Strip either spelling.
    if had_scheme:
        return rebuilt
    return rebuilt.removeprefix("placeholder://").removeprefix("placeholder:")


def _redact_parameter_bag(raw: str) -> str:
    """Redact secret-bearing values in a ``k=v`` bag (a query string or a fragment)."""
    # Nothing to do for an absent or empty bag.
    if not raw:
        return raw
    # Rebuilt parameters, preserving order and unknown keys so the record stays readable.
    redacted_parameters = []
    # Split on BOTH separators: "&" is conventional, but ";" is accepted by several servers and
    # splitting on "&" alone let "?a=1;api_key=..." through as one unrecognised parameter.
    for parameter in re.split(r"[&;]", raw):
        # Split each parameter into name and value at the first "=".
        name, equals, value = parameter.partition("=")
        # A bare token with no "=" still has to be checked - "?sk-LIVE..." is a credential even
        # though it parses as a nameless flag.
        if not equals:
            redacted_parameters.append(
                _REDACTED if _looks_like_secret(unquote(parameter)) else parameter
            )
            continue
        # Percent-decode BOTH halves before matching. Comparing the raw text let "%74oken=" hide
        # a secret-bearing name and "%73%6b-" hide a secret-bearing value.
        decoded_name = _fully_decode(name).lower()
        decoded_value = _fully_decode(value)
        # Redact when the NAME looks credential-bearing, or the VALUE carries a known prefix.
        if any(marker in decoded_name for marker in _SECRET_QUERY_KEYS) or _looks_like_secret(
            decoded_value
        ):
            redacted_parameters.append(f"{name}={_REDACTED}")
        else:
            redacted_parameters.append(parameter)
    # Reassemble with the conventional separator.
    return "&".join(redacted_parameters)

class AuthLog:
    """Append-only JSONL authorization log — a compliance/safe-harbor artifact per run."""

    def __init__(self, path: str | Path) -> None:
        # Destination JSONL file. Parent directories are created lazily on the first record().
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
        # One JSON object per decision. Field names are the log's on-disk schema, so anything
        # reading these files (or a program owner reviewing them) binds to these exact keys.
        entry = {
            # UTC + ISO-8601 so entries from different machines/timezones still sort correctly.
            "timestamp": datetime.now(UTC).isoformat(),
            "program": program,
            # Redacted, not raw: this file is meant to be shareable as a safe-harbor artifact.
            "target": redact_target(target),
            # Fingerprint, not the text: enough to prove two entries used the same prompt, while
            # keeping working exploit text out of a file meant to be shared with a program owner.
            "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16],
            # Length is kept because the hash alone says nothing about the scale of what was sent.
            "prompt_len": len(prompt),
            "requested_live": requested_live,  # what the operator asked for
            "live": live,  # what actually happened (a denied --live attempt logs live=false)
            # The scope gate's verdict for this attempt.
            "allowed": allowed,
            # The deciding asset / gate, copied verbatim from the ScopeDecision or the dry-run gate.
            "reason": reason,
        }
        # Create the log directory on demand so the first attempt of a fresh install still records.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Append-only mode: existing entries are never rewritten, which is what makes the file
        # usable as an audit trail.
        with self.path.open("a", encoding="utf-8") as log_file:
            # One compact JSON object per line - the JSONL shape, so the file stays streamable.
            log_file.write(json.dumps(entry) + "\n")
        # Return the entry so callers (and tests) can assert on exactly what was recorded.
        return entry


async def openai_chat_transport(prompt: str, target: str, program: Program) -> tuple[str, dict]:
    """Default transport: POST an OpenAI-compatible chat completion to ``target``.

    Reads ``PROMPTSTRIKE_TARGET_API_KEY`` / ``PROMPTSTRIKE_TARGET_MODEL`` from the environment.
    Imported lazily so httpx is only required when actually firing live.
    """
    # Imported here, not at module scope, so the rest of the tool (and every dry run) works
    # without httpx installed - reaching this line means traffic is genuinely about to be sent.
    import httpx

    # Which model to ask for; the default keeps a bare `--live` run from failing on a missing var.
    model = os.environ.get("PROMPTSTRIKE_TARGET_MODEL", "gpt-4o-mini")
    # Base headers for the JSON request body.
    headers = {"Content-Type": "application/json"}
    # Credentials come from the environment only - never from the program YAML or the CLI args.
    api_key = os.environ.get("PROMPTSTRIKE_TARGET_API_KEY")
    # Only add an Authorization header when a key is actually configured; some targets need none.
    if api_key:
        # Bearer scheme, per the OpenAI-compatible convention this transport implements.
        headers["Authorization"] = f"Bearer {api_key}"
    # Single-turn chat-completions body - the probe prompt is the whole user message.
    payload = {"model": model, "messages": [{"role": "user", "content": prompt}]}
    # Bounded timeout, and the context manager guarantees the connection is closed on any error.
    async with httpx.AsyncClient(timeout=30.0) as client:
        # The actual outbound request. This function performs NO scope check of its own - it is
        # only ever reached through TargetClient.send, which has already run the gate.
        response = await client.post(target, json=payload, headers=headers)
        # Turn a 4xx/5xx into an exception so a rejected probe is never mistaken for a clean reply.
        response.raise_for_status()
        # Parse the body while the client is still open.
        data = response.json()
    # Dig out the assistant text with .get() defaults, so a 200 that omits message/content yields
    # "" instead of raising. Note an explicitly EMPTY "choices" list would still raise IndexError.
    text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    # Return the reply plus the metadata TargetClient records on the Evidence.
    return text, {"model": data.get("model", model), "status_code": response.status_code}


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
        allow_live: bool = False,
    ) -> None:
        # The authorized program whose scope every send is checked against.
        self.program = program
        # Minimum-interval limiter applied before each live send (the no-DoS guard).
        self.rate_limiter = rate_limiter
        # Append-only authorization log; every attempt is recorded, allowed or not.
        self.auth_log = auth_log
        # Injectable transport so tests never touch the network.
        self.transport = transport or openai_chat_transport
        # Model identifier recorded on captured Evidence.
        self.model = model
        # Whether this client may EVER send live traffic. Defaults to False so a caller that
        # does not think about it cannot send: the CLI passes `not settings.dry_run`, and any
        # library consumer must opt in deliberately and visibly at the construction site.
        self.allow_live = allow_live

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

        Step 0 below is the global kill-switch. It lives here rather than only in the CLI because
        this method is the single point every prompt passes through; a gate in a command can be
        routed around by the TUI, a future command, or any library consumer, which would leave
        the switch enforced somewhere other than where the documentation says it is.
        """
        # Step 0 - global kill-switch, before any scope or transport work.
        if live and not self.allow_live:
            # Record the refusal before raising. A denied attempt is part of the safe-harbor
            # artifact - the log's value comes from showing what was refused, not only what was
            # sent - and live=False records what actually happened, not what was asked for.
            self.auth_log.record(
                program=self.program.name,
                target=target,
                prompt=prompt,
                requested_live=True,
                live=False,
                allowed=False,
                reason="global dry-run is active (PROMPTSTRIKE_DRY_RUN); live traffic refused",
            )
            # Fail closed and loudly. Silently downgrading to a dry run would be worse: an
            # operator who believes they fired live probes and did not is exactly the failure
            # this gate exists to prevent.
            raise DryRunError(
                "live traffic refused: PROMPTSTRIKE_DRY_RUN is true (the safety default). "
                "Set PROMPTSTRIKE_DRY_RUN=false to permit live traffic."
            )

        # Step 1 - evaluate scope BEFORE any transport work. check() never sends anything itself,
        # so nothing has touched the network at this point regardless of the verdict.
        decision = check(self.program, target)
        # Step 2 - log the attempt. Denied attempts are logged too: the log's value as a
        # safe-harbor artifact comes from showing what was REFUSED, not only what was sent.
        self.auth_log.record(
            program=self.program.name,
            target=target,
            prompt=prompt,
            requested_live=live,
            # A denied --live attempt records live=false: what HAPPENED, not what was asked for.
            live=live and decision.allowed,
            allowed=decision.allowed,
            reason=decision.reason,
        )
        # Step 3 - refuse an out-of-scope target. Raising here means the transport below is
        # unreachable for anything the program did not authorize.
        if not decision.allowed:
            # ScopeError (not DryRunError): the fix is a scope registration, not an env setting.
            raise ScopeError(decision.reason)

        # Step 4 - the default path. `live` is False unless the caller opted in, so a forgotten
        # flag produces evidence with no network use rather than silent traffic.
        if not live:
            # Render-only: never touch the network.
            return Evidence(
                prompt=prompt,
                response="",
                model=self.model,
                # dry_run=True is recorded on the Evidence itself, so a rendered exchange can
                # never later be mistaken for a real one; the target is redacted before storage.
                metadata={"dry_run": True, "target": redact_target(target)},
            )

        # Step 5 - live. Pace first: the limiter is acquired before EVERY send, which is what
        # makes the no-DoS guard unconditional rather than a policy the caller has to remember.
        await self.rate_limiter.acquire()
        # Monotonic start stamp for the latency measurement below.
        send_started_at = time.monotonic()
        # The one and only outbound call in the tool - everything above had to pass to reach it.
        response_text, transport_metadata = await self.transport(prompt, target, self.program)
        # Round-trip time in milliseconds; reported in findings as reproduction detail.
        latency_ms = int((time.monotonic() - send_started_at) * 1000)
        # Capture the real exchange as the reproducibility artifact for any resulting finding.
        return Evidence(
            prompt=prompt,
            response=response_text,
            # Prefer the model the target actually answered with; fall back to the configured one.
            model=str(transport_metadata.get("model", self.model)),
            # Version is best-effort - most OpenAI-compatible targets do not report one.
            model_version=str(transport_metadata.get("model_version", "")),
            latency_ms=latency_ms,
            # Transport metadata is merged in, then dry_run/target are set last so a transport
            # cannot overwrite the dry-run marker or reinstate an unredacted target.
            metadata={**transport_metadata, "dry_run": False, "target": redact_target(target)},
        )
