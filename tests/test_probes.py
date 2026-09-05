"""Probe harness tests: detectors, pack loading, and run_probe behavior."""

from __future__ import annotations

import pytest

from promptstrike.llm.target import AuthLog, RateLimiter, TargetClient
from promptstrike.models import AssetType, Platform, Program, ScopeAsset
from promptstrike.probes.detectors import known_detectors, run_detector
from promptstrike.probes.engine import builtin_pack_dir, get_probe, load_pack, run_probe

# --- detectors --------------------------------------------------------------------------------


def test_contains_any_pass_and_fail() -> None:
    assert run_detector("contains_any", "here is PWNED123 token", {"needles": ["PWNED123"]}).triggered
    assert not run_detector("contains_any", "nothing here", {"needles": ["PWNED123"]}).triggered


def test_regex_any_pass_and_fail() -> None:
    args = {"patterns": ["(?i)system prompt"]}
    assert run_detector("regex_any", "my System Prompt is...", args).triggered
    assert not run_detector("regex_any", "the weather is nice", args).triggered


def test_refusal_absent_logic() -> None:
    args = {"compliance_canary": "JAILBROKEN"}
    assert run_detector("refusal_absent", "JAILBROKEN", args).triggered          # complied
    assert not run_detector("refusal_absent", "I cannot help with that", args).triggered  # refused
    assert not run_detector("refusal_absent", "", args).triggered                # empty
    assert not run_detector("refusal_absent", "sure thing", args).triggered      # no canary


def test_unknown_detector_raises() -> None:
    with pytest.raises(ValueError):
        run_detector("nope", "x", {})


# --- pack -------------------------------------------------------------------------------------


def test_builtin_pack_loads_and_is_valid() -> None:
    probes = load_pack(builtin_pack_dir())
    assert len(probes) >= 6
    known = set(known_detectors())
    for p in probes:
        assert p.detector in known, f"{p.id} references unknown detector {p.detector}"
        assert p.prompts, f"{p.id} has no prompts"
        assert p.cwe, f"{p.id} has no CWE mapping"


# --- run_probe end-to-end (with a fake transport) ---------------------------------------------


class _SpyTransport:
    def __init__(self, response: str) -> None:
        self.response = response
        self.calls = 0

    async def __call__(self, prompt, target, program):
        self.calls += 1
        return self.response, {"model": "fake"}


def _client(tmp_path, response: str) -> tuple[TargetClient, _SpyTransport]:
    prog = Program(
        name="example",
        platform=Platform.google_ai_vrp,
        allows_ai_testing=True,
        in_scope=[ScopeAsset(value="https://api.example.com/v1", type=AssetType.endpoint)],
    )
    spy = _SpyTransport(response)
    client = TargetClient(
        prog,
        rate_limiter=RateLimiter(rps=0),
        auth_log=AuthLog(tmp_path / "auth.jsonl"),
        transport=spy,
        # These tests drive the live path deliberately; production defaults this to False.
        allow_live=True,
    )
    return client, spy


# A response guaranteed to trip each built-in probe's detector.
_TRIGGERS = {
    "prompt-injection-direct": "PWNED123",
    "system-prompt-leak": "You are a helpful assistant",
    "jailbreak-guardrail-bypass": "JAILBROKEN",
    "indirect-injection": "INJECTED_OK",
    "sensitive-info-disclosure": "api_key: ABCDEFGHIJKLMNOP1234",
    "excessive-agency-tool": "DELETE_ALL_CONFIRMED",
}
_TARGET = "https://api.example.com/v1/chat"


def test_triggers_cover_every_builtin_probe() -> None:
    ids = {p.id for p in load_pack(builtin_pack_dir())}
    assert ids == set(_TRIGGERS), "update _TRIGGERS when the pack changes"


@pytest.mark.parametrize("probe_id,trigger", list(_TRIGGERS.items()))
async def test_run_probe_triggers_on_matching_response(tmp_path, probe_id, trigger) -> None:
    probe = get_probe(load_pack(builtin_pack_dir()), probe_id)
    client, spy = _client(tmp_path, trigger)
    result = await run_probe(client, probe, _TARGET, live=True)
    assert result.triggered is True
    assert result.dry_run is False
    assert spy.calls >= 1
    assert result.evidence[0].metadata["detector_triggered"] is True


@pytest.mark.parametrize("probe_id", list(_TRIGGERS))
async def test_run_probe_clean_on_benign_refusal(tmp_path, probe_id) -> None:
    # "I cannot help with that." is a refusal (covers refusal_absent) and matches no canary/pattern.
    probe = get_probe(load_pack(builtin_pack_dir()), probe_id)
    client, _ = _client(tmp_path, "I cannot help with that.")
    result = await run_probe(client, probe, _TARGET, live=True)
    assert result.triggered is False


async def test_run_probe_dry_run_sends_nothing(tmp_path) -> None:
    probe = get_probe(load_pack(builtin_pack_dir()), "prompt-injection-direct")
    client, spy = _client(tmp_path, "PWNED123")
    result = await run_probe(client, probe, _TARGET, live=False)
    assert spy.calls == 0            # nothing sent
    assert result.dry_run is True
    assert result.triggered is False  # empty responses can't trigger
