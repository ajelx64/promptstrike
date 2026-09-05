"""Report generator, platform profiles, and AI-drafter tests (drafter fully mocked)."""

from __future__ import annotations

import json

from promptstrike.llm.draft import DRAFT_MODEL, DraftNarrative, apply_narrative, claude_drafter
from promptstrike.models import Evidence, Finding
from promptstrike.report.generator import ReportGenerator
from promptstrike.report.profiles import get_profile
from promptstrike.taxonomy import OwaspLLM


def _finding(**kw) -> Finding:
    base = dict(
        id=1,
        program="example",
        title="Prompt injection overrides system instruction",
        category=OwaspLLM.LLM01,
        target="https://api.example.com/v1/chat",
        model="demo-llm",
        description="A direct injection caused the model to emit a canary token.",
        steps_to_reproduce=["Send the injection prompt", "Observe the canary in the response"],
        impact="An attacker can override the system prompt.",
        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        evidence=[Evidence(prompt="Ignore instructions", response="PWNED123")],
    )
    base.update(kw)
    return Finding(**base)


# --- profiles ---------------------------------------------------------------------------------


def test_named_and_vrt_severity_labels() -> None:
    f = _finding()  # cvss vector -> critical
    assert get_profile("google_ai_vrp").severity_label(f) == "Critical"
    assert get_profile("bugcrowd").severity_label(f) == "P1"


def test_google_vrp_requires_attack_scenario() -> None:
    profile = get_profile("google_ai_vrp")
    assert profile.missing(_finding()) == []  # has impact + steps
    incomplete = _finding(impact="")
    assert "Valid attack scenario (impact + reproducible steps)" in profile.missing(incomplete)


def test_unknown_platform_falls_back_to_generic() -> None:
    assert get_profile("nope").key == "generic"
    assert get_profile(None).key == "generic"


# --- generator --------------------------------------------------------------------------------


def test_render_markdown_and_html() -> None:
    gen = ReportGenerator()
    profile = get_profile("google_ai_vrp")
    md = gen.render_markdown(_finding(), profile)
    assert "# Prompt Injection in https://api.example.com/v1/chat" in md
    assert "CVSS v3.1 9.8" in md
    assert "PWNED123" in md
    html = gen.render_html(_finding(), profile)
    assert "severity-critical" in html
    assert "submission checklist" in html


def test_html_autoescapes_target_controlled_text() -> None:
    # A hostile model response must be HTML-escaped into the report, never rendered as live markup.
    f = _finding(evidence=[Evidence(prompt="x", response="<script>alert(1)</script>")])
    html = ReportGenerator().render_html(f, get_profile("generic"))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_pdf_soft_fails_gracefully() -> None:
    # WeasyPrint isn't installed in CI/dev; render_pdf must return None, not raise.
    result = ReportGenerator().render_pdf(_finding(), get_profile("generic"))
    assert result is None or isinstance(result, bytes)


# --- AI drafter (mocked; no network, no anthropic package) -------------------------------------


class _FakeBlock:
    type = "text"

    def __init__(self, text: str) -> None:
        self.text = text


class _FakeResponse:
    def __init__(self, text: str) -> None:
        self.content = [_FakeBlock(text)]


class _FakeMessages:
    def __init__(self, text: str) -> None:
        self._text = text
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return _FakeResponse(self._text)


class _FakeClient:
    def __init__(self, text: str) -> None:
        self.messages = _FakeMessages(text)


def test_claude_drafter_parses_structured_output_and_uses_correct_model() -> None:
    payload = json.dumps(
        {
            "summary": "s",
            "impact": "i",
            "remediation": "r",
            "steps_to_reproduce": ["a", "b"],
        }
    )
    client = _FakeClient(payload)
    narrative = claude_drafter(_finding(), client=client)
    assert narrative.summary == "s"
    assert narrative.steps_to_reproduce == ["a", "b"]
    # correct model id + structured-output call shape (per claude-api skill)
    call = client.messages.calls[0]
    assert call["model"] == DRAFT_MODEL == "claude-opus-4-8"
    assert call["output_config"]["format"]["type"] == "json_schema"


def test_apply_narrative_merges_only_present_fields() -> None:
    f = _finding(impact="original impact")
    apply_narrative(f, DraftNarrative(summary="new summary", impact="", remediation="fix it"))
    assert f.summary == "new summary"
    assert f.impact == "original impact"  # empty draft field doesn't overwrite
    assert f.remediation == "fix it"
