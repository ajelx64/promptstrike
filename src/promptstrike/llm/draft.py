"""AI-assisted report-narrative drafting via Claude.

Human-in-the-loop only: this drafts *narrative* fields (summary / impact / remediation / steps) from
the captured evidence — it never submits anything and never invents behavior not shown in the evidence.
The Anthropic client is lazily imported and injectable, so tests and offline use need neither the
`anthropic` package nor an API key. Model + call shape per the `claude-api` skill.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol

from promptstrike import taxonomy
from promptstrike.models import Finding

DRAFT_MODEL = "claude-opus-4-8"

_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "impact": {"type": "string"},
        "remediation": {"type": "string"},
        "steps_to_reproduce": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "impact", "remediation", "steps_to_reproduce"],
    "additionalProperties": False,
}

_SYSTEM = (
    "You are assisting an authorized bug-bounty researcher in drafting a vulnerability report for an "
    "AI/LLM security finding. Given the finding metadata and the captured request/response evidence, "
    "write a concise, factual, professional report narrative. Do NOT exaggerate impact or invent "
    "behavior not shown in the evidence. Provide a one-paragraph summary, an impact statement grounded "
    "strictly in the evidence, concrete reproduction steps, and remediation guidance. Return JSON only."
)


@dataclass
class DraftNarrative:
    """Narrative fields drafted by a :class:`Drafter`.

    Every field defaults empty rather than raising on a partial response, so
    :func:`apply_narrative` can merge whatever the model actually produced without special-casing
    a failed or truncated draft.
    """

    summary: str = ""
    impact: str = ""
    remediation: str = ""
    steps_to_reproduce: list[str] | None = None


class Drafter(Protocol):
    """The callable shape a narrative-drafting function must satisfy.

    Lets :func:`claude_drafter` be swapped for a deterministic test double or a different model
    without changing any caller's type.
    """

    def __call__(self, finding: Finding) -> DraftNarrative: ...


def _prompt(finding: Finding) -> str:
    lines = [
        f"Vulnerability: {finding.title}",
        f"OWASP-LLM category: {finding.category.value} ({taxonomy.title(finding.category)})",
        f"Target: {finding.target}",
        f"Model under test: {finding.model} {finding.model_version}".strip(),
        f"CVSS v3.1: {finding.cvss_v31_score} ({finding.cvss_v31_vector})",
        "",
        "Evidence transcript(s):",
    ]
    for i, ev in enumerate(finding.evidence, 1):
        lines.append(f"[{i}] PROMPT: {ev.prompt}")
        lines.append(f"[{i}] RESPONSE: {ev.response}")
    return "\n".join(lines)


def claude_drafter(finding: Finding, *, client=None, model: str = DRAFT_MODEL) -> DraftNarrative:
    """Draft narrative fields for a finding using Claude. Needs `anthropic` + ANTHROPIC_API_KEY."""
    if client is None:
        import anthropic  # lazy import — only required when actually drafting

        client = anthropic.Anthropic()  # resolves ANTHROPIC_API_KEY from the environment
    response = client.messages.create(
        model=model,
        max_tokens=2000,
        system=_SYSTEM,
        messages=[{"role": "user", "content": _prompt(finding)}],
        output_config={"format": {"type": "json_schema", "schema": _SCHEMA}},
    )
    text = next((b.text for b in response.content if b.type == "text"), "{}")
    data = json.loads(text)
    return DraftNarrative(
        summary=data.get("summary", ""),
        impact=data.get("impact", ""),
        remediation=data.get("remediation", ""),
        steps_to_reproduce=data.get("steps_to_reproduce") or None,
    )


def apply_narrative(finding: Finding, narrative: DraftNarrative) -> Finding:
    """Merge drafted narrative into a finding (only overwrites fields the drafter actually produced)."""
    if narrative.summary:
        finding.summary = narrative.summary
    if narrative.impact:
        finding.impact = narrative.impact
    if narrative.remediation:
        finding.remediation = narrative.remediation
    if narrative.steps_to_reproduce:
        finding.steps_to_reproduce = narrative.steps_to_reproduce
    return finding
