"""Promote a probe run into a reportable :class:`Finding`.

Promotion assembles the structured skeleton (title, category, target, evidence, reproduction steps,
CWE/OWASP mapping) from a :class:`ProbeResult`. Narrative fields (impact, remediation) are left for the
operator or the AI-assisted drafter in the report stage — promotion never fabricates impact.
"""

from __future__ import annotations

from promptstrike import taxonomy
from promptstrike.cvss import Severity
from promptstrike.models import Finding, Platform, ProbeResult, Program


def _first_model(result: ProbeResult) -> str:
    return next((ev.model for ev in result.evidence if ev.model), "")


def _steps_from_evidence(result: ProbeResult) -> list[str]:
    steps = [f"Target endpoint: {result.target}"]
    for i, ev in enumerate(result.evidence, 1):
        steps.append(f"{i}. Send prompt: {ev.prompt!r}")
        if ev.response:
            snippet = " ".join(ev.response.split())
            if len(snippet) > 200:
                snippet = snippet[:200] + "..."
            steps.append(f"   Observed response: {snippet!r}")
    return steps


def _description(result: ProbeResult) -> str:
    name = taxonomy.title(result.category)
    return (
        f"Probe '{result.probe_id}' ({result.category.value} — {name}) was run against "
        f"{result.target}. Detector '{result.detector}' verdict: {result.detail}"
    )


def promote(
    result: ProbeResult,
    *,
    program: Program | None = None,
    title: str | None = None,
    cvss_v31_vector: str = "",
    platform: Platform | None = None,
    severity: Severity | None = None,
) -> Finding:
    """Build a draft :class:`Finding` from a probe run. A CVSS vector, if given, sets score+severity."""
    category = result.category
    resolved_platform = platform or (program.platform if program else Platform.other)
    finding = Finding(
        run_id=result.run_id,
        program=result.program,
        platform=resolved_platform,
        title=title or f"{taxonomy.title(category)} in {result.target}",
        category=category,
        target=result.target,
        model=_first_model(result),
        summary=result.detail,
        description=_description(result),
        steps_to_reproduce=_steps_from_evidence(result),
        evidence=list(result.evidence),
        cvss_v31_vector=cvss_v31_vector,
    )
    # An explicit severity applies only when a CVSS vector didn't already derive one.
    if severity is not None and not cvss_v31_vector:
        finding.severity = severity
    return finding
