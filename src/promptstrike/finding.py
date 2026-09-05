"""Promote a probe run into a reportable :class:`Finding`.

Promotion assembles the structured skeleton (title, category, target, evidence, reproduction steps,
CWE/OWASP mapping) from a :class:`ProbeResult`. Narrative fields (impact, remediation) are left for the
operator or the AI-assisted drafter in the report stage — promotion never fabricates impact.
"""

from __future__ import annotations

from promptstrike import taxonomy
from promptstrike.cvss import Severity
from promptstrike.llm.target import redact_target
from promptstrike.models import Finding, Platform, ProbeResult, Program


def _first_model(result: ProbeResult) -> str:
    # First evidence entry that recorded a model name, else "" when none did (dry runs do not).
    return next((entry.model for entry in result.evidence if entry.model), "")


def _steps_from_evidence(result: ProbeResult) -> list[str]:
    # Numbered reproduction steps always start by naming the target that was probed.
    # Redacted, because these steps are rendered into the report that is SUBMITTED to a
    # third-party program - a target written with inline credentials would disclose the
    # operator's own secrets to that program.
    steps = [f"Target endpoint: {redact_target(result.target)}"]
    # Number each evidence entry as one reproduction step, in the order prompts were sent.
    for step_number, evidence_entry in enumerate(result.evidence, 1):
        # Record exactly which prompt was sent at this step.
        steps.append(f"{step_number}. Send prompt: {evidence_entry.prompt!r}")
        # Only add an "Observed response" line when the target returned one (dry runs won't).
        if evidence_entry.response:
            # Collapse whitespace/newlines so one response renders as a single reproduction line.
            snippet = " ".join(evidence_entry.response.split())
            # Truncate long responses so the reproduction steps stay readable.
            if len(snippet) > 200:
                snippet = snippet[:200] + "..."
            # Attach the (possibly truncated) response snippet under its prompt.
            steps.append(f"   Observed response: {snippet!r}")
    # Hand back the full ordered list of reproduction-step strings.
    return steps


def _description(result: ProbeResult) -> str:
    # Resolve the human-readable OWASP category title for the description text.
    name = taxonomy.title(result.category)
    # Build the finding's narrative description from the probe run's recorded facts only.
    return (
        f"Probe '{result.probe_id}' ({result.category.value} — {name}) was run against "
        f"{redact_target(result.target)}. Detector '{result.detector}' verdict: {result.detail}"
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
    # Carry the probe's OWASP-LLM category straight through onto the finding.
    category = result.category
    # Prefer an explicit platform override, else fall back to the program's platform, else "other".
    resolved_platform = platform or (program.platform if program else Platform.other)
    # Assemble the structured finding skeleton; narrative fields are intentionally left for later.
    finding = Finding(
        run_id=result.run_id,
        program=result.program,
        platform=resolved_platform,
        # Redacted like every other consumer of the target. This line is why the auto-
        # generated title used to carry credentials into the HTML and PDF reports while the
        # `target` field three lines below was clean.
        title=title or f"{taxonomy.title(category)} in {redact_target(result.target)}",
        category=category,
        # Redacted at promotion. Every field derived from the target is redacted the same
        # way - title, description and reproduction steps above - so no downstream consumer
        # reconstructs the credential form from any of them. Note the redactor removes
        # userinfo, secret-bearing query/fragment values and known credential prefixes; it
        # is not a guarantee against a secret embedded in an arbitrary path segment.
        target=redact_target(result.target),
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
    # Return the assembled draft finding for the operator (or report stage) to refine further.
    return finding
