"""Platform submission profiles.

A profile maps a Finding to one venue's severity taxonomy and required-field checklist. The checklist
drives both the report's submission-readiness section and the T7 pre-submission linter.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from promptstrike.cvss import Severity
from promptstrike.models import Finding

# Human-readable severity labels for platforms that just want a named tier.
_NAMED = {
    Severity.critical: "Critical",
    Severity.high: "High",
    Severity.medium: "Medium",
    Severity.low: "Low",
    Severity.info: "Informational",
}
# Bugcrowd VRT priority bands.
_VRT = {
    Severity.critical: "P1",
    Severity.high: "P2",
    Severity.medium: "P3",
    Severity.low: "P4",
    Severity.info: "P5",
}


# Frozen: a checklist item is a plain immutable value handed straight to the report template.
@dataclass(frozen=True)
class ChecklistItem:
    """One line of a platform's submission-readiness checklist: a label and whether it passes."""

    label: str
    ok: bool


# Frozen: a Profile is static per-platform config, never mutated after it is built below.
@dataclass(frozen=True)
class Profile:
    """One platform's severity taxonomy plus the required-field checks it expects on submission."""

    key: str
    display_name: str
    severity_scheme: str  # "named" | "vrt"
    required: tuple[tuple[str, Callable[[Finding], bool]], ...]

    def severity_label(self, finding: Finding) -> str:
        """Render ``finding``'s severity in this platform's own scheme (named tier or VRT band)."""
        # Pick this platform's severity vocabulary: VRT priority bands or plain named tiers.
        table = _VRT if self.severity_scheme == "vrt" else _NAMED
        # Translate the finding's internal severity enum into that platform's label string.
        return table[finding.severity]

    def checklist(self, finding: Finding) -> list[ChecklistItem]:
        """Evaluate every required check against ``finding`` and return the pass/fail list."""
        # Run every required predicate now, so the template only ever reads pre-computed results.
        return [ChecklistItem(label, pred(finding)) for label, pred in self.required]

    def missing(self, finding: Finding) -> list[str]:
        """Labels of the checklist items ``finding`` does not yet satisfy."""
        # Only the failing labels, for prompting the operator on what to fix before submission.
        return [item.label for item in self.checklist(finding) if not item.ok]


def _has_title(f: Finding) -> bool:
    # Rejects blank/placeholder titles; 8 chars is a low bar, not a style requirement.
    return len(f.title.strip()) >= 8


def _has_steps(f: Finding) -> bool:
    # True once at least one reproduction step has been recorded.
    return len(f.steps_to_reproduce) > 0


def _has_evidence(f: Finding) -> bool:
    # True once at least one captured request/response transcript is attached.
    return len(f.evidence) > 0


def _has_impact(f: Finding) -> bool:
    # True once the operator has written a non-blank impact statement.
    return bool(f.impact.strip())


def _has_remediation(f: Finding) -> bool:
    # True once the operator has written non-blank remediation guidance.
    return bool(f.remediation.strip())


def _has_cvss(f: Finding) -> bool:
    # True once a CVSS v3.1 score has been computed for this finding.
    return f.cvss_v31_score is not None


def _has_cwe(f: Finding) -> bool:
    # True once at least one CWE id has been mapped to this finding.
    return len(f.cwe) > 0


def _has_model(f: Finding) -> bool:
    # True once the target model name/version has been recorded.
    return bool(f.model.strip())


# Checklist items every platform expects; each platform's tuple below extends this common base.
_COMMON: tuple[tuple[str, Callable[[Finding], bool]], ...] = (
    ("Specific, descriptive title", _has_title),
    ("Steps to reproduce present", _has_steps),
    ("Evidence / PoC transcript attached", _has_evidence),
    ("Impact stated", _has_impact),
    ("CVSS v3.1 score set", _has_cvss),
)


# Registry of platform submission profiles, keyed by the CLI's --platform value.
PROFILES: dict[str, Profile] = {
    "google_ai_vrp": Profile(
        "google_ai_vrp",
        "Google AI VRP",
        "named",
        _COMMON
        + (
            (
                "Valid attack scenario (impact + reproducible steps)",
                lambda f: _has_impact(f) and _has_steps(f),
            ),
        ),
    ),
    "openai_h1": Profile(
        "openai_h1",
        "OpenAI (HackerOne)",
        "named",
        _COMMON + (("CWE mapped", _has_cwe), ("Remediation suggested", _has_remediation)),
    ),
    "anthropic_h1": Profile(
        "anthropic_h1",
        "Anthropic (HackerOne)",
        "named",
        _COMMON + (("CWE mapped", _has_cwe), ("Remediation suggested", _has_remediation)),
    ),
    "msrc": Profile(
        "msrc",
        "Microsoft MSRC",
        "named",
        _COMMON + (("Product + version / model identified", _has_model),),
    ),
    "bugcrowd": Profile(
        "bugcrowd",
        "Bugcrowd",
        "vrt",
        _COMMON + (("CWE mapped", _has_cwe),),
    ),
    "generic": Profile("generic", "Generic", "named", _COMMON),
}


def get_profile(key: str | None) -> Profile:
    """Resolve a profile by key, falling back to the generic profile for unknown/blank keys."""
    if not key:
        # No platform specified: fall back to the generic profile rather than raising.
        return PROFILES["generic"]
    # Unknown keys also degrade to generic, since this key is often supplied straight from the CLI.
    return PROFILES.get(key, PROFILES["generic"])
