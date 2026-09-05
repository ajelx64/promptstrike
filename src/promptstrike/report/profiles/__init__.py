"""Platform submission profiles.

A profile maps a Finding to one venue's severity taxonomy and required-field checklist. The checklist
drives both the report's submission-readiness section and the T7 pre-submission linter.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from promptstrike.cvss import Severity
from promptstrike.models import Finding

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


@dataclass(frozen=True)
class ChecklistItem:
    """One line of a platform's submission-readiness checklist: a label and whether it passes."""

    label: str
    ok: bool


@dataclass(frozen=True)
class Profile:
    """One platform's severity taxonomy plus the required-field checks it expects on submission."""

    key: str
    display_name: str
    severity_scheme: str  # "named" | "vrt"
    required: tuple[tuple[str, Callable[[Finding], bool]], ...]

    def severity_label(self, finding: Finding) -> str:
        """Render ``finding``'s severity in this platform's own scheme (named tier or VRT band)."""
        table = _VRT if self.severity_scheme == "vrt" else _NAMED
        return table[finding.severity]

    def checklist(self, finding: Finding) -> list[ChecklistItem]:
        """Evaluate every required check against ``finding`` and return the pass/fail list."""
        return [ChecklistItem(label, pred(finding)) for label, pred in self.required]

    def missing(self, finding: Finding) -> list[str]:
        """Labels of the checklist items ``finding`` does not yet satisfy."""
        return [item.label for item in self.checklist(finding) if not item.ok]


def _has_title(f: Finding) -> bool:
    return len(f.title.strip()) >= 8


def _has_steps(f: Finding) -> bool:
    return len(f.steps_to_reproduce) > 0


def _has_evidence(f: Finding) -> bool:
    return len(f.evidence) > 0


def _has_impact(f: Finding) -> bool:
    return bool(f.impact.strip())


def _has_remediation(f: Finding) -> bool:
    return bool(f.remediation.strip())


def _has_cvss(f: Finding) -> bool:
    return f.cvss_v31_score is not None


def _has_cwe(f: Finding) -> bool:
    return len(f.cwe) > 0


def _has_model(f: Finding) -> bool:
    return bool(f.model.strip())


_COMMON: tuple[tuple[str, Callable[[Finding], bool]], ...] = (
    ("Specific, descriptive title", _has_title),
    ("Steps to reproduce present", _has_steps),
    ("Evidence / PoC transcript attached", _has_evidence),
    ("Impact stated", _has_impact),
    ("CVSS v3.1 score set", _has_cvss),
)


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
        return PROFILES["generic"]
    return PROFILES.get(key, PROFILES["generic"])
