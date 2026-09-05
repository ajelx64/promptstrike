"""Pre-submission triage: dedup a finding against local history + lint it against a platform checklist.

Deliberately local-only — no platform API calls. The goal is to stop *you* from submitting a duplicate
or an incomplete report, which is the single biggest driver of rejections and reputation damage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from promptstrike.models import Finding
from promptstrike.report.profiles import Profile


def _norm_target(target: str) -> str:
    t = target.strip().lower()
    if "://" in t:
        u = urlparse(t)
        return f"{u.hostname or ''}{(u.path or '').rstrip('/')}"
    return t.rstrip("/")


def _host(target: str) -> str:
    t = target.strip().lower()
    if "://" in t:
        return urlparse(t).hostname or ""
    return t.split("/", 1)[0]


@dataclass
class DedupResult:
    """Result of :func:`dedupe`: prior finding ids that look like duplicates or same-host variants."""

    duplicates: list[int] = field(default_factory=list)  # same category + same target
    variants: list[int] = field(default_factory=list)  # same category + same host, different target


def dedupe(new: Finding, existing: list[Finding]) -> DedupResult:
    """Flag prior findings that look like duplicates (same category+target) or variants (same host)."""
    result = DedupResult()
    new_target = _norm_target(new.target)
    new_host = _host(new.target)
    for f in existing:
        if f.id is None or f.id == new.id:
            continue
        if f.category != new.category:
            continue
        if _norm_target(f.target) == new_target:
            result.duplicates.append(f.id)
        elif new_host and _host(f.target) == new_host:
            result.variants.append(f.id)
    return result


def lint(finding: Finding, profile: Profile) -> list[str]:
    """Return the platform-checklist items this finding does not yet satisfy."""
    return profile.missing(finding)
