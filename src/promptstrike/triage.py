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
    # Case-fold and trim so "HTTPS://Foo/" and "https://foo" compare equal.
    t = target.strip().lower()
    if "://" in t:
        # A URL-shaped target: compare by host + path, ignoring scheme/query/fragment differences.
        u = urlparse(t)
        return f"{u.hostname or ''}{(u.path or '').rstrip('/')}"
    # A bare host/path target (no scheme) — just strip any trailing slash.
    return t.rstrip("/")


def _host(target: str) -> str:
    # Case-fold and trim, same rationale as _norm_target above.
    t = target.strip().lower()
    if "://" in t:
        # A URL-shaped target: the host is whatever urlparse extracts.
        return urlparse(t).hostname or ""
    # A bare host/path target: the host is everything before the first "/".
    return t.split("/", 1)[0]


@dataclass
class DedupResult:
    """Result of :func:`dedupe`: prior finding ids that look like duplicates or same-host variants."""

    duplicates: list[int] = field(default_factory=list)  # same category + same target
    variants: list[int] = field(default_factory=list)  # same category + same host, different target


def dedupe(new: Finding, existing: list[Finding]) -> DedupResult:
    """Flag prior findings that look like duplicates (same category+target) or variants (same host)."""
    # Accumulates the duplicate and variant prior-finding ids as we scan.
    result = DedupResult()
    # Normalize the new finding's target once, for comparison against every prior finding.
    new_target = _norm_target(new.target)
    # Extract the new finding's host once too, for the looser same-host variant check.
    new_host = _host(new.target)
    for prior_finding in existing:
        # Skip findings that were never persisted (no id) and skip comparing the finding to itself.
        if prior_finding.id is None or prior_finding.id == new.id:
            continue
        # A different OWASP-LLM category rules out both duplicate and variant for this pair.
        if prior_finding.category != new.category:
            continue
        if _norm_target(prior_finding.target) == new_target:
            # Same category and the same normalized target — this looks like an exact duplicate.
            result.duplicates.append(prior_finding.id)
        elif new_host and _host(prior_finding.target) == new_host:
            # Same category and host, but a different target — likely a variant, not a duplicate.
            result.variants.append(prior_finding.id)
    # Hand back everything flagged as a likely duplicate or variant of the new finding.
    return result


def lint(finding: Finding, profile: Profile) -> list[str]:
    """Return the platform-checklist items this finding does not yet satisfy."""
    # Delegate to the platform profile, which owns its own submission-checklist logic. This module
    # makes no platform API calls of its own — dedup and lint are both purely local-history checks.
    return profile.missing(finding)
