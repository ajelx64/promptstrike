"""CVSS scoring.

CVSS **v3.1** base scores are computed here per the official FIRST specification — this is the
scoring system HackerOne, Bugcrowd, and Microsoft MSRC use in practice, so it is what our reports
lead with.

CVSS **v4.0** vectors are *parsed and validated* but deliberately NOT scored: the v4.0 base score
uses a 270-entry MacroVector interpolation table that is error-prone to reproduce by hand, and a
subtly-wrong score in a submitted report damages researcher credibility more than an absent one. We
record the validated v4.0 vector for reference and point to FIRST's authoritative calculator. See the
project plan's "Risks & open items" for the rationale.
"""

from __future__ import annotations

import math
from enum import Enum


class Severity(str, Enum):
    """CVSS v3.1 qualitative severity band — also used as a probe's pre-scoring severity hint."""

    critical = "critical"  # CVSS base score 9.0-10.0
    high = "high"  # CVSS base score 7.0-8.9
    medium = "medium"  # CVSS base score 4.0-6.9
    low = "low"  # CVSS base score 0.1-3.9
    info = "info"  # CVSS "None" band / informational


def severity_from_score(score: float) -> Severity:
    """Map a 0.0–10.0 base score to the CVSS v3.1 qualitative band."""
    # A score of exactly 0.0 has no exploitable impact under CVSS v3.1 — informational only.
    if score <= 0.0:
        return Severity.info
    # 0.1-3.9 is the CVSS v3.1 "Low" severity band.
    if score < 4.0:
        return Severity.low
    # 4.0-6.9 is the CVSS v3.1 "Medium" severity band.
    if score < 7.0:
        return Severity.medium
    # 7.0-8.9 is the CVSS v3.1 "High" severity band.
    if score < 9.0:
        return Severity.high
    # 9.0-10.0 is the CVSS v3.1 "Critical" severity band.
    return Severity.critical


# --- CVSS v3.1 base metric coefficients (FIRST spec) -------------------------------------------
# Attack Vector (AV) weights: Network > Adjacent > Local > Physical.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
# Attack Complexity (AC) weights: Low > High.
_AC = {"L": 0.77, "H": 0.44}
# User Interaction (UI) weights: None > Required.
_UI = {"N": 0.85, "R": 0.62}
# Confidentiality/Integrity/Availability (C/I/A) impact weights: High > Low > None.
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
# Privileges Required depends on Scope (Changed raises the L/H weights).
_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}
# The eight base metrics every CVSS v3.1 vector must declare, used to validate a parsed vector.
_V31_BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def parse_v31_vector(vector: str) -> dict[str, str]:
    """Parse a ``CVSS:3.x/...`` vector into a metric->value dict, validating required base metrics."""
    # Split on "/" — a v3.1 vector is "CVSS:3.x" followed by "METRIC:VALUE" segments.
    parts = vector.strip().split("/")
    # The first segment must identify this as a CVSS v3.x vector before we parse further.
    if not parts or not parts[0].upper().startswith("CVSS:3"):
        raise ValueError(f"Not a CVSS v3.x vector: {vector!r}")
    # Collects each METRIC:VALUE pair found after the "CVSS:3.x" prefix.
    metrics: dict[str, str] = {}
    # Walk every segment after the version prefix.
    for segment in parts[1:]:
        # Each segment must be a "METRIC:VALUE" pair — reject anything else outright.
        if ":" not in segment:
            raise ValueError(f"Malformed metric segment {segment!r} in {vector!r}")
        # Split once on ":" so a value that itself contains a colon is preserved intact.
        key, value = segment.split(":", 1)
        # Normalize to uppercase so lookups against the coefficient tables above always hit.
        metrics[key.upper()] = value.upper()
    # Find which of the eight required base metrics the vector never declared.
    missing = [metric_key for metric_key in _V31_BASE_METRICS if metric_key not in metrics]
    # A vector missing any required base metric cannot be scored — fail loudly here.
    if missing:
        raise ValueError(f"Missing required base metrics {missing} in {vector!r}")
    # Hand back the normalized metric->value mapping for score_v31 to consume.
    return metrics


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A roundup: smallest one-decimal number >= value (float-safe)."""
    # Scale to an integer to avoid binary floating-point rounding errors in the comparison below.
    int_input = round(value * 100_000)
    # Already exact at one decimal place (e.g. 4.30000) — no rounding up needed.
    if int_input % 10_000 == 0:
        return int_input / 100_000.0
    # Otherwise round UP to the next one-decimal value, per Appendix A's roundup definition.
    return (math.floor(int_input / 10_000) + 1) / 10.0


def score_v31(vector: str) -> tuple[float, Severity]:
    """Return ``(base_score, severity)`` for a CVSS v3.1 vector. Raises ValueError on bad input."""
    # Parse and validate the vector's base metrics before touching any spec arithmetic.
    metrics = parse_v31_vector(vector)
    # Scope (S) gates which formula branch and which PR weight table apply below.
    scope = metrics["S"]
    # Scope only has two legal values in CVSS v3.1: Unchanged or Changed.
    if scope not in ("U", "C"):
        raise ValueError(f"Invalid Scope value {scope!r} in {vector!r}")
    try:
        # Look up the Attack Vector / Attack Complexity / User Interaction coefficients.
        av, ac, ui = _AV[metrics["AV"]], _AC[metrics["AC"]], _UI[metrics["UI"]]
        # Privileges Required is looked up under the Scope-specific weight table.
        pr = _PR[scope][metrics["PR"]]
        # Look up the Confidentiality / Integrity / Availability impact coefficients.
        c, i, a = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]
    except KeyError as exc:
        # A metric value missing from its coefficient table means an invalid vector, not a bug here.
        raise ValueError(f"Invalid metric value in {vector!r}: {exc}") from exc

    # Impact Sub-Score (ISS): the combined C/I/A impact per the spec's formula.
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        # Unchanged-scope Impact formula.
        impact = 6.42 * iss
    else:
        # Changed-scope Impact formula uses different constants than the Unchanged-scope one.
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    # Exploitability sub-score combines AV/AC/PR/UI per the spec's fixed 8.22 coefficient.
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        # No impact on C/I/A at all means a base score of exactly 0.0, per the spec.
        base = 0.0
    elif scope == "U":
        # Unchanged-scope base score: Impact + Exploitability, capped at 10.0, then rounded up.
        base = _roundup(min(impact + exploitability, 10.0))
    else:
        # Changed-scope base score applies the 1.08 multiplier before capping and rounding up.
        base = _roundup(min(1.08 * (impact + exploitability), 10.0))
    # Translate the numeric base score into its qualitative severity band for the caller.
    return base, severity_from_score(base)


# --- CVSS v4.0 (validate-only) -----------------------------------------------------------------
# The eleven base metrics every CVSS v4.0 vector must declare, used only for structural validation.
_V40_BASE_METRICS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")


def parse_v40_vector(vector: str) -> dict[str, str]:
    """Parse & validate a ``CVSS:4.0/...`` vector's base metrics. Does NOT compute a score."""
    # Split on "/" — a v4.0 vector is "CVSS:4.0" followed by "METRIC:VALUE" segments.
    parts = vector.strip().split("/")
    # The first segment must identify this as a CVSS v4.0 vector before we parse further.
    if not parts or not parts[0].upper().startswith("CVSS:4"):
        raise ValueError(f"Not a CVSS v4.0 vector: {vector!r}")
    # Collects each METRIC:VALUE pair found after the "CVSS:4.0" prefix.
    metrics: dict[str, str] = {}
    # Walk every segment after the version prefix.
    for segment in parts[1:]:
        # Each segment must be a "METRIC:VALUE" pair — reject anything else outright.
        if ":" not in segment:
            raise ValueError(f"Malformed metric segment {segment!r} in {vector!r}")
        # Split once on ":" so a value that itself contains a colon is preserved intact.
        key, value = segment.split(":", 1)
        # Normalize to uppercase for consistency with the v3.1 parser above.
        metrics[key.upper()] = value.upper()
    # Find which of the eleven required base metrics the vector never declared.
    missing = [metric_key for metric_key in _V40_BASE_METRICS if metric_key not in metrics]
    # A vector missing any required base metric fails validation — this function never scores it.
    if missing:
        raise ValueError(f"Missing required v4.0 base metrics {missing} in {vector!r}")
    # Hand back the normalized metric->value mapping, for reference/display only (never scored).
    return metrics
