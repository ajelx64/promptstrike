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

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"  # CVSS "None" band / informational


def severity_from_score(score: float) -> Severity:
    """Map a 0.0–10.0 base score to the CVSS v3.1 qualitative band."""
    if score <= 0.0:
        return Severity.info
    if score < 4.0:
        return Severity.low
    if score < 7.0:
        return Severity.medium
    if score < 9.0:
        return Severity.high
    return Severity.critical


# --- CVSS v3.1 base metric coefficients (FIRST spec) -------------------------------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
# Privileges Required depends on Scope (Changed raises the L/H weights).
_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}
_V31_BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def parse_v31_vector(vector: str) -> dict[str, str]:
    """Parse a ``CVSS:3.x/...`` vector into a metric->value dict, validating required base metrics."""
    parts = vector.strip().split("/")
    if not parts or not parts[0].upper().startswith("CVSS:3"):
        raise ValueError(f"Not a CVSS v3.x vector: {vector!r}")
    metrics: dict[str, str] = {}
    for seg in parts[1:]:
        if ":" not in seg:
            raise ValueError(f"Malformed metric segment {seg!r} in {vector!r}")
        key, val = seg.split(":", 1)
        metrics[key.upper()] = val.upper()
    missing = [m for m in _V31_BASE_METRICS if m not in metrics]
    if missing:
        raise ValueError(f"Missing required base metrics {missing} in {vector!r}")
    return metrics


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A roundup: smallest one-decimal number >= value (float-safe)."""
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000.0
    return (math.floor(int_input / 10_000) + 1) / 10.0


def score_v31(vector: str) -> tuple[float, Severity]:
    """Return ``(base_score, severity)`` for a CVSS v3.1 vector. Raises ValueError on bad input."""
    m = parse_v31_vector(vector)
    scope = m["S"]
    if scope not in ("U", "C"):
        raise ValueError(f"Invalid Scope value {scope!r} in {vector!r}")
    try:
        av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
        pr = _PR[scope][m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError as exc:
        raise ValueError(f"Invalid metric value in {vector!r}: {exc}") from exc

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base = 0.0
    elif scope == "U":
        base = _roundup(min(impact + exploitability, 10.0))
    else:
        base = _roundup(min(1.08 * (impact + exploitability), 10.0))
    return base, severity_from_score(base)


# --- CVSS v4.0 (validate-only) -----------------------------------------------------------------
_V40_BASE_METRICS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")


def parse_v40_vector(vector: str) -> dict[str, str]:
    """Parse & validate a ``CVSS:4.0/...`` vector's base metrics. Does NOT compute a score."""
    parts = vector.strip().split("/")
    if not parts or not parts[0].upper().startswith("CVSS:4"):
        raise ValueError(f"Not a CVSS v4.0 vector: {vector!r}")
    metrics: dict[str, str] = {}
    for seg in parts[1:]:
        if ":" not in seg:
            raise ValueError(f"Malformed metric segment {seg!r} in {vector!r}")
        key, val = seg.split(":", 1)
        metrics[key.upper()] = val.upper()
    missing = [m for m in _V40_BASE_METRICS if m not in metrics]
    if missing:
        raise ValueError(f"Missing required v4.0 base metrics {missing} in {vector!r}")
    return metrics
