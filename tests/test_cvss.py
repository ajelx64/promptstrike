"""CVSS v3.1 scoring + vector validation tests, with hand-verified fixtures."""

from __future__ import annotations

import pytest

from promptstrike.cvss import (
    Severity,
    parse_v40_vector,
    score_v31,
    severity_from_score,
)


@pytest.mark.parametrize(
    "vector,expected_score,expected_sev",
    [
        # Canonical "worst common web" — 9.8 Critical.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, Severity.critical),
        # Low-confidentiality info leak — 5.3 Medium.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, Severity.medium),
        # No impact — 0.0 / informational.
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0, Severity.info),
        # Scope-changed full impact — 10.0 Critical.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, Severity.critical),
    ],
)
def test_score_v31_fixtures(vector: str, expected_score: float, expected_sev: Severity) -> None:
    score, sev = score_v31(vector)
    assert score == expected_score
    assert sev == expected_sev


def test_score_v31_is_case_insensitive() -> None:
    lower = "cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h"
    assert score_v31(lower)[0] == 9.8


@pytest.mark.parametrize(
    "bad",
    [
        "CVSS:2.0/AV:N/AC:L",                       # wrong version
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # invalid AV value
        "not-a-vector",
    ],
)
def test_score_v31_rejects_bad_vectors(bad: str) -> None:
    with pytest.raises(ValueError):
        score_v31(bad)


@pytest.mark.parametrize(
    "score,band",
    [
        (0.0, Severity.info),
        (3.9, Severity.low),
        (4.0, Severity.medium),
        (6.9, Severity.medium),
        (7.0, Severity.high),
        (8.9, Severity.high),
        (9.0, Severity.critical),
        (10.0, Severity.critical),
    ],
)
def test_severity_bands(score: float, band: Severity) -> None:
    assert severity_from_score(score) == band


def test_parse_v40_valid_and_missing() -> None:
    ok = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    metrics = parse_v40_vector(ok)
    assert metrics["VC"] == "H" and metrics["AT"] == "N"
    with pytest.raises(ValueError):
        parse_v40_vector("CVSS:4.0/AV:N/AC:L")  # missing base metrics
    with pytest.raises(ValueError):
        parse_v40_vector("CVSS:3.1/AV:N")  # wrong version
