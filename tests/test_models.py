"""Core model validation + serialization tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from promptstrike.cvss import Severity
from promptstrike.models import (
    AssetType,
    Finding,
    FindingStatus,
    Probe,
    Program,
    ScopeAsset,
)
from promptstrike.taxonomy import OwaspLLM


def test_program_name_slugified_and_display_defaulted() -> None:
    p = Program(name="  Google-AI-VRP  ")
    assert p.name == "google-ai-vrp"
    assert p.display_name == "google-ai-vrp"  # defaults to name
    assert p.allows_ai_testing is False  # conservative default


def test_program_rejects_non_slug_name() -> None:
    with pytest.raises(ValidationError):
        Program(name="not a slug!")


def test_scope_asset_requires_value() -> None:
    with pytest.raises(ValidationError):
        ScopeAsset(value="   ")
    a = ScopeAsset(value="https://api.example.com", type=AssetType.endpoint)
    assert a.value == "https://api.example.com"


def test_probe_fills_default_cwe_from_category() -> None:
    probe = Probe(id="pi-basic", name="Basic PI", category=OwaspLLM.LLM01, detector="regex")
    assert probe.cwe == ["CWE-1427"]  # from taxonomy default for LLM01
    # explicit cwe is preserved
    probe2 = Probe(
        id="pi-2", name="x", category=OwaspLLM.LLM01, detector="regex", cwe=["CWE-999"]
    )
    assert probe2.cwe == ["CWE-999"]


def test_finding_applies_cvss_v31_score_and_severity() -> None:
    f = Finding(
        program="example",
        title="Prompt injection leaks system prompt",
        category=OwaspLLM.LLM01,
        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    assert f.cvss_v31_score == 9.8
    assert f.severity == Severity.critical
    assert f.status == FindingStatus.draft
    assert f.cwe == ["CWE-1427"]


def test_finding_validates_v40_vector() -> None:
    with pytest.raises(ValidationError):
        Finding(
            program="example",
            title="x",
            category=OwaspLLM.LLM01,
            cvss_v40_vector="CVSS:4.0/AV:N/AC:L",  # incomplete -> rejected
        )


def test_finding_round_trips_json() -> None:
    f = Finding(
        program="example",
        title="Excessive agency: tool abuse",
        category=OwaspLLM.LLM06,
        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    )
    restored = Finding.model_validate_json(f.model_dump_json())
    assert restored.title == f.title
    assert restored.cvss_v31_score == 5.3
    assert restored.category == OwaspLLM.LLM06
