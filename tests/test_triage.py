"""Triage dedup + checklist-lint tests."""

from __future__ import annotations

from promptstrike.models import Finding
from promptstrike.report.profiles import get_profile
from promptstrike.taxonomy import OwaspLLM
from promptstrike.triage import dedupe, lint


def _f(id_: int, category: OwaspLLM, target: str) -> Finding:
    return Finding(id=id_, program="example", title="t" * 10, category=category, target=target)


def test_dedupe_flags_same_category_same_target_as_duplicate() -> None:
    new = _f(2, OwaspLLM.LLM01, "https://api.example.com/v1/chat")
    existing = [_f(1, OwaspLLM.LLM01, "https://api.example.com/v1/chat")]
    result = dedupe(new, existing)
    assert result.duplicates == [1]
    assert result.variants == []


def test_dedupe_flags_same_host_different_path_as_variant() -> None:
    new = _f(2, OwaspLLM.LLM01, "https://api.example.com/v1/chat")
    existing = [_f(1, OwaspLLM.LLM01, "https://api.example.com/v2/complete")]
    result = dedupe(new, existing)
    assert result.duplicates == []
    assert result.variants == [1]


def test_dedupe_ignores_other_categories_and_self() -> None:
    new = _f(2, OwaspLLM.LLM01, "https://api.example.com/v1/chat")
    existing = [
        _f(3, OwaspLLM.LLM07, "https://api.example.com/v1/chat"),  # different category
        _f(2, OwaspLLM.LLM01, "https://api.example.com/v1/chat"),  # self
    ]
    result = dedupe(new, existing)
    assert result.duplicates == []
    assert result.variants == []


def test_lint_returns_checklist_gaps() -> None:
    finding = _f(1, OwaspLLM.LLM01, "https://api.example.com/v1/chat")  # bare: no impact/steps/cvss
    gaps = lint(finding, get_profile("google_ai_vrp"))
    assert "Impact stated" in gaps
    assert "CVSS v3.1 score set" in gaps
