"""Findings enriched from the vendored knowledge pack (increment 1).

Two rules are load-bearing here and are asserted rather than assumed:

* **Factual mappings auto-derive.** Framework ids for a category are lookups, not judgements, so a
  finding fills them in the same way ``_fill_cwe`` already fills CWEs.
* **Authored prose never auto-fills.** ``remediation`` feeds the submission-readiness checklist
  (``profiles._has_remediation``). Auto-filling it would make that check permanently green and
  destroy its signal, so the pack only ever *suggests* remediation.
"""

from __future__ import annotations

from promptstrike import knowledge
from promptstrike.models import Finding
from promptstrike.report.profiles import get_profile
from promptstrike.taxonomy import OwaspLLM


def _finding(**kw) -> Finding:
    base = {"program": "acme", "title": "Prompt injection in chat endpoint", "category": OwaspLLM.LLM01}
    return Finding(**{**base, **kw})


# --------------------------------------------------------------------------------------
# Factual mappings auto-derive
# --------------------------------------------------------------------------------------


def test_finding_derives_framework_refs_from_pack():
    f = _finding()
    assert f.framework_refs, "expected framework refs derived from the knowledge pack"
    assert f.refs("llmsvs"), "LLM01 should map to LLMSVS controls"


def test_derived_refs_match_the_pack_mapping():
    f = _finding(category=OwaspLLM.LLM06)
    expected = knowledge.pack().mapping_for(OwaspLLM.LLM06)
    assert f.refs("llmsvs") == expected.refs("llmsvs")


def test_explicit_refs_are_not_overwritten():
    """An operator who curated refs by hand keeps them."""
    f = _finding(framework_refs={"llmsvs": ["1.1"]})
    assert f.refs("llmsvs") == ["1.1"]


def test_refs_for_unmapped_framework_is_empty_not_error():
    assert _finding().refs("nonexistent") == []


def test_every_category_produces_resolvable_refs():
    """A ref that does not resolve would render a citation to a nonexistent control."""
    pack = knowledge.pack()
    for category in OwaspLLM:
        f = _finding(category=category)
        for fw_key, ids in f.framework_refs.items():
            for entry_id in ids:
                assert pack.entry(fw_key, entry_id) is not None, (
                    f"{category.value} cites {fw_key}:{entry_id}, which is not in the pack"
                )


# --------------------------------------------------------------------------------------
# Authored prose does not auto-fill
# --------------------------------------------------------------------------------------


def test_remediation_is_not_auto_filled():
    """Guards profiles._has_remediation: auto-filling would make the checklist item meaningless."""
    assert _finding().remediation == ""


def test_operator_remediation_is_preserved():
    assert _finding(remediation="Rotate the key.").remediation == "Rotate the key."


def test_readiness_checklist_still_flags_missing_remediation():
    """The end-to-end guarantee the previous test protects."""
    profile = get_profile("openai_h1")
    assert "Remediation suggested" in profile.missing(_finding())


def test_suggested_remediation_is_available_for_every_category():
    for category in OwaspLLM:
        assert knowledge.suggest_remediation(category).strip(), (
            f"{category.value} has no suggested remediation"
        )


def test_suggested_remediation_matches_the_pack():
    assert knowledge.suggest_remediation(OwaspLLM.LLM01) == (
        knowledge.pack().mapping_for(OwaspLLM.LLM01).remediation
    )


def test_applying_a_suggestion_satisfies_the_checklist():
    """The intended workflow: operator reviews the suggestion, accepts it, and it counts."""
    f = _finding(remediation=knowledge.suggest_remediation(OwaspLLM.LLM01))
    assert "Remediation suggested" not in get_profile("openai_h1").missing(f)


# --------------------------------------------------------------------------------------
# Backward compatibility with findings persisted before this change
# --------------------------------------------------------------------------------------


def test_legacy_finding_json_still_deserializes():
    """Findings were stored as JSON blobs; old rows have no framework_refs key."""
    legacy = (
        '{"id": 7, "program": "acme", "title": "Old finding", "category": "LLM01", '
        '"severity": "medium", "cwe": ["CWE-1427"], "status": "draft", '
        '"created_at": "2026-01-01T00:00:00Z"}'
    )
    f = Finding.model_validate_json(legacy)
    assert f.id == 7
    assert f.title == "Old finding"
    assert f.refs("llmsvs"), "a legacy finding should gain mappings on load"


def test_legacy_finding_round_trips_through_the_store(tmp_path):
    from promptstrike.storage import FindingStore

    with FindingStore(tmp_path / "findings.db") as store:
        fid = store.add(_finding())
        loaded = store.get(fid)

    assert loaded is not None
    assert loaded.refs("llmsvs") == _finding().refs("llmsvs")
