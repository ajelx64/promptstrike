"""Tests for the vendored AI-security knowledge pack.

Two distinct concerns, deliberately kept apart:

* **Loader mechanics** are tested against a synthetic fixture pack written to ``tmp_path``. Fast,
  deterministic, and unaffected by curation changes — these tests describe the *contract*.
* **Pack integrity** is tested against the real shipped pack. These catch curation mistakes (a
  dangling mapping reference, a source missing its license, a duplicated ID) that a fixture never
  would. They are the reason a bad copy-paste can't reach a generated report.
"""

from __future__ import annotations

from datetime import date

import pytest
import yaml

from promptstrike import knowledge
from promptstrike.taxonomy import OwaspLLM

# --------------------------------------------------------------------------------------
# Fixture pack — the minimum shape a pack must have.
# --------------------------------------------------------------------------------------

_FIXTURE_MANIFEST = {
    "pack_version": "0.0.1-test",
    "sources": [
        {
            "key": "demo",
            "name": "Demo Framework",
            "version": "1.0",
            "url": "https://example.invalid/demo",
            "license": "CC BY-SA 4.0",
            "attribution": "Demo Framework, used under CC BY-SA 4.0.",
            "retrieved": "2026-07-20",
        }
    ],
}

_FIXTURE_DEMO = {
    "entries": [
        {"id": "D01", "title": "First Thing", "description": "The first demo entry."},
        {"id": "D02", "title": "Second Thing", "description": "The second demo entry."},
        {
            "id": "D02.000",
            "title": "Second Thing Sub",
            "description": "A sub-entry.",
            "parent": "D02",
        },
    ]
}

_FIXTURE_MAPPINGS = {
    "LLM01": {"demo": ["D01"], "remediation": "Constrain the prompt boundary."},
    "LLM07": {"demo": ["D02"]},
}


def _write_pack(root, *, manifest=None, demo=None, mappings=None):
    """Materialise a pack on disk; returns the pack root."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "MANIFEST.yaml").write_text(
        yaml.safe_dump(manifest if manifest is not None else _FIXTURE_MANIFEST),
        encoding="utf-8",
    )
    (root / "demo.yaml").write_text(
        yaml.safe_dump(demo if demo is not None else _FIXTURE_DEMO), encoding="utf-8"
    )
    (root / "mappings.yaml").write_text(
        yaml.safe_dump(mappings if mappings is not None else _FIXTURE_MAPPINGS),
        encoding="utf-8",
    )
    return root


@pytest.fixture
def fixture_pack(tmp_path):
    return knowledge.load_pack(_write_pack(tmp_path / "pack"))


# --------------------------------------------------------------------------------------
# Loader mechanics
# --------------------------------------------------------------------------------------


def test_load_pack_reads_sources_and_entries(fixture_pack):
    fw = fixture_pack.framework("demo")
    assert fw.source.name == "Demo Framework"
    assert fw.source.license == "CC BY-SA 4.0"
    assert fw.source.retrieved == date(2026, 7, 20)
    assert len(fw.entries) == 3


def test_entry_lookup_by_id(fixture_pack):
    entry = fixture_pack.entry("demo", "D01")
    assert entry is not None
    assert entry.title == "First Thing"


def test_entry_lookup_returns_none_for_unknown_id(fixture_pack):
    assert fixture_pack.entry("demo", "NOPE") is None


def test_unknown_framework_raises(fixture_pack):
    with pytest.raises(KeyError):
        fixture_pack.framework("does-not-exist")


def test_sub_entry_records_parent(fixture_pack):
    assert fixture_pack.entry("demo", "D02.000").parent == "D02"
    assert fixture_pack.entry("demo", "D02").parent is None


def test_mapping_resolves_category_to_entries(fixture_pack):
    mapping = fixture_pack.mapping_for(OwaspLLM.LLM01)
    assert mapping.refs("demo") == ["D01"]
    assert mapping.remediation == "Constrain the prompt boundary."


def test_mapping_for_unmapped_category_is_empty_not_error(fixture_pack):
    """An unmapped category must degrade to empty, never raise — reports still render."""
    mapping = fixture_pack.mapping_for(OwaspLLM.LLM09)
    assert mapping.refs("demo") == []
    assert mapping.remediation == ""


def test_search_matches_title_and_description(fixture_pack):
    hits = fixture_pack.search("first")
    assert [(h.framework, h.entry.id) for h in hits] == [("demo", "D01")]


def test_search_is_case_insensitive(fixture_pack):
    assert fixture_pack.search("FIRST THING")


def test_search_can_scope_to_frameworks(fixture_pack):
    assert fixture_pack.search("thing", frameworks=["demo"])
    assert fixture_pack.search("thing", frameworks=["other"]) == []


def test_attributions_lists_every_source(fixture_pack):
    attributions = fixture_pack.attributions()
    assert any("Demo Framework" in a for a in attributions)
    assert len(attributions) == len(fixture_pack.frameworks)


def test_duplicate_ids_are_rejected(tmp_path):
    """A duplicated ID silently shadows an entry — refuse to load rather than mis-cite."""
    dupe = {"entries": [{"id": "D01", "title": "A"}, {"id": "D01", "title": "B"}]}
    root = _write_pack(tmp_path / "dupe", demo=dupe, mappings={})
    with pytest.raises(ValueError, match="duplicate"):
        knowledge.load_pack(root)


def test_mapping_referencing_unknown_entry_is_rejected(tmp_path):
    """A dangling reference would render a citation to an ID that does not exist."""
    root = _write_pack(tmp_path / "dangling", mappings={"LLM01": {"demo": ["GHOST"]}})
    with pytest.raises(ValueError, match="GHOST"):
        knowledge.load_pack(root)


def test_mapping_referencing_unknown_framework_is_rejected(tmp_path):
    root = _write_pack(tmp_path / "badfw", mappings={"LLM01": {"nosuch": ["D01"]}})
    with pytest.raises(ValueError, match="nosuch"):
        knowledge.load_pack(root)


def test_mapping_with_unknown_category_is_rejected(tmp_path):
    root = _write_pack(tmp_path / "badcat", mappings={"LLM99": {"demo": ["D01"]}})
    with pytest.raises(ValueError, match="LLM99"):
        knowledge.load_pack(root)


def test_misspelled_entry_key_is_rejected(tmp_path):
    """`extra="forbid"`: a curation typo must fail loudly, not silently drop the field."""
    typo = {"entries": [{"id": "D01", "title": "A", "parnet": "D02"}]}
    root = _write_pack(tmp_path / "typo", demo=typo, mappings={})
    with pytest.raises(ValueError, match="parnet"):
        knowledge.load_pack(root)


def test_misspelled_source_key_is_rejected(tmp_path):
    manifest = {
        "pack_version": "0.0.1-test",
        "sources": [{**_FIXTURE_MANIFEST["sources"][0], "licence": "CC0"}],
    }
    root = _write_pack(tmp_path / "srctypo", manifest=manifest, mappings={})
    with pytest.raises(ValueError, match="licence"):
        knowledge.load_pack(root)


def test_framework_file_with_no_entries_is_rejected(tmp_path):
    """A mis-keyed `entires:` would otherwise load as a valid-but-empty framework."""
    root = _write_pack(tmp_path / "empty", demo={"entires": []}, mappings={})
    with pytest.raises(ValueError, match="no entries"):
        knowledge.load_pack(root)


def test_unknown_tactic_reference_is_rejected(tmp_path):
    """A tactic that resolves to nothing would render as a bare id in a report."""
    bad = {"entries": [{"id": "D01", "title": "A", "tactics": ["TA-GHOST"]}]}
    root = _write_pack(tmp_path / "tactic", demo=bad, mappings={})
    with pytest.raises(ValueError, match="TA-GHOST"):
        knowledge.load_pack(root)


def test_unverified_source_without_note_is_rejected(tmp_path):
    manifest = {
        "pack_version": "0.0.1-test",
        "sources": [{**_FIXTURE_MANIFEST["sources"][0], "verified": False}],
    }
    root = _write_pack(tmp_path / "unverifiedsrc", manifest=manifest, mappings={})
    with pytest.raises(ValueError, match="unverified"):
        knowledge.load_pack(root)


def test_source_without_license_is_rejected(tmp_path):
    """Attribution is a division rule; a source with no license must not ship."""
    manifest = {
        "pack_version": "0.0.1-test",
        "sources": [
            {
                "key": "demo",
                "name": "Demo",
                "url": "https://example.invalid/demo",
                "license": "",
                "attribution": "x",
                "retrieved": "2026-07-20",
            }
        ],
    }
    root = _write_pack(tmp_path / "nolicense", manifest=manifest, mappings={})
    with pytest.raises(ValueError, match="license"):
        knowledge.load_pack(root)


def test_data_file_without_manifest_source_is_rejected(tmp_path):
    """Every shipped data file must declare provenance."""
    root = _write_pack(tmp_path / "orphan", mappings={})
    (root / "orphan.yaml").write_text(
        yaml.safe_dump({"entries": [{"id": "X1", "title": "x"}]}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="orphan"):
        knowledge.load_pack(root)


def test_pack_is_cached(tmp_path):
    """The default pack loads once; repeated access must not re-read from disk."""
    assert knowledge.pack() is knowledge.pack()


# --------------------------------------------------------------------------------------
# Integrity of the real shipped pack
# --------------------------------------------------------------------------------------


def test_real_pack_loads():
    assert knowledge.pack().frameworks


@pytest.mark.parametrize(
    "key", ["owasp_llm", "owasp_agentic", "atlas", "llmsvs", "aidefend"]
)
def test_real_pack_ships_expected_framework(key):
    fw = knowledge.pack().framework(key)
    assert fw.entries, f"{key} has no entries"


def test_every_real_source_carries_provenance():
    for fw in knowledge.pack().frameworks.values():
        src = fw.source
        assert src.url.startswith("http"), f"{src.key} has no source URL"
        assert src.license, f"{src.key} has no license"
        assert src.attribution, f"{src.key} has no attribution string"
        assert src.retrieved, f"{src.key} has no retrieval date"


def test_owasp_llm_pack_matches_the_taxonomy_enum():
    """The pack must stay in lockstep with the public enum other modules import."""
    ids = {e.id.split(":")[0] for e in knowledge.pack().framework("owasp_llm").entries}
    assert ids == {c.value for c in OwaspLLM}


def test_every_owasp_llm_category_has_a_mapping():
    """A category with no mapping silently produces an unenriched report."""
    pack = knowledge.pack()
    unmapped = [c.value for c in OwaspLLM if pack.mapping_for(c).is_empty()]
    assert not unmapped, f"categories with no framework mapping: {unmapped}"


def test_real_atlas_tactics_resolve_to_titles():
    """Techniques cite tactic ids; those must be lookup-able or reports render bare ids."""
    pack = knowledge.pack()
    injection = pack.entry("atlas", "AML.T0051")
    assert injection is not None and injection.tactics
    for tactic_id in injection.tactics:
        tactic = pack.entry("atlas", tactic_id)
        assert tactic is not None and tactic.title, f"{tactic_id} does not resolve"
    assert pack.entry("atlas", "AML.TA0005").title == "Execution"


def test_unverified_entries_are_flagged_not_hidden():
    """Entries whose upstream wording could not be confirmed must self-declare."""
    for fw in knowledge.pack().frameworks.values():
        for entry in fw.entries:
            if not entry.verified:
                assert entry.source_note, (
                    f"{fw.source.key}:{entry.id} is unverified but explains nothing"
                )
