"""Data contracts for the vendored knowledge pack.

The pack is a set of reference frameworks (OWASP LLM/Agentic Top 10, MITRE ATLAS, LLMSVS, AIDEFEND)
plus a mapping from our own OWASP-LLM category to entries in those frameworks. Everything a report
cites must be traceable to a source recorded in ``MANIFEST.yaml`` — provenance is a hard requirement,
not metadata, because these IDs end up in vulnerability reports read by third parties.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from pydantic import BaseModel, ConfigDict, Field

# Curation-facing models forbid unknown keys. With pydantic's default (`extra="ignore"`) a typo in
# hand-curated YAML — `parnet:` for `parent:`, `soruce_note:` for `source_note:` — would be silently
# dropped and the entry would load looking valid. That defeats the entire point of a loader whose job
# is to turn a curation slip into a failing test rather than a bad citation in a report.
_STRICT = ConfigDict(extra="forbid")


class SourceMeta(BaseModel):
    """Provenance for one upstream framework. Every field here exists to survive scrutiny."""

    model_config = _STRICT

    key: str
    name: str
    url: str
    license: str
    attribution: str
    retrieved: date
    version: str = ""
    #: False when the upstream wording could not be machine-confirmed (e.g. PDF-only release).
    verified: bool = True
    note: str = ""


class Entry(BaseModel):
    """One citable item: an OWASP category, an ATLAS technique, a control, a countermeasure."""

    model_config = _STRICT

    id: str
    title: str
    description: str = ""
    #: Set for hierarchical schemes (ATLAS sub-techniques, LLMSVS controls within a chapter).
    parent: str | None = None
    #: Tactic ids this entry serves (ATLAS). Validated at load time to resolve to entries in the
    #: same framework, so a report can render a tactic's title rather than a bare id.
    tactics: list[str] = Field(default_factory=list)
    #: Chapter/section label for verification standards.
    chapter: str = ""
    #: Assurance level(s) a verification-standard requirement applies at (e.g. ["L2", "L3"]).
    levels: list[str] = Field(default_factory=list)
    #: Upstream cross-references the source itself publishes (never ones we invent).
    refs: list[str] = Field(default_factory=list)
    #: False when this entry's wording is transcribed from a secondary source.
    verified: bool = True
    #: Required whenever ``verified`` is False — explains what could not be confirmed.
    source_note: str = ""


class CategoryMapping(BaseModel):
    """Framework entries and draft remediation associated with one OWASP-LLM category."""

    category: str
    #: framework key -> entry ids in that framework.
    entries: dict[str, list[str]] = Field(default_factory=dict)
    #: Draft remediation text, sourced from defensive-countermeasure frameworks.
    remediation: str = ""

    def refs(self, framework: str) -> list[str]:
        """Related entry ids in one framework; empty list if the mapping has none for it."""
        return list(self.entries.get(framework, []))

    def is_empty(self) -> bool:
        """True when this category has neither framework refs nor remediation text at all.

        Used to find OWASP-LLM categories the pack does not yet map — a gap worth curating,
        not an error condition, so :meth:`KnowledgePack.mapping_for` returns this rather than
        raising for an unmapped category.
        """
        return not any(self.entries.values()) and not self.remediation


class Framework(BaseModel):
    """One upstream framework: its provenance plus its entries, indexed by id."""

    source: SourceMeta
    entries: list[Entry] = Field(default_factory=list)

    def by_id(self, entry_id: str) -> Entry | None:
        """Look up one entry by id within this framework, or ``None`` if it is not present."""
        return self._index.get(entry_id)

    @property
    def _index(self) -> dict[str, Entry]:
        # Built lazily and memoised on the instance; packs are loaded once and read many times.
        cached = self.__dict__.get("_id_index")
        if cached is None:
            cached = {e.id: e for e in self.entries}
            self.__dict__["_id_index"] = cached
        return cached


@dataclass(frozen=True)
class SearchHit:
    """One :meth:`KnowledgePack.search` match: an entry paired with the framework it came from."""

    framework: str
    entry: Entry


class KnowledgePack(BaseModel):
    """The loaded pack. Constructed only via :func:`promptstrike.knowledge.load_pack`."""

    pack_version: str = ""
    frameworks: dict[str, Framework] = Field(default_factory=dict)
    mappings: dict[str, CategoryMapping] = Field(default_factory=dict)

    def framework(self, key: str) -> Framework:
        """Look up one framework by key, raising a clear error naming the ones that do exist."""
        try:
            return self.frameworks[key]
        except KeyError:
            raise KeyError(
                f"unknown framework {key!r}; pack has {sorted(self.frameworks)}"
            ) from None

    def entry(self, framework: str, entry_id: str) -> Entry | None:
        """Resolve one entry by ``(framework, entry_id)``, or ``None`` if the id is not present."""
        return self.framework(framework).by_id(entry_id)

    def mapping_for(self, category) -> CategoryMapping:
        """Never raises: an unmapped category yields an empty mapping so reports still render."""
        key = getattr(category, "value", category)
        return self.mappings.get(key) or CategoryMapping(category=key)

    def search(self, query: str, *, frameworks: list[str] | None = None) -> list[SearchHit]:
        """Case-insensitive substring search over id/title/description, all frameworks by default.

        Pass ``frameworks`` to narrow the search to specific keys; an unknown key is skipped
        rather than raised, so a stale key never breaks a broader search.
        """
        needle = query.strip().lower()
        if not needle:
            return []
        scope = frameworks if frameworks is not None else list(self.frameworks)
        hits: list[SearchHit] = []
        for key in scope:
            fw = self.frameworks.get(key)
            if fw is None:
                continue
            for entry in fw.entries:
                haystack = f"{entry.id} {entry.title} {entry.description}".lower()
                if needle in haystack:
                    hits.append(SearchHit(framework=key, entry=entry))
        return hits

    def attributions(self) -> list[str]:
        """Attribution lines for every source, for rendering into generated reports."""
        return [fw.source.attribution for fw in self.frameworks.values()]
