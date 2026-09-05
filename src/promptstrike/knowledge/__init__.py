"""Vendored AI-security knowledge pack.

Offline-first reference data — OWASP Top 10 for LLM Applications, OWASP Top 10 for Agentic
Applications, MITRE ATLAS, OWASP verification standards, and defensive countermeasures — used to
enrich findings with the framework identifiers a bug-bounty triager actually works in.

The pack is *vendored*, not fetched: reports must be reproducible, the tool must work offline, and
pulling adversarial reference content over the network at test time would be a supply-chain risk in a
security tool. Refreshing is a separate, human-gated operation.

Typical use::

    from promptstrike import knowledge

    mapping = knowledge.pack().mapping_for(finding.category)
    technique = knowledge.pack().entry("atlas", mapping.refs("atlas")[0])
"""

from __future__ import annotations

# Re-exported so callers can do `from promptstrike import knowledge` and use `knowledge.pack()`
# without knowing the pack lives in a `loader` submodule internally.
from promptstrike.knowledge.loader import load_pack, pack, refs_for, suggest_remediation
from promptstrike.knowledge.models import (
    CategoryMapping,
    Entry,
    Framework,
    KnowledgePack,
    SearchHit,
    SourceMeta,
)

# Public surface of this package; keeps `from promptstrike.knowledge import *` and static
# analysis tools aligned with what is actually meant to be used from outside this package.
__all__ = [
    "CategoryMapping",
    "Entry",
    "Framework",
    "KnowledgePack",
    "SearchHit",
    "SourceMeta",
    "load_pack",
    "pack",
    "refs_for",
    "suggest_remediation",
]
