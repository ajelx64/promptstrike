"""Loading and validation for the vendored knowledge pack.

Validation is deliberately strict and happens at load time. A dangling reference or a duplicated id
would render a vulnerability report that cites a framework entry which does not exist — a failure that
is invisible in review and damaging when a triager checks it. Refusing to load turns that class of
curation mistake into a failing test instead.

The pack ships as package data (``knowledge/data``) rather than under the gitignored ``data/`` dir:
it is public, citable reference material and must be installed alongside the code.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from promptstrike.knowledge.models import (
    CategoryMapping,
    Entry,
    Framework,
    KnowledgePack,
    SourceMeta,
)
from promptstrike.taxonomy import OwaspLLM

MANIFEST_NAME = "MANIFEST.yaml"
MAPPINGS_NAME = "mappings.yaml"


def _data_dir() -> Path:
    return Path(__file__).parent / "data"


def _read_yaml(path: Path) -> Any:
    if not path.exists():
        raise ValueError(f"knowledge pack is missing {path.name} ({path})")
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _load_sources(manifest: dict) -> dict[str, SourceMeta]:
    sources: dict[str, SourceMeta] = {}
    for raw in manifest.get("sources", []):
        meta = SourceMeta(**raw)
        if not meta.license.strip():
            raise ValueError(f"source {meta.key!r} declares no license; attribution is required")
        if not meta.attribution.strip():
            raise ValueError(f"source {meta.key!r} declares no attribution string")
        if not meta.verified and not meta.note.strip():
            # Mirrors the entry-level rule: an unverified source must say what it could not confirm,
            # or downstream readers cannot judge how much to trust its ids.
            raise ValueError(f"source {meta.key!r} is marked unverified but carries no note")
        if meta.key in sources:
            raise ValueError(f"duplicate source key {meta.key!r} in {MANIFEST_NAME}")
        sources[meta.key] = meta
    return sources


def _load_framework(path: Path, source: SourceMeta) -> Framework:
    payload = _read_yaml(path)
    entries: list[Entry] = []
    seen: set[str] = set()
    for raw in payload.get("entries", []):
        entry = Entry(**raw)
        if entry.id in seen:
            raise ValueError(f"duplicate entry id {entry.id!r} in {path.name}")
        if not entry.verified and not entry.source_note.strip():
            raise ValueError(
                f"{path.name}:{entry.id} is marked unverified but carries no source_note"
            )
        seen.add(entry.id)
        entries.append(entry)

    if not entries:
        # Almost always a mis-keyed top-level mapping (`entires:`), which would otherwise load as a
        # valid-but-empty framework and quietly strip every citation that framework should provide.
        raise ValueError(
            f"{path.name} declares no entries; expected a top-level 'entries:' list"
        )

    for entry in entries:
        if entry.parent is not None and entry.parent not in seen:
            raise ValueError(f"{path.name}:{entry.id} has unknown parent {entry.parent!r}")
        for tactic in entry.tactics:
            if tactic not in seen:
                raise ValueError(f"{path.name}:{entry.id} cites unknown tactic {tactic!r}")

    return Framework(source=source, entries=entries)


def _load_mappings(root: Path, frameworks: dict[str, Framework]) -> dict[str, CategoryMapping]:
    payload = _read_yaml(root / MAPPINGS_NAME)
    valid_categories = {c.value for c in OwaspLLM}
    mappings: dict[str, CategoryMapping] = {}

    for category, raw in payload.items():
        if category not in valid_categories:
            raise ValueError(
                f"{MAPPINGS_NAME} maps unknown category {category!r}; "
                f"expected one of {sorted(valid_categories)}"
            )
        raw = dict(raw or {})
        remediation = str(raw.pop("remediation", "") or "")
        entries: dict[str, list[str]] = {}
        for fw_key, ids in raw.items():
            if fw_key not in frameworks:
                raise ValueError(
                    f"{MAPPINGS_NAME}:{category} references unknown framework {fw_key!r}"
                )
            fw = frameworks[fw_key]
            ids = list(ids or [])
            for entry_id in ids:
                if fw.by_id(entry_id) is None:
                    raise ValueError(
                        f"{MAPPINGS_NAME}:{category} references unknown "
                        f"{fw_key} entry {entry_id!r}"
                    )
            entries[fw_key] = ids
        mappings[category] = CategoryMapping(
            category=category, entries=entries, remediation=remediation
        )
    return mappings


def load_pack(root: str | Path) -> KnowledgePack:
    """Load and fully validate a pack from ``root``. Raises ``ValueError`` on any integrity problem."""
    root = Path(root)
    if not root.is_dir():
        raise ValueError(f"knowledge pack directory not found: {root}")

    manifest = _read_yaml(root / MANIFEST_NAME)
    sources = _load_sources(manifest)

    data_files = {
        p.stem: p
        for p in sorted(root.glob("*.yaml"))
        if p.name not in {MANIFEST_NAME, MAPPINGS_NAME}
    }

    orphans = sorted(set(data_files) - set(sources))
    if orphans:
        raise ValueError(
            f"data file(s) with no {MANIFEST_NAME} source entry: {orphans}; "
            "every shipped framework must declare its provenance"
        )
    missing = sorted(set(sources) - set(data_files))
    if missing:
        raise ValueError(f"{MANIFEST_NAME} declares source(s) with no data file: {missing}")

    frameworks = {key: _load_framework(path, sources[key]) for key, path in data_files.items()}
    mappings = _load_mappings(root, frameworks)

    return KnowledgePack(
        pack_version=str(manifest.get("pack_version", "")),
        frameworks=frameworks,
        mappings=mappings,
    )


@lru_cache(maxsize=1)
def pack() -> KnowledgePack:
    """The shipped pack, loaded once per process."""
    return load_pack(_data_dir())


def refs_for(category) -> dict[str, list[str]]:
    """Framework entry ids associated with an OWASP-LLM category, ready for ``Finding``."""
    mapping = pack().mapping_for(category)
    return {key: list(ids) for key, ids in mapping.entries.items() if ids}


def suggest_remediation(category) -> str:
    """A *draft* remediation for a category, for the operator to review and edit.

    Deliberately not applied automatically. ``Finding.remediation`` feeds the submission-readiness
    checklist (``report.profiles._has_remediation``); silently filling it would make that check pass
    for every finding and destroy the signal it exists to give. Callers surface this as a suggestion
    the operator explicitly accepts.
    """
    return pack().mapping_for(category).remediation
