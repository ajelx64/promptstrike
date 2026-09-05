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
    # Package-relative path to the vendored pack directory, shipped inside the installed package.
    return Path(__file__).parent / "data"


def _read_yaml(path: Path) -> Any:
    if not path.exists():
        # Fail with a message naming the exact missing file, rather than a bare FileNotFoundError.
        raise ValueError(f"knowledge pack is missing {path.name} ({path})")
    # Parse the YAML; `or {}` turns an empty file into an empty dict instead of None.
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _load_sources(manifest: dict) -> dict[str, SourceMeta]:
    # Accumulates validated sources, keyed by source key, for the framework loader to attach.
    sources: dict[str, SourceMeta] = {}
    # Walk every source entry declared in MANIFEST.yaml.
    for raw in manifest.get("sources", []):
        # Parse into the strict pydantic model; an unrecognized key raises here (see models._STRICT).
        meta = SourceMeta(**raw)
        if not meta.license.strip():
            # A source with no declared license cannot legally be cited in a generated report.
            raise ValueError(f"source {meta.key!r} declares no license; attribution is required")
        if not meta.attribution.strip():
            # Attribution text is what actually gets printed in reports; it must be present.
            raise ValueError(f"source {meta.key!r} declares no attribution string")
        if not meta.verified and not meta.note.strip():
            # Mirrors the entry-level rule: an unverified source must say what it could not confirm,
            # or downstream readers cannot judge how much to trust its ids.
            raise ValueError(f"source {meta.key!r} is marked unverified but carries no note")
        if meta.key in sources:
            # A duplicate key would silently shadow the first source under the same identifier.
            raise ValueError(f"duplicate source key {meta.key!r} in {MANIFEST_NAME}")
        # Store the validated source under its key for later lookup.
        sources[meta.key] = meta
    # Every source that passed validation, ready for the framework loader to attach as provenance.
    return sources


def _load_framework(path: Path, source: SourceMeta) -> Framework:
    # Parse this framework's own YAML file (e.g. owasp_llm.yaml, atlas.yaml).
    payload = _read_yaml(path)
    # Entries collected in file order; returned as part of the Framework below.
    entries: list[Entry] = []
    # Ids seen so far in this file, used both to catch duplicates and to validate cross-references.
    seen: set[str] = set()
    for raw in payload.get("entries", []):
        # Parse one entry via the strict model; a misspelled field raises immediately.
        entry = Entry(**raw)
        if entry.id in seen:
            # A duplicate id would make later lookups by id ambiguous.
            raise ValueError(f"duplicate entry id {entry.id!r} in {path.name}")
        if not entry.verified and not entry.source_note.strip():
            # An unverified entry must explain what could not be confirmed about it.
            raise ValueError(
                f"{path.name}:{entry.id} is marked unverified but carries no source_note"
            )
        # Record the id before moving to the next entry, so later entries can reference it.
        seen.add(entry.id)
        entries.append(entry)

    if not entries:
        # Almost always a mis-keyed top-level mapping (`entires:`), which would otherwise load as a
        # valid-but-empty framework and quietly strip every citation that framework should provide.
        raise ValueError(
            f"{path.name} declares no entries; expected a top-level 'entries:' list"
        )

    # Second pass: cross-reference validation needs every id already collected in `seen`.
    for entry in entries:
        if entry.parent is not None and entry.parent not in seen:
            # A hierarchical entry pointing at a parent id that does not exist in this file.
            raise ValueError(f"{path.name}:{entry.id} has unknown parent {entry.parent!r}")
        for tactic in entry.tactics:
            if tactic not in seen:
                # A tactic reference (ATLAS) that does not resolve within the same framework.
                raise ValueError(f"{path.name}:{entry.id} cites unknown tactic {tactic!r}")

    # Bundle the validated entries together with their already-validated source provenance.
    return Framework(source=source, entries=entries)


def _load_mappings(root: Path, frameworks: dict[str, Framework]) -> dict[str, CategoryMapping]:
    # Parse mappings.yaml, which links our own OWASP-LLM categories to framework entries.
    payload = _read_yaml(root / MAPPINGS_NAME)
    # The full set of OWASP-LLM category values a mapping is allowed to name.
    valid_categories = {category.value for category in OwaspLLM}
    # Validated per-category mappings, built up below and returned at the end.
    mappings: dict[str, CategoryMapping] = {}

    for category, raw in payload.items():
        if category not in valid_categories:
            # A mapping keyed by a category that does not exist in the taxonomy is a curation typo.
            raise ValueError(
                f"{MAPPINGS_NAME} maps unknown category {category!r}; "
                f"expected one of {sorted(valid_categories)}"
            )
        # Work on a mutable copy so `remediation` can be popped out below without touching the input.
        raw = dict(raw or {})
        # Pull the free-text remediation draft out; whatever remains are framework -> ids entries.
        remediation = str(raw.pop("remediation", "") or "")
        # Validated framework -> entry-id lists for this one category.
        entries: dict[str, list[str]] = {}
        for fw_key, ids in raw.items():
            if fw_key not in frameworks:
                # A mapping citing a framework that was never loaded (typo or removed framework).
                raise ValueError(
                    f"{MAPPINGS_NAME}:{category} references unknown framework {fw_key!r}"
                )
            # The already-loaded, already-validated framework this category cites entries in.
            fw = frameworks[fw_key]
            # Normalize a possibly-null YAML list to a concrete list of ids.
            ids = list(ids or [])
            for entry_id in ids:
                if fw.by_id(entry_id) is None:
                    # A cited id that does not actually exist in that framework's entries.
                    raise ValueError(
                        f"{MAPPINGS_NAME}:{category} references unknown "
                        f"{fw_key} entry {entry_id!r}"
                    )
            # Record this framework's id list for the category, even if it later proves empty.
            entries[fw_key] = ids
        # Build the validated mapping for this category once every framework/id has been checked.
        mappings[category] = CategoryMapping(
            category=category, entries=entries, remediation=remediation
        )
    # Every category mapping that passed validation.
    return mappings


def load_pack(root: str | Path) -> KnowledgePack:
    """Load and fully validate a pack from ``root``. Raises ``ValueError`` on any integrity problem."""
    # Normalize to a Path so the rest of this function can use Path operations uniformly.
    root = Path(root)
    if not root.is_dir():
        # No point trying to read individual files if the pack directory itself is missing.
        raise ValueError(f"knowledge pack directory not found: {root}")

    # Parse the top-level manifest, which lists every source this pack vendors.
    manifest = _read_yaml(root / MANIFEST_NAME)
    # Validate every declared source before touching any per-framework data file.
    sources = _load_sources(manifest)

    # Every *.yaml file except the two special ones, keyed by filename stem (the framework key).
    data_files = {
        yaml_path.stem: yaml_path
        for yaml_path in sorted(root.glob("*.yaml"))
        if yaml_path.name not in {MANIFEST_NAME, MAPPINGS_NAME}
    }

    # A data file shipped with no matching MANIFEST.yaml source entry has no declared provenance.
    orphans = sorted(set(data_files) - set(sources))
    if orphans:
        raise ValueError(
            f"data file(s) with no {MANIFEST_NAME} source entry: {orphans}; "
            "every shipped framework must declare its provenance"
        )
    # A source declared in the manifest with no corresponding data file on disk.
    missing = sorted(set(sources) - set(data_files))
    if missing:
        raise ValueError(f"{MANIFEST_NAME} declares source(s) with no data file: {missing}")

    # Load and validate every framework's entries against its already-validated source.
    frameworks = {key: _load_framework(path, sources[key]) for key, path in data_files.items()}
    # Load and validate the category -> framework-entry mappings against the loaded frameworks.
    mappings = _load_mappings(root, frameworks)

    # Assemble the fully validated pack; this is the only place a KnowledgePack is constructed.
    return KnowledgePack(
        pack_version=str(manifest.get("pack_version", "")),
        frameworks=frameworks,
        mappings=mappings,
    )


@lru_cache(maxsize=1)
def pack() -> KnowledgePack:
    """The shipped pack, loaded once per process."""
    # Cached (maxsize=1): every caller in the process shares one validated, immutable pack instance.
    return load_pack(_data_dir())


def refs_for(category) -> dict[str, list[str]]:
    """Framework entry ids associated with an OWASP-LLM category, ready for ``Finding``."""
    # Look up (or synthesize an empty) mapping for this category from the shared pack.
    mapping = pack().mapping_for(category)
    # Drop framework keys with no ids, so callers never see an empty list they'd have to filter.
    return {key: list(ids) for key, ids in mapping.entries.items() if ids}


def suggest_remediation(category) -> str:
    """A *draft* remediation for a category, for the operator to review and edit.

    Deliberately not applied automatically. ``Finding.remediation`` feeds the submission-readiness
    checklist (``report.profiles._has_remediation``); silently filling it would make that check pass
    for every finding and destroy the signal it exists to give. Callers surface this as a suggestion
    the operator explicitly accepts.
    """
    # Pull the curated draft remediation text straight from the category's mapping.
    return pack().mapping_for(category).remediation
