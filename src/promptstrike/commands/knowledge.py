"""``promptstrike knowledge`` — inspect the vendored AI-security knowledge pack.

Read-only. This group exists so the pack can be verified end-to-end without any UI: if a framework
reference looks wrong in a report, `knowledge show` settles whether the data or the rendering is at
fault. It also gives the operator a way to browse the corpus while writing a finding by hand.
"""

from __future__ import annotations

import typer

from promptstrike import knowledge
from promptstrike.taxonomy import OwaspLLM

# Sub-app for every `promptstrike knowledge <verb>` command below.
knowledge_app = typer.Typer(
    help="Inspect the vendored AI-security knowledge pack (offline reference data).",
    no_args_is_help=True,
)


def _framework_or_exit(key: str):
    try:
        # Look up the framework by its key (e.g. "atlas", "owasp_llm").
        return knowledge.pack().framework(key)
    except KeyError as exc:
        # exc.args[0], not str(exc): str() on a KeyError renders the message's repr, so the
        # operator sees the whole line wrapped in literal double quotes.
        typer.echo(exc.args[0], err=True)
        raise typer.Exit(code=2) from None


@knowledge_app.command("sources")
def sources() -> None:
    """List the vendored frameworks with their provenance."""
    # The whole loaded knowledge pack, covering every vendored framework.
    pack = knowledge.pack()
    typer.echo(f"knowledge pack {pack.pack_version} — {len(pack.frameworks)} frameworks")
    for key in sorted(pack.frameworks):
        # Provenance (license, version, verification state) for this one framework.
        src = pack.frameworks[key].source
        # How many entries this framework contributes.
        count = len(pack.frameworks[key].entries)
        state = "verified" if src.verified else "UNVERIFIED"
        typer.echo(
            f"  {key:15s} {count:4d} entries  {src.license:14s} v{src.version or '-':10s} {state}"
        )
        typer.echo(f"  {'':15s} {src.url}")
    typer.echo("\nAttribution (include when citing):")
    for line in pack.attributions():
        # Collapse any embedded newlines/extra whitespace so each attribution prints on one line.
        typer.echo(f"  - {' '.join(line.split())}")


@knowledge_app.command("show")
def show(
    framework: str = typer.Argument(..., help="Framework key, e.g. atlas / llmsvs / owasp_llm"),
    entry_id: str | None = typer.Option(None, "--id", help="Show a single entry in detail"),
) -> None:
    """List a framework's entries, or show one entry in detail."""
    # Resolve the framework, exiting with a clear message if the key is unknown.
    framework_data = _framework_or_exit(framework)

    if entry_id is None:
        # No --id given: list every entry in the framework, flagging unverified ones.
        typer.echo(f"{framework_data.source.name} ({len(framework_data.entries)} entries)")
        for entry in framework_data.entries:
            flag = "" if entry.verified else "  [UNVERIFIED]"
            typer.echo(f"  {entry.id:18s} {entry.title}{flag}")
        return

    # --id given: look up that one entry within the framework.
    entry = framework_data.by_id(entry_id)
    if entry is None:
        typer.echo(f"{framework} has no entry {entry_id!r}", err=True)
        raise typer.Exit(code=2)

    typer.echo(f"{entry.id} — {entry.title}")
    if entry.description:
        typer.echo(f"\n{entry.description}")
    if entry.parent:
        # Resolve the parent entry's title too, so the hierarchy reads as more than a bare id.
        parent = framework_data.by_id(entry.parent)
        typer.echo(f"\nParent:   {entry.parent} ({parent.title if parent else '?'})")
    if entry.tactics:
        # Resolve each tactic id to its title where possible, falling back to the bare id.
        resolved = ", ".join(
            f"{tactic} ({framework_data.by_id(tactic).title})"
            if framework_data.by_id(tactic)
            else tactic
            for tactic in entry.tactics
        )
        typer.echo(f"Tactics:  {resolved}")
    if entry.chapter:
        typer.echo(f"Chapter:  {entry.chapter}")
    if entry.levels:
        typer.echo(f"Levels:   {', '.join(entry.levels)}")
    if not entry.verified:
        # Surface the sourcing caveat inline rather than letting an unverified entry look final.
        typer.echo(f"\n[UNVERIFIED] {' '.join(entry.source_note.split())}")
    typer.echo(f"\nSource:   {framework_data.source.name} — {framework_data.source.url}")


@knowledge_app.command("search")
def search(
    query: str = typer.Argument(..., help="Substring to look for in ids, titles, descriptions"),
    framework: list[str] = typer.Option(
        None, "--framework", "-f", help="Restrict to a framework (repeatable)"
    ),
) -> None:
    """Search across the pack."""
    # Normalize the repeatable --framework option to a plain list, or None for "search everything".
    scope = list(framework) if framework else None
    if scope:
        # Validate the filter. `search` silently skips unknown keys, so a typo'd --framework
        # would confidently answer "no matches" — the worst possible lie in a triage tool.
        for key in scope:
            _framework_or_exit(key)
    # Run the actual substring search across the requested framework(s).
    hits = knowledge.pack().search(query, frameworks=scope)
    if not hits:
        typer.echo(f"no matches for {query!r}")
        return
    typer.echo(f"{len(hits)} match(es) for {query!r}")
    for hit in hits:
        flag = "" if hit.entry.verified else "  [UNVERIFIED]"
        typer.echo(f"  {hit.framework:15s} {hit.entry.id:18s} {hit.entry.title}{flag}")


@knowledge_app.command("map")
def map_category(
    category: str = typer.Argument(..., help="OWASP-LLM category, e.g. LLM01"),
) -> None:
    """Show what a finding in this category resolves to, and its suggested remediation."""
    try:
        # Normalize and validate the category string against the OWASP-LLM taxonomy.
        owasp = OwaspLLM(category.upper())
    except ValueError:
        typer.echo(
            f"unknown category {category!r}; expected one of "
            f"{', '.join(category.value for category in OwaspLLM)}",
            err=True,
        )
        raise typer.Exit(code=2) from None

    # The loaded knowledge pack, used both for the category's own title and its cross-references.
    pack = knowledge.pack()
    # The other frameworks' entries mapped to this OWASP-LLM category, plus draft remediation.
    mapping = pack.mapping_for(owasp)
    typer.echo(f"{owasp.value} — {pack.entry('owasp_llm', f'{owasp.value}:2025').title}")
    for fw_key in sorted(mapping.entries):
        typer.echo(f"\n{fw_key}:")
        for entry_id in mapping.refs(fw_key):
            # Resolve each referenced id back to its full entry, if the pack still has one.
            entry = pack.entry(fw_key, entry_id)
            flag = "" if entry is None or entry.verified else "  [UNVERIFIED]"
            typer.echo(f"  {entry_id:18s} {entry.title if entry else '?'}{flag}")
    if mapping.remediation:
        # Explicitly frame this as a draft — the pack must never read as a final answer.
        typer.echo("\nSuggested remediation (a draft to edit, not an answer):")
        typer.echo(f"  {' '.join(mapping.remediation.split())}")
