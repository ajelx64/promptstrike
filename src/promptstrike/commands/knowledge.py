"""``promptstrike knowledge`` — inspect the vendored AI-security knowledge pack.

Read-only. This group exists so the pack can be verified end-to-end without any UI: if a framework
reference looks wrong in a report, `knowledge show` settles whether the data or the rendering is at
fault. It also gives the operator a way to browse the corpus while writing a finding by hand.
"""

from __future__ import annotations

import typer

from promptstrike import knowledge
from promptstrike.taxonomy import OwaspLLM

knowledge_app = typer.Typer(
    help="Inspect the vendored AI-security knowledge pack (offline reference data).",
    no_args_is_help=True,
)


def _framework_or_exit(key: str):
    try:
        return knowledge.pack().framework(key)
    except KeyError as exc:
        # exc.args[0], not str(exc): str() on a KeyError renders the message's repr, so the
        # operator sees the whole line wrapped in literal double quotes.
        typer.echo(exc.args[0], err=True)
        raise typer.Exit(code=2) from None


@knowledge_app.command("sources")
def sources() -> None:
    """List the vendored frameworks with their provenance."""
    pack = knowledge.pack()
    typer.echo(f"knowledge pack {pack.pack_version} — {len(pack.frameworks)} frameworks")
    for key in sorted(pack.frameworks):
        src = pack.frameworks[key].source
        count = len(pack.frameworks[key].entries)
        state = "verified" if src.verified else "UNVERIFIED"
        typer.echo(
            f"  {key:15s} {count:4d} entries  {src.license:14s} v{src.version or '-':10s} {state}"
        )
        typer.echo(f"  {'':15s} {src.url}")
    typer.echo("\nAttribution (include when citing):")
    for line in pack.attributions():
        typer.echo(f"  - {' '.join(line.split())}")


@knowledge_app.command("show")
def show(
    framework: str = typer.Argument(..., help="Framework key, e.g. atlas / llmsvs / owasp_llm"),
    entry_id: str | None = typer.Option(None, "--id", help="Show a single entry in detail"),
) -> None:
    """List a framework's entries, or show one entry in detail."""
    fw = _framework_or_exit(framework)

    if entry_id is None:
        typer.echo(f"{fw.source.name} ({len(fw.entries)} entries)")
        for entry in fw.entries:
            flag = "" if entry.verified else "  [UNVERIFIED]"
            typer.echo(f"  {entry.id:18s} {entry.title}{flag}")
        return

    entry = fw.by_id(entry_id)
    if entry is None:
        typer.echo(f"{framework} has no entry {entry_id!r}", err=True)
        raise typer.Exit(code=2)

    typer.echo(f"{entry.id} — {entry.title}")
    if entry.description:
        typer.echo(f"\n{entry.description}")
    if entry.parent:
        parent = fw.by_id(entry.parent)
        typer.echo(f"\nParent:   {entry.parent} ({parent.title if parent else '?'})")
    if entry.tactics:
        resolved = ", ".join(
            f"{t} ({fw.by_id(t).title})" if fw.by_id(t) else t for t in entry.tactics
        )
        typer.echo(f"Tactics:  {resolved}")
    if entry.chapter:
        typer.echo(f"Chapter:  {entry.chapter}")
    if entry.levels:
        typer.echo(f"Levels:   {', '.join(entry.levels)}")
    if not entry.verified:
        typer.echo(f"\n[UNVERIFIED] {' '.join(entry.source_note.split())}")
    typer.echo(f"\nSource:   {fw.source.name} — {fw.source.url}")


@knowledge_app.command("search")
def search(
    query: str = typer.Argument(..., help="Substring to look for in ids, titles, descriptions"),
    framework: list[str] = typer.Option(
        None, "--framework", "-f", help="Restrict to a framework (repeatable)"
    ),
) -> None:
    """Search across the pack."""
    scope = list(framework) if framework else None
    if scope:
        # Validate the filter. `search` silently skips unknown keys, so a typo'd --framework
        # would confidently answer "no matches" — the worst possible lie in a triage tool.
        for key in scope:
            _framework_or_exit(key)
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
        owasp = OwaspLLM(category.upper())
    except ValueError:
        typer.echo(
            f"unknown category {category!r}; expected one of "
            f"{', '.join(c.value for c in OwaspLLM)}",
            err=True,
        )
        raise typer.Exit(code=2) from None

    pack = knowledge.pack()
    mapping = pack.mapping_for(owasp)
    typer.echo(f"{owasp.value} — {pack.entry('owasp_llm', f'{owasp.value}:2025').title}")
    for fw_key in sorted(mapping.entries):
        typer.echo(f"\n{fw_key}:")
        for entry_id in mapping.refs(fw_key):
            entry = pack.entry(fw_key, entry_id)
            flag = "" if entry is None or entry.verified else "  [UNVERIFIED]"
            typer.echo(f"  {entry_id:18s} {entry.title if entry else '?'}{flag}")
    if mapping.remediation:
        typer.echo("\nSuggested remediation (a draft to edit, not an answer):")
        typer.echo(f"  {' '.join(mapping.remediation.split())}")
