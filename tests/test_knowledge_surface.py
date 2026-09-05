"""Headless surface for the knowledge pack (increment 2).

Two consumers, tested at the level each is used:

* the ``promptstrike knowledge`` CLI group, driven through Typer's runner;
* the report generator, which must render a finding's framework references *and* cite the
  sources they came from — attribution is a division rule, not a nicety.

This exists before any TUI on purpose: proving the pack end-to-end headlessly means a later
rendering bug is unambiguously a UI bug rather than a data bug.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from promptstrike import knowledge
from promptstrike.cli import app
from promptstrike.models import Finding, Platform
from promptstrike.report.generator import ReportGenerator
from promptstrike.report.profiles import get_profile
from promptstrike.taxonomy import OwaspLLM

runner = CliRunner()


def _finding(**kw) -> Finding:
    base = {
        "program": "acme",
        "platform": Platform.openai_h1,
        "title": "Indirect prompt injection via retrieved document",
        "category": OwaspLLM.LLM01,
    }
    return Finding(**{**base, **kw})


def _run(*args):
    result = runner.invoke(app, list(args))
    assert result.exit_code == 0, result.output
    return result.output


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------


def test_sources_lists_every_framework_with_license():
    out = _run("knowledge", "sources")
    for key in ("owasp_llm", "owasp_agentic", "atlas", "llmsvs", "aidefend"):
        assert key in out
    assert "Apache-2.0" in out and "CC BY-SA 4.0" in out


def test_sources_shows_verification_state_per_source():
    """An operator must be able to see at a glance which data is confirmed.

    The agentic pack was transcribed from a secondary source and later confirmed verbatim against
    the canonical OWASP PDF (see MANIFEST owasp_agentic note); the sources view must reflect that.
    """
    out = _run("knowledge", "sources")
    agentic_line = next(ln for ln in out.splitlines() if "owasp_agentic" in ln)
    assert "verified" in agentic_line.lower()
    assert "unverified" not in agentic_line.lower()


def test_show_lists_entries_for_a_framework():
    out = _run("knowledge", "show", "owasp_llm")
    assert "LLM01:2025" in out
    assert "Prompt Injection" in out


def test_show_single_entry_includes_detail():
    out = _run("knowledge", "show", "atlas", "--id", "AML.T0051")
    assert "LLM Prompt Injection" in out
    assert "AML.TA0005" in out or "Execution" in out


def test_show_unknown_framework_fails_with_useful_message():
    result = runner.invoke(app, ["knowledge", "show", "nope"])
    assert result.exit_code != 0
    assert "nope" in result.output


def test_show_unknown_entry_id_fails():
    result = runner.invoke(app, ["knowledge", "show", "atlas", "--id", "AML.T9999"])
    assert result.exit_code != 0


def test_search_finds_across_frameworks():
    out = _run("knowledge", "search", "jailbreak")
    assert "AML.T0054" in out


def test_search_can_scope_to_one_framework():
    out = _run("knowledge", "search", "jailbreak", "--framework", "atlas")
    assert "AML.T0054" in out
    assert "AID-" not in out


def test_search_with_no_hits_is_not_an_error():
    result = runner.invoke(app, ["knowledge", "search", "zzzznotathing"])
    assert result.exit_code == 0
    assert "no match" in result.output.lower()


def test_map_shows_what_a_category_resolves_to():
    out = _run("knowledge", "map", "LLM01")
    assert "AML.T0051" in out
    assert "5.11" in out


# --------------------------------------------------------------------------------------
# Report rendering
# --------------------------------------------------------------------------------------


@pytest.fixture
def rendered() -> str:
    return ReportGenerator().render_markdown(_finding(), get_profile("openai_h1"))


def test_report_renders_framework_references(rendered):
    assert "AML.T0051" in rendered
    assert "ASI01:2026" in rendered


def test_report_renders_reference_titles_not_bare_ids(rendered):
    """A bare id is not useful to a triager who does not have the matrix memorised."""
    assert "LLM Prompt Injection" in rendered


def test_report_cites_sources_for_referenced_frameworks(rendered):
    assert "MITRE ATLAS" in rendered
    assert "Apache License" in rendered or "Apache-2.0" in rendered


def test_report_does_not_cite_unreferenced_sources():
    """LLM02 does not map to owasp_agentic; citing it would be misleading noise."""
    rendered = ReportGenerator().render_markdown(
        _finding(category=OwaspLLM.LLM02), get_profile("openai_h1")
    )
    assert "ASI0" not in rendered
    assert "Agentic" not in rendered


def test_report_does_not_flag_verified_references(rendered):
    """LLM01 cites ASI01:2026, now confirmed verbatim against the canonical OWASP PDF.

    A confirmed reference must render clean — flagging it 'unverified' would wrongly tell a triager
    the citation is untrustworthy. (The 'unverified' render path is still covered by
    ``test_unresolvable_reference_is_not_rendered_as_a_confident_citation``.)
    """
    assert "ASI01:2026" in rendered
    assert "unverified" not in rendered.lower()


def test_report_flags_reference_from_an_unverified_source(monkeypatch):
    """A source-level unverified flag taints its entries even when the entry looks clean.

    Guards the ``entry.verified and framework.source.verified`` rule in the report generator, which
    otherwise loses live coverage now that every vendored entry and source is verified.
    """
    agentic_source = knowledge.pack().framework("owasp_agentic").source
    monkeypatch.setattr(agentic_source, "note", "forced unverified for test")
    monkeypatch.setattr(agentic_source, "verified", False)
    rendered = ReportGenerator().render_markdown(_finding(), get_profile("openai_h1"))
    assert "ASI01:2026" in rendered
    assert "unverified" in rendered.lower()


def test_report_carries_aidefend_non_affiliation_disclaimer(rendered):
    """Citing AIDEFEND without its disclaimer could imply MITRE/OWASP endorsement."""
    assert "not affiliated" in rendered.lower()


def test_report_still_renders_for_a_finding_with_no_refs():
    """Degrade gracefully: an operator who cleared refs still gets a report."""
    f = _finding()
    f.framework_refs = {}
    out = ReportGenerator().render_markdown(f, get_profile("openai_h1"))
    assert "Prompt Injection in acme" in out  # the derived report_title still renders
    assert "Related framework references" not in out
    # Attribution is NOT conditional on refs: the OWASP category, CVSS, and CWE are cited by
    # construction in every report.
    assert "## Attribution" in out


def test_report_always_attributes_owasp_llm_cvss_and_cwe():
    """Cited by construction, not by reference — the case derived attribution silently missed."""
    f = _finding()
    f.framework_refs = {}
    out = ReportGenerator().render_markdown(f, get_profile("openai_h1"))
    assert "OWASP Top 10 for LLM Applications" in out
    assert "FIRST.org" in out
    assert "cwe.mitre.org" in out


def test_unresolvable_reference_is_not_rendered_as_a_confident_citation():
    """A ghost id must not be indistinguishable from a confirmed one."""
    f = _finding()
    f.framework_refs = {"atlas": ["AML.T9999"]}
    out = ReportGenerator().render_markdown(f, get_profile("openai_h1"))
    assert "AML.T9999" in out
    assert "not present in vendored knowledge pack" in out


def test_reference_to_a_missing_framework_does_not_break_the_report():
    f = _finding()
    f.framework_refs = {"ghostfw": ["X1"]}
    out = ReportGenerator().render_markdown(f, get_profile("openai_h1"))
    assert "Prompt Injection in acme" in out
    assert "ghostfw" not in out


def test_search_with_unknown_framework_filter_is_an_error_not_an_empty_result():
    """A typo'd filter answering 'no matches' is the worst possible lie in a triage tool."""
    result = runner.invoke(app, ["knowledge", "search", "jailbreak", "-f", "atls"])
    assert result.exit_code == 2
    assert "atls" in result.output


def test_unknown_framework_message_is_not_repr_wrapped():
    result = runner.invoke(app, ["knowledge", "show", "nope"])
    assert not result.output.strip().startswith('"')


def test_html_render_also_includes_references():
    out = ReportGenerator().render_html(_finding(), get_profile("openai_h1"))
    assert "AML.T0051" in out


def test_suggested_remediation_is_offered_not_asserted(rendered):
    """The report must not present a pack suggestion as the operator's own remediation."""
    assert "_(to be completed)_" in rendered
    suggestion = knowledge.suggest_remediation(OwaspLLM.LLM01)
    assert suggestion[:40] not in rendered
