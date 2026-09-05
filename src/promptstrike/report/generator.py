"""Report generator — ported from an earlier internal report generator.

Keeps the reused pattern (Jinja2 with autoescape on, so target-controlled prompt/response text is
HTML-escaped into the report) and makes the WeasyPrint import **lazy** so a missing GTK/Pango stack
soft-fails to HTML instead of breaking the whole tool. Sync (CLI context) rather than the async
`to_thread` render the original used inside FastAPI.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from promptstrike import taxonomy
from promptstrike.models import Finding
from promptstrike.report.profiles import Profile


def _templates_dir() -> Path:
    return Path(__file__).parent / "templates"


# Sources every report cites *by construction* rather than by reference, and which therefore must be
# attributed unconditionally. The OWASP-LLM category appears in the metadata block and inside
# `report_title` (whose text comes from taxonomy._TITLES — OWASP's verbatim 2025 category names);
# CVSS and CWE appear alongside it. Deriving attribution only from `framework_refs` missed all three,
# because `mappings.yaml` has no `owasp_llm` key: the category *is* the OWASP id.
_CVSS_ATTRIBUTION = (
    "CVSS v3.1 / v4.0 (Common Vulnerability Scoring System), (c) FIRST.org, Inc. — "
    "https://www.first.org/cvss/"
)
_CWE_ATTRIBUTION = (
    "CWE(TM) (Common Weakness Enumeration), (c) The MITRE Corporation — https://cwe.mitre.org/"
)


class ReportGenerator:
    """Renders a Finding into Markdown, HTML, or PDF via Jinja2, autoescape on for target text."""

    def __init__(self, templates_dir: Path | None = None) -> None:
        self.env = Environment(
            loader=FileSystemLoader(str(templates_dir or _templates_dir())),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def _framework_context(self, finding: Finding) -> tuple[list[dict], list[str]]:
        """Resolve a finding's framework refs to titles, and collect only the sources it uses.

        Two deliberate choices: refs are resolved so the report shows "AML.T0051 — LLM Prompt
        Injection" rather than a bare id a triager would have to look up; and attribution is emitted
        only for frameworks this finding actually cites, because listing all five would be noise and
        would imply corroboration the finding does not have.
        """
        from promptstrike import knowledge

        pack = knowledge.pack()
        groups: list[dict] = []
        # Unconditional: these are cited by construction in every report, not by reference.
        attributions: list[str] = [
            " ".join(pack.framework("owasp_llm").source.attribution.split()),
            _CVSS_ATTRIBUTION,
            _CWE_ATTRIBUTION,
        ]

        for fw_key in sorted(finding.framework_refs):
            ids = finding.refs(fw_key)
            if not ids:
                continue
            try:
                framework = pack.framework(fw_key)
            except KeyError:
                # A ref to a framework no longer in the pack: skip rather than break the report.
                continue
            refs = []
            for entry_id in ids:
                entry = pack.entry(fw_key, entry_id)
                if entry is None:
                    # An id that does not resolve must NOT render as a confident citation — a
                    # triager checking it would find nothing upstream.
                    refs.append(
                        {
                            "id": entry_id,
                            "title": "",
                            "verified": False,
                            "note": (
                                f"id not present in vendored knowledge pack {pack.pack_version}"
                            ),
                        }
                    )
                    continue
                refs.append(
                    {
                        "id": entry_id,
                        "title": entry.title,
                        # A source flagged unverified taints its entries even when the entry
                        # itself carries no flag; today they agree, but nothing enforces that.
                        "verified": entry.verified and framework.source.verified,
                        "note": " ".join(
                            (entry.source_note or framework.source.note).split()
                        ),
                    }
                )
            # NB: key is `refs`, not `items` — Jinja resolves `group.items` to dict.items (the
            # built-in method) before the mapping key, which silently yields a non-iterable.
            groups.append({"key": fw_key, "name": framework.source.name, "refs": refs})
            attributions.append(" ".join(framework.source.attribution.split()))

        return groups, attributions

    def _context(self, finding: Finding, profile: Profile) -> dict:
        framework_groups, attributions = self._framework_context(finding)
        return {
            "framework_groups": framework_groups,
            "attributions": attributions,
            "finding": finding,
            "profile": profile,
            "report_title": f"{taxonomy.title(finding.category)} in {finding.target or finding.program}",
            "generated_date": date.today().strftime("%B %d, %Y"),
            "platform_severity": profile.severity_label(finding),
            "owasp_title": taxonomy.title(finding.category),
            "checklist": profile.checklist(finding),
            "compliance_note": "Conducted within authorized program scope; see the run authorization log.",
        }

    def render_markdown(self, finding: Finding, profile: Profile) -> str:
        """Render ``finding`` as a Markdown report using ``profile``'s severity scheme + checklist."""
        return self.env.get_template("report/finding.md.j2").render(
            **self._context(finding, profile)
        )

    def render_html(self, finding: Finding, profile: Profile) -> str:
        """Render ``finding`` as an HTML report; :meth:`render_pdf` converts this output to PDF."""
        return self.env.get_template("report/finding.html").render(
            **self._context(finding, profile)
        )

    def render_pdf(self, finding: Finding, profile: Profile) -> bytes | None:
        """Render a PDF, or return None (soft-fail) if WeasyPrint / its system libs are unavailable."""
        html = self.render_html(finding, profile)
        try:
            import weasyprint  # lazy: a missing GTK/Pango stack must not break import
        except Exception:
            return None
        try:
            return weasyprint.HTML(string=html).write_pdf()
        except Exception:
            return None
