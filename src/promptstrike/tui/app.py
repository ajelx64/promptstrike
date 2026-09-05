"""The promptstrike triage & report workbench.

A second front-end over the SAME engine the CLI uses — nothing here reimplements scope checking,
CVSS, profiles, or rendering. The CLI remains the scriptable, loggable path; this is for the part of
bug-bounty work that actually consumes the hours: turning captured results into a submission.

Deliberately contains NO code path that sends traffic to a target. Probing stays on the CLI until a
"Run" tab is built as its own reviewable increment, so the risky surface is isolated from this one.

THREADING NOTE. ``storage.FindingStore`` opens its sqlite3 connection with the default
``check_same_thread=True``. Every store access here therefore happens on Textual's event loop; no
``@work(thread=True)`` worker may touch the store. Reads are small (a local findings DB) so this
costs nothing, and it keeps the store's threading contract unchanged.
"""

from __future__ import annotations

from pathlib import Path

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Markdown,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)

from promptstrike import knowledge
from promptstrike.config import get_settings
from promptstrike.models import Finding
from promptstrike.report.generator import ReportGenerator
from promptstrike.report.profiles import get_profile
from promptstrike.storage import FindingStore

_COLUMNS = ("id", "severity", "category", "status", "title")


def _summary_markdown(finding: Finding) -> str:
    """The detail pane: what the finding is, and what the pack says it relates to."""
    pack = knowledge.pack()
    lines = [
        f"# {finding.title}",
        "",
        f"- **Program:** {finding.program} — {finding.platform.value}",
        f"- **Category:** {finding.category.value}",
        f"- **Severity:** {finding.severity.value}"
        + (f" (CVSS {finding.cvss_v31_score})" if finding.cvss_v31_score is not None else ""),
        f"- **CWE:** {', '.join(finding.cwe) or '—'}",
        f"- **Target:** {finding.target or '—'}",
        f"- **Status:** {finding.status.value}",
        "",
        "## Related framework references",
    ]
    if not finding.framework_refs:
        lines.append("_none_")
    for fw_key in sorted(finding.framework_refs):
        ids = finding.refs(fw_key)
        if not ids:
            continue
        try:
            name = pack.framework(fw_key).source.name
        except KeyError:
            name = fw_key
        lines += ["", f"**{name}**", ""]
        for entry_id in ids:
            entry = pack.entry(fw_key, entry_id)
            title = f" — {entry.title}" if entry else ""
            flag = "  _(unverified)_" if entry is not None and not entry.verified else ""
            lines.append(f"- `{entry_id}`{title}{flag}")
    return "\n".join(lines)


def _checklist_markdown(finding: Finding) -> str:
    profile = get_profile(finding.platform.value)
    items = profile.checklist(finding)
    lines = [f"## {profile.display_name} readiness", ""]
    lines += [f"- [{'x' if i.ok else ' '}] {i.label}" for i in items]
    missing = [i.label for i in items if not i.ok]
    lines += ["", f"**{len(items) - len(missing)}/{len(items)} ready**"]
    if missing:
        lines.append(f"Outstanding: {', '.join(missing)}")
    return "\n".join(lines)


class WorkbenchApp(App):
    """Triage & report workbench."""

    CSS = """
    Screen { layout: vertical; }
    #findings { height: 1fr; }
    #detail, #checklist { width: 1fr; padding: 0 1; }
    #remediation { height: 1fr; border: round $accent; }
    #status { dock: bottom; height: 1; background: $panel; color: $text-muted; padding: 0 1; }
    """

    # TextArea swallows printable keys, which is correct — the operator must be able to type an
    # "s" into their remediation prose. But it means the plain single-key bindings are dead while
    # the editor has focus, so ctrl+s is bound with priority=True to fire regardless of focus.
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Reload"),
        Binding("i", "insert_suggestion", "Insert suggestion"),
        Binding("s", "save", "Save finding"),
        Binding("ctrl+s", "save", "Save (works while editing)", priority=True),
    ]

    def __init__(self, db_path: Path | None = None) -> None:
        super().__init__()
        settings = get_settings()
        settings.ensure_dirs()
        self._db_path = Path(db_path) if db_path else Path(settings.db_path)
        self._store: FindingStore | None = None
        self._findings: list[Finding] = []
        self._current: Finding | None = None
        #: Unsaved remediation text, keyed by finding id. The workbench exists to author prose, so
        #: navigating away from an edit must never destroy it — drafts are stashed and restored
        #: rather than discarded, and survive a reload.
        self._drafts: dict[int, str] = {}
        self.status_text = ""

    # -- lifecycle ---------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        """Lay out the Findings/Detail/Report tabs plus the status bar and footer."""
        yield Header(show_clock=False)
        with TabbedContent(initial="tab-findings"):
            with TabPane("Findings", id="tab-findings"):
                yield DataTable(id="findings", cursor_type="row")
            with TabPane("Detail", id="tab-detail"):
                with Horizontal():
                    with VerticalScroll():
                        yield Markdown(id="detail")
                    with VerticalScroll():
                        yield Markdown(id="checklist")
                yield TextArea(id="remediation", language=None)
            with TabPane("Report", id="tab-report"):
                with VerticalScroll():
                    yield Markdown(id="report")
            # A "Run" tab slots in here later; it is the only surface that would send traffic
            # to a target, so it stays a separate, separately-reviewed increment.
        yield Static("", id="status")
        yield Footer()

    def on_mount(self) -> None:
        """Open the findings store and load the table once Textual's event loop is running."""
        table = self.query_one("#findings", DataTable)
        table.add_columns(*_COLUMNS)
        self._store = FindingStore(self._db_path)
        self.action_refresh()

    def on_unmount(self) -> None:
        """Close the store's sqlite3 connection so the app never leaves it dangling."""
        if self._store is not None:
            self._store.close()
            self._store = None

    # -- data --------------------------------------------------------------------------

    def _set_status(self, message: str) -> None:
        #: Mirrored onto the app so callers (and tests) read app state, not widget internals.
        self.status_text = message
        self.query_one("#status", Static).update(message)

    def _stash_draft(self) -> None:
        """Preserve the editor's text for the current finding if it differs from what is saved."""
        if self._current is None or self._current.id is None:
            return
        editor = self.query_one("#remediation", TextArea)
        if editor.text.strip() != (self._current.remediation or "").strip():
            self._drafts[self._current.id] = editor.text
        else:
            self._drafts.pop(self._current.id, None)

    def _draft_suffix(self) -> str:
        return f"  [{len(self._drafts)} unsaved draft(s)]" if self._drafts else ""

    def action_refresh(self) -> None:
        """Reload findings from the store while preserving the cursor position and any drafts.

        Any unsaved editor text is stashed first (see ``_stash_draft``) so a reload triggered
        while the operator is mid-edit — e.g. after saving elsewhere — never discards prose they
        have not committed yet. The cursor is restored to the same finding id when possible,
        rather than snapping back to row 0, since reloading is meant to refresh data, not to move
        the operator around the table.
        """
        if self._store is None:
            return
        self._stash_draft()
        keep_id = self._current.id if self._current else None
        self._findings = self._store.list()
        table = self.query_one("#findings", DataTable)
        table.clear()
        for f in self._findings:
            table.add_row(
                str(f.id), f.severity.value, f.category.value, f.status.value, f.title
            )
        if self._findings:
            # Keep the operator where they were; reloading should not move the cursor.
            index = next(
                (i for i, f in enumerate(self._findings) if f.id == keep_id), 0
            )
            self._current = None  # force a reload of the (possibly changed) finding
            table.move_cursor(row=index)
            self._select(index)
            self._set_status(
                f"{len(self._findings)} finding(s) — {self._db_path}{self._draft_suffix()}"
            )
        else:
            self._current = None
            self._set_status(f"No findings yet in {self._db_path}")

    def _select(self, index: int) -> None:
        if not (0 <= index < len(self._findings)):
            return
        finding = self._findings[index]
        # Only reload the editor when the selection actually moves. RowHighlighted arrives as a
        # queued message, so re-selecting the same finding would otherwise discard whatever the
        # operator had typed but not yet saved.
        changed = self._current is None or self._current.id != finding.id
        if changed:
            # Stash the OUTGOING finding's unsaved text before the editor is reloaded.
            self._stash_draft()
        self._current = finding
        self.query_one("#detail", Markdown).update(_summary_markdown(finding))
        self.query_one("#checklist", Markdown).update(_checklist_markdown(finding))
        if changed:
            draft = self._drafts.get(finding.id) if finding.id is not None else None
            self.query_one("#remediation", TextArea).text = (
                draft if draft is not None else finding.remediation
            )
            if draft is not None:
                self._set_status(
                    f"Restored unsaved draft for finding {finding.id} — 's' (or ctrl+s) to save"
                )
        self.query_one("#report", Markdown).update(
            ReportGenerator().render_markdown(finding, get_profile(finding.platform.value))
        )

    @on(DataTable.RowHighlighted, "#findings")
    def _on_row(self, event: DataTable.RowHighlighted) -> None:
        # RowHighlighted is queued, and `clear()` + `add_row()` during a reload post one for row 0.
        # That event can land AFTER an explicit selection and silently override it, so drop any
        # event whose row no longer matches where the cursor actually is.
        if event.cursor_row != self.query_one("#findings", DataTable).cursor_row:
            return
        self._select(event.cursor_row)

    # -- actions -----------------------------------------------------------------------

    def action_insert_suggestion(self) -> None:
        """Put the pack's draft remediation in the editor for the operator to review.

        It is inserted into the EDITOR, never written straight to the finding: remediation is
        authored prose the operator owns and the readiness checklist measures. Accepting it is an
        explicit act (edit, then save), which is the whole reason the pack only ever suggests.
        """
        if self._current is None:
            self._set_status("No finding selected")
            return
        suggestion = knowledge.suggest_remediation(self._current.category)
        if not suggestion.strip():
            self._set_status(f"No suggestion for {self._current.category.value}")
            return
        self.query_one("#remediation", TextArea).text = " ".join(suggestion.split())
        self._set_status("Suggested remediation inserted — review and edit, then 's' to save")

    def action_save(self) -> None:
        """Write the editor's remediation text to the current finding and clear its unsaved draft."""
        if self._current is None or self._store is None:
            self._set_status("No finding selected")
            return
        self._current.remediation = self.query_one("#remediation", TextArea).text.strip()
        self._store.update(self._current)
        if self._current.id is not None:
            self._drafts.pop(self._current.id, None)  # no longer unsaved
        self._select(self._findings.index(self._current))
        self._set_status(f"Saved finding {self._current.id}{self._draft_suffix()}")


def run(db_path: Path | None = None) -> None:
    """Launch the workbench app, optionally against a specific findings database (mainly tests)."""
    WorkbenchApp(db_path=db_path).run()
