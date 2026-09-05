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

# Column order for the Findings table; used both to add the columns and to know it matches
# the row values built in action_refresh.
_COLUMNS = ("id", "severity", "category", "status", "title")


def _summary_markdown(finding: Finding) -> str:
    """The detail pane: what the finding is, and what the pack says it relates to."""
    # The loaded knowledge pack, used to resolve framework reference ids to titles below.
    pack = knowledge.pack()
    # Header block: the fixed fields every finding has, rendered as Markdown bullet points.
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
        # No cross-references at all: say so explicitly rather than leaving a blank section.
        lines.append("_none_")
    # One section per framework this finding cites (ATLAS, OWASP-LLM, etc.), in a stable order.
    for fw_key in sorted(finding.framework_refs):
        # This finding's referenced entry ids within that one framework.
        ids = finding.refs(fw_key)
        if not ids:
            continue
        try:
            # Prefer the framework's human-readable display name for the section heading.
            name = pack.framework(fw_key).source.name
        except KeyError:
            # Framework key not found in the pack (e.g. pack changed underneath); fall back to
            # the raw key rather than raising out of a detail-view render.
            name = fw_key
        lines += ["", f"**{name}**", ""]
        for entry_id in ids:
            # Resolve the id to its full entry so the title (and verification state) can show.
            entry = pack.entry(fw_key, entry_id)
            title = f" — {entry.title}" if entry else ""
            flag = "  _(unverified)_" if entry is not None and not entry.verified else ""
            lines.append(f"- `{entry_id}`{title}{flag}")
    # Join the whole Markdown document into the single string Textual's Markdown widget wants.
    return "\n".join(lines)


# The checklist pane: this finding's readiness against its platform's submission profile.
def _checklist_markdown(finding: Finding) -> str:
    # Resolve the platform-specific report profile for this finding.
    profile = get_profile(finding.platform.value)
    # Every checklist item that profile defines, each carrying its own pass/fail state.
    items = profile.checklist(finding)
    lines = [f"## {profile.display_name} readiness", ""]
    # One Markdown checkbox line per item, checked or not per its ok state.
    lines += [f"- [{'x' if i.ok else ' '}] {i.label}" for i in items]
    # Labels of the items still outstanding, for both the tally and the summary line below.
    missing = [i.label for i in items if not i.ok]
    lines += ["", f"**{len(items) - len(missing)}/{len(items)} ready**"]
    if missing:
        lines.append(f"Outstanding: {', '.join(missing)}")
    # Join the whole Markdown document into the single string Textual's Markdown widget wants.
    return "\n".join(lines)


class WorkbenchApp(App):
    """Triage & report workbench."""

    # Textual CSS: findings table fills the top, detail/checklist share a row, the remediation
    # editor takes the rest, and the status bar is docked to the bottom.
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
        # Let Textual's App base class do its own setup first.
        super().__init__()
        # Load configuration so the default findings database path can be resolved below.
        settings = get_settings()
        # Make sure the data directories exist before the store tries to open a db file in them.
        settings.ensure_dirs()
        # An explicit db_path (mainly used by tests) wins; otherwise use the configured default.
        self._db_path = Path(db_path) if db_path else Path(settings.db_path)
        # The findings store connection; opened lazily in on_mount once the app is running.
        self._store: FindingStore | None = None
        # The findings currently loaded into the table, in table row order.
        self._findings: list[Finding] = []
        # The finding shown in the Detail/Report tabs right now, if any.
        self._current: Finding | None = None
        #: Unsaved remediation text, keyed by finding id. The workbench exists to author prose, so
        #: navigating away from an edit must never destroy it — drafts are stashed and restored
        #: rather than discarded, and survive a reload.
        self._drafts: dict[int, str] = {}
        # Backing value for the status bar; mirrored so tests can assert on it directly.
        self.status_text = ""

    # -- lifecycle ---------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        """Lay out the Findings/Detail/Report tabs plus the status bar and footer."""
        # Top title bar; no clock, since this is a local desktop tool, not a dashboard.
        yield Header(show_clock=False)
        # The three tabs the operator switches between; Findings is shown first.
        with TabbedContent(initial="tab-findings"):
            with TabPane("Findings", id="tab-findings"):
                # The table of every finding; cursor_type="row" makes arrow keys move a whole
                # row rather than a single cell.
                yield DataTable(id="findings", cursor_type="row")
            with TabPane("Detail", id="tab-detail"):
                # Summary and checklist panes sit side by side above the remediation editor.
                with Horizontal():
                    with VerticalScroll():
                        # The finding's summary (program, category, severity, framework refs).
                        yield Markdown(id="detail")
                    with VerticalScroll():
                        # The platform-submission checklist for this finding.
                        yield Markdown(id="checklist")
                # Free-text editor where the operator authors (or edits an AI suggestion for)
                # this finding's remediation.
                yield TextArea(id="remediation", language=None)
            with TabPane("Report", id="tab-report"):
                with VerticalScroll():
                    # A live preview of the report that would be generated for this finding.
                    yield Markdown(id="report")
            # A "Run" tab slots in here later; it is the only surface that would send traffic
            # to a target, so it stays a separate, separately-reviewed increment.
        # Single-line status bar, updated by _set_status throughout the app's lifetime.
        yield Static("", id="status")
        # Key-binding hint bar Textual renders automatically from BINDINGS.
        yield Footer()

    def on_mount(self) -> None:
        """Open the findings store and load the table once Textual's event loop is running."""
        # Find the Findings DataTable widget composed above.
        table = self.query_one("#findings", DataTable)
        # Set up its columns to match _COLUMNS before any rows are added.
        table.add_columns(*_COLUMNS)
        # Open the sqlite3-backed store now, on the event loop, per the threading note above.
        self._store = FindingStore(self._db_path)
        # Populate the table (and select the first finding) for the first time.
        self.action_refresh()

    def on_unmount(self) -> None:
        """Close the store's sqlite3 connection so the app never leaves it dangling."""
        if self._store is not None:
            # Close the connection explicitly rather than relying on garbage collection.
            self._store.close()
            # Clear the reference so nothing can accidentally use a closed store afterward.
            self._store = None

    # -- data --------------------------------------------------------------------------

    def _set_status(self, message: str) -> None:
        #: Mirrored onto the app so callers (and tests) read app state, not widget internals.
        self.status_text = message
        # Push the same text into the actual status-bar widget so the operator sees it too.
        self.query_one("#status", Static).update(message)

    def _stash_draft(self) -> None:
        """Preserve the editor's text for the current finding if it differs from what is saved."""
        if self._current is None or self._current.id is None:
            # Nothing selected, or a finding without an id yet: there is nothing to stash.
            return
        # The remediation editor whose text might have unsaved edits.
        editor = self.query_one("#remediation", TextArea)
        if editor.text.strip() != (self._current.remediation or "").strip():
            # Text differs from the last-saved remediation: keep it as a pending draft.
            self._drafts[self._current.id] = editor.text
        else:
            # Text matches what is already saved: no draft needed, so drop any stale one.
            self._drafts.pop(self._current.id, None)

    def _draft_suffix(self) -> str:
        # A short " [N unsaved draft(s)]" tag to append to status messages, or nothing at all.
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
            # No store open yet (shouldn't happen post on_mount, but keeps this method safe
            # to call defensively).
            return
        # Stash any unsaved edit for the CURRENT finding before it might be swapped out below.
        self._stash_draft()
        # Remember which finding was selected so the cursor can be restored to it after reload.
        keep_id = self._current.id if self._current else None
        # Re-fetch every finding from the store; this is the "reload" itself.
        self._findings = self._store.list()
        table = self.query_one("#findings", DataTable)
        # Drop all existing rows before repopulating from the fresh list.
        table.clear()
        for finding in self._findings:
            # One row per finding, in the same column order as _COLUMNS.
            table.add_row(
                str(finding.id),
                finding.severity.value,
                finding.category.value,
                finding.status.value,
                finding.title,
            )
        if self._findings:
            # Keep the operator where they were; reloading should not move the cursor.
            index = next(
                (i for i, finding in enumerate(self._findings) if finding.id == keep_id), 0
            )
            self._current = None  # force a reload of the (possibly changed) finding
            # Move the visible cursor to the same finding's new row position.
            table.move_cursor(row=index)
            # Reload the Detail/Report panes for whatever finding now sits at that row.
            self._select(index)
            self._set_status(
                f"{len(self._findings)} finding(s) — {self._db_path}{self._draft_suffix()}"
            )
        else:
            # Store is empty: nothing to select or show.
            self._current = None
            self._set_status(f"No findings yet in {self._db_path}")

    def _select(self, index: int) -> None:
        if not (0 <= index < len(self._findings)):
            # Out-of-range row (e.g. an empty table): nothing to select.
            return
        finding = self._findings[index]
        # Only reload the editor when the selection actually moves. RowHighlighted arrives as a
        # queued message, so re-selecting the same finding would otherwise discard whatever the
        # operator had typed but not yet saved.
        changed = self._current is None or self._current.id != finding.id
        if changed:
            # Stash the OUTGOING finding's unsaved text before the editor is reloaded.
            self._stash_draft()
        # Track this as the finding now shown in the Detail/Report panes.
        self._current = finding
        # Refresh the summary pane for the newly selected finding.
        self.query_one("#detail", Markdown).update(_summary_markdown(finding))
        # Refresh the platform-checklist pane for the newly selected finding.
        self.query_one("#checklist", Markdown).update(_checklist_markdown(finding))
        if changed:
            # Prefer any stashed unsaved draft over the finding's last-saved remediation.
            draft = self._drafts.get(finding.id) if finding.id is not None else None
            self.query_one("#remediation", TextArea).text = (
                draft if draft is not None else finding.remediation
            )
            if draft is not None:
                # Tell the operator their unsaved text came back, not the saved value.
                self._set_status(
                    f"Restored unsaved draft for finding {finding.id} — 's' (or ctrl+s) to save"
                )
        # Re-render the Report tab's live preview for the newly selected finding.
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
        # The cursor genuinely moved to this row: load its finding into the panes.
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
        # Look up the pack's draft remediation text for this finding's OWASP-LLM category.
        suggestion = knowledge.suggest_remediation(self._current.category)
        if not suggestion.strip():
            # The pack has no draft remediation for this category; say so rather than clearing
            # whatever the operator may already have typed.
            self._set_status(f"No suggestion for {self._current.category.value}")
            return
        # Collapse embedded whitespace/newlines before dropping the suggestion into the editor.
        self.query_one("#remediation", TextArea).text = " ".join(suggestion.split())
        self._set_status("Suggested remediation inserted — review and edit, then 's' to save")

    def action_save(self) -> None:
        """Write the editor's remediation text to the current finding and clear its unsaved draft."""
        if self._current is None or self._store is None:
            self._set_status("No finding selected")
            return
        # Pull the operator's (possibly edited) remediation text out of the editor.
        self._current.remediation = self.query_one("#remediation", TextArea).text.strip()
        # Persist it to the findings database — the one durable write this action performs.
        self._store.update(self._current)
        if self._current.id is not None:
            self._drafts.pop(self._current.id, None)  # no longer unsaved
        # Re-render the panes so the Report preview reflects the just-saved remediation.
        self._select(self._findings.index(self._current))
        self._set_status(f"Saved finding {self._current.id}{self._draft_suffix()}")


def run(db_path: Path | None = None) -> None:
    """Launch the workbench app, optionally against a specific findings database (mainly tests)."""
    # Construct and hand control to Textual's own event loop until the operator quits.
    WorkbenchApp(db_path=db_path).run()
