"""Local persistence: probe runs (JSON files) and findings (SQLite).

Runs are one JSON file per run under the evidence dir — human-inspectable and easy to promote. Findings
live in SQLite so they can be listed, filtered, and updated as they move through draft -> submitted.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from promptstrike.models import Finding, ProbeResult

# Run ids become filenames under the evidence directory, so they are restricted to characters
# that cannot traverse or absolutise a path.
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class RunStore:
    """JSON-file store of :class:`ProbeResult` runs (``<run_id>.json`` under the evidence dir)."""

    def __init__(self, evidence_dir: str | Path) -> None:
        # Where each run's JSON file lives; created lazily on first save, not here.
        self.dir = Path(evidence_dir)

    def _path(self, run_id: str) -> Path:
        # The on-disk path for a given run id, whether or not it exists yet.
        # Validate before the join. ProbeResult.run_id has no model-level validator, and
        # `finding promote <run-id>` passes operator input straight through, so this is the only
        # thing standing between that input and an arbitrary filesystem path.
        if not _RUN_ID_RE.match(run_id):
            raise ValueError(f"invalid run id {run_id!r}: expected [A-Za-z0-9_-]")
        return self.dir / f"{run_id}.json"

    def save(self, result: ProbeResult) -> Path:
        """Persist ``result`` as ``<run_id>.json`` and return the path, creating the dir if needed."""
        # Create the evidence directory on first use rather than requiring it to pre-exist.
        self.dir.mkdir(parents=True, exist_ok=True)
        # Resolve the destination path from the run's own id.
        path = self._path(result.run_id)
        # Pretty-print the JSON so a saved run is human-inspectable, per the module docstring.
        path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        # Return the path so callers can report or open the file directly.
        return path

    def get(self, run_id: str) -> ProbeResult | None:
        """Load one run by id, or ``None`` if no file for that run exists."""
        path = self._path(run_id)
        # No file for this run id means no such run — not an error condition.
        if not path.exists():
            return None
        # Parse the stored JSON straight back into a ProbeResult model.
        return ProbeResult.model_validate_json(path.read_text(encoding="utf-8"))

    def list(self) -> list[ProbeResult]:
        """Every persisted run, filename-sorted. A missing evidence dir is empty, not an error."""
        # No directory yet means no runs have ever been saved.
        if not self.dir.exists():
            return []
        # Sorted glob gives a deterministic (filename == run_id) ordering.
        return [
            ProbeResult.model_validate_json(run_file.read_text(encoding="utf-8"))
            for run_file in sorted(self.dir.glob("*.json"))
        ]


# The findings table: a handful of indexed columns for filtering/listing, plus the full model kept
# as JSON in `data` so no migration is needed whenever the Finding schema grows a field.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT, platform TEXT, title TEXT, category TEXT,
    severity TEXT, status TEXT, run_id TEXT, created_at TEXT,
    data TEXT NOT NULL
)
"""


class FindingStore:
    """SQLite store of findings; the full model is kept as JSON in ``data`` with indexed columns."""

    def __init__(self, db_path: str | Path) -> None:
        # Accept either a str or Path uniformly from here on.
        self.db_path = Path(db_path)
        # Create the parent directory on first use so the db file can be created there.
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # Open (or create) the SQLite database file at this path.
        self._conn = sqlite3.connect(str(self.db_path))
        # Ensure the findings table exists; a no-op on every connection after the first.
        self._conn.execute(_SCHEMA)
        # Commit the schema creation so it persists even if nothing else is ever written.
        self._conn.commit()

    def close(self) -> None:
        """Close the underlying sqlite3 connection."""
        # Release the SQLite file handle.
        self._conn.close()

    def __enter__(self) -> FindingStore:
        # Support `with FindingStore(...) as store:` so close() always runs.
        return self

    def __exit__(self, *exc) -> None:
        # Always close on context-manager exit, regardless of whether an exception occurred.
        self.close()

    def _cols(self, finding: Finding) -> tuple:
        # Column order here must exactly match the INSERT/UPDATE statements below.
        return (
            finding.program,
            finding.platform.value,
            finding.title,
            finding.category.value,
            finding.severity.value,
            finding.status.value,
            finding.run_id,
            finding.created_at.isoformat(),
            finding.model_dump_json(),
        )

    def add(self, finding: Finding) -> int:
        """Insert ``finding``, assign it the database's autoincrement id, and return that id.

        The id is unknown until after the INSERT, so the embedded ``data`` JSON is written once
        without it and then re-persisted with the assigned id folded in — otherwise a finding
        reloaded from ``data`` would come back with ``id=None``.
        """
        # First pass: insert with the data JSON still carrying finding.id unset (None).
        cursor = self._conn.execute(
            "INSERT INTO findings "
            "(program,platform,title,category,severity,status,run_id,created_at,data) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            self._cols(finding),
        )
        # SQLite hands back the row's new autoincrement id only after the INSERT completes.
        finding.id = int(cursor.lastrowid)
        # Re-persist so the embedded JSON carries the assigned id.
        self._conn.execute(
            "UPDATE findings SET data=? WHERE id=?", (finding.model_dump_json(), finding.id)
        )
        # Commit both statements as one unit of work.
        self._conn.commit()
        # Hand back the assigned id for the caller to hold onto.
        return finding.id

    def get(self, finding_id: int) -> Finding | None:
        """Load one finding by id, or ``None`` if no such finding exists."""
        # Only the embedded JSON is needed to fully reconstruct the Finding.
        row = self._conn.execute(
            "SELECT data FROM findings WHERE id=?", (finding_id,)
        ).fetchone()
        # No row means no finding with this id — not an error condition.
        return Finding.model_validate_json(row[0]) if row else None

    def list(self) -> list[Finding]:
        """Every stored finding, id-ascending."""
        # Fetch every finding's embedded JSON, oldest (lowest id) first.
        rows = self._conn.execute("SELECT data FROM findings ORDER BY id").fetchall()
        # Reconstruct each row's JSON back into a Finding model.
        return [Finding.model_validate_json(row[0]) for row in rows]

    def update(self, finding: Finding) -> None:
        """Overwrite a stored finding's row (indexed columns + embedded JSON) by its id.

        Raises ``ValueError`` if ``finding.id`` is ``None`` — there is no row to update against,
        and silently no-op-ing would look like a successful save that never happened.
        """
        # An id-less finding was never inserted, so there is no row to target.
        if finding.id is None:
            raise ValueError("cannot update a finding with no id")
        # Overwrite every indexed column and the embedded JSON in one statement, keyed by id.
        self._conn.execute(
            "UPDATE findings SET "
            "program=?,platform=?,title=?,category=?,severity=?,status=?,run_id=?,created_at=?,data=? "
            "WHERE id=?",
            (*self._cols(finding), finding.id),
        )
        # Persist the overwrite immediately.
        self._conn.commit()
