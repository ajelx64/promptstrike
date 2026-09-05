"""Local persistence: probe runs (JSON files) and findings (SQLite).

Runs are one JSON file per run under the evidence dir — human-inspectable and easy to promote. Findings
live in SQLite so they can be listed, filtered, and updated as they move through draft -> submitted.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from promptstrike.models import Finding, ProbeResult


class RunStore:
    """JSON-file store of :class:`ProbeResult` runs (``<run_id>.json`` under the evidence dir)."""

    def __init__(self, evidence_dir: str | Path) -> None:
        self.dir = Path(evidence_dir)

    def _path(self, run_id: str) -> Path:
        return self.dir / f"{run_id}.json"

    def save(self, result: ProbeResult) -> Path:
        """Persist ``result`` as ``<run_id>.json`` and return the path, creating the dir if needed."""
        self.dir.mkdir(parents=True, exist_ok=True)
        path = self._path(result.run_id)
        path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        return path

    def get(self, run_id: str) -> ProbeResult | None:
        """Load one run by id, or ``None`` if no file for that run exists."""
        path = self._path(run_id)
        if not path.exists():
            return None
        return ProbeResult.model_validate_json(path.read_text(encoding="utf-8"))

    def list(self) -> list[ProbeResult]:
        """Every persisted run, filename-sorted. A missing evidence dir is empty, not an error."""
        if not self.dir.exists():
            return []
        return [
            ProbeResult.model_validate_json(p.read_text(encoding="utf-8"))
            for p in sorted(self.dir.glob("*.json"))
        ]


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
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        """Close the underlying sqlite3 connection."""
        self._conn.close()

    def __enter__(self) -> FindingStore:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _cols(self, f: Finding) -> tuple:
        return (
            f.program,
            f.platform.value,
            f.title,
            f.category.value,
            f.severity.value,
            f.status.value,
            f.run_id,
            f.created_at.isoformat(),
            f.model_dump_json(),
        )

    def add(self, finding: Finding) -> int:
        """Insert ``finding``, assign it the database's autoincrement id, and return that id.

        The id is unknown until after the INSERT, so the embedded ``data`` JSON is written once
        without it and then re-persisted with the assigned id folded in — otherwise a finding
        reloaded from ``data`` would come back with ``id=None``.
        """
        cur = self._conn.execute(
            "INSERT INTO findings "
            "(program,platform,title,category,severity,status,run_id,created_at,data) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            self._cols(finding),
        )
        finding.id = int(cur.lastrowid)
        # Re-persist so the embedded JSON carries the assigned id.
        self._conn.execute(
            "UPDATE findings SET data=? WHERE id=?", (finding.model_dump_json(), finding.id)
        )
        self._conn.commit()
        return finding.id

    def get(self, finding_id: int) -> Finding | None:
        """Load one finding by id, or ``None`` if no such finding exists."""
        row = self._conn.execute(
            "SELECT data FROM findings WHERE id=?", (finding_id,)
        ).fetchone()
        return Finding.model_validate_json(row[0]) if row else None

    def list(self) -> list[Finding]:
        """Every stored finding, id-ascending."""
        rows = self._conn.execute("SELECT data FROM findings ORDER BY id").fetchall()
        return [Finding.model_validate_json(r[0]) for r in rows]

    def update(self, finding: Finding) -> None:
        """Overwrite a stored finding's row (indexed columns + embedded JSON) by its id.

        Raises ``ValueError`` if ``finding.id`` is ``None`` — there is no row to update against,
        and silently no-op-ing would look like a successful save that never happened.
        """
        if finding.id is None:
            raise ValueError("cannot update a finding with no id")
        self._conn.execute(
            "UPDATE findings SET "
            "program=?,platform=?,title=?,category=?,severity=?,status=?,run_id=?,created_at=?,data=? "
            "WHERE id=?",
            (*self._cols(finding), finding.id),
        )
        self._conn.commit()
