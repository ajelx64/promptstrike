"""Triage & report workbench (increment 3).

Driven through Textual's `run_test()` harness so these exercise the real app: real widgets, real
store, real report render. Structural assertions ("the class defines a TabPane") would pass while
the app was broken, so everything here goes through the running application.

The workbench must contain no path that sends traffic to a target — one test asserts that directly,
because it is a division hard gate rather than a style preference.
"""

from __future__ import annotations

import pytest

from promptstrike.models import Finding, Platform
from promptstrike.report.profiles import get_profile
from promptstrike.storage import FindingStore
from promptstrike.taxonomy import OwaspLLM
from promptstrike.tui.app import WorkbenchApp

pytestmark = pytest.mark.asyncio


def _seed(db_path, **kw) -> int:
    base = {
        "program": "acme",
        "platform": Platform.openai_h1,
        "title": "Indirect prompt injection via retrieved document",
        "category": OwaspLLM.LLM01,
        "steps_to_reproduce": ["Send the crafted document", "Observe the injected instruction"],
        "impact": "Attacker-controlled instructions execute with the assistant's privileges.",
    }
    with FindingStore(db_path) as store:
        return store.add(Finding(**{**base, **kw}))


async def test_app_starts_and_lists_findings(tmp_path):
    db = tmp_path / "findings.db"
    _seed(db)
    _seed(db, title="System prompt disclosed via error path", category=OwaspLLM.LLM07)

    async with WorkbenchApp(db_path=db).run_test() as pilot:
        table = pilot.app.query_one("#findings")
        assert table.row_count == 2


async def test_empty_database_does_not_crash(tmp_path):
    async with WorkbenchApp(db_path=tmp_path / "empty.db").run_test() as pilot:
        assert pilot.app.query_one("#findings").row_count == 0
        assert "No findings" in pilot.app.status_text


async def test_detail_pane_shows_framework_references(tmp_path):
    db = tmp_path / "findings.db"
    _seed(db)
    async with WorkbenchApp(db_path=db).run_test() as pilot:
        source = pilot.app.query_one("#detail").source
        assert "AML.T0051" in source
        assert "LLM Prompt Injection" in source


async def test_report_tab_renders_the_finding(tmp_path):
    db = tmp_path / "findings.db"
    _seed(db)
    async with WorkbenchApp(db_path=db).run_test() as pilot:
        source = pilot.app.query_one("#report").source
        assert "Related framework references" in source
        assert "Attribution" in source


async def test_insert_suggestion_populates_editor_but_not_the_finding(tmp_path):
    """The whole point of suggest-not-fill: the operator must accept it explicitly."""
    db = tmp_path / "findings.db"
    fid = _seed(db)
    async with WorkbenchApp(db_path=db).run_test() as pilot:
        await pilot.press("i")
        assert pilot.app.query_one("#remediation").text.strip()
        # Not just "unpersisted" — the suggestion must not reach the in-memory finding either,
        # or a later save of an untouched finding would silently adopt it as the operator's own.
        assert pilot.app._current.remediation == ""

    with FindingStore(db) as store:
        assert store.get(fid).remediation == ""


async def test_save_persists_the_edited_remediation(tmp_path):
    db = tmp_path / "findings.db"
    fid = _seed(db)
    async with WorkbenchApp(db_path=db).run_test() as pilot:
        await pilot.pause()  # let queued RowHighlighted settle before editing
        pilot.app.query_one("#remediation").text = "Pin the retrieval source and strip instructions."
        await pilot.press("s")

    with FindingStore(db) as store:
        assert store.get(fid).remediation == "Pin the retrieval source and strip instructions."


async def test_saving_a_suggestion_satisfies_the_readiness_checklist(tmp_path):
    """End-to-end of the workflow the workbench exists for."""
    db = tmp_path / "findings.db"
    fid = _seed(db)
    with FindingStore(db) as store:
        assert "Remediation suggested" in get_profile("openai_h1").missing(store.get(fid))

    async with WorkbenchApp(db_path=db).run_test() as pilot:
        await pilot.press("i")
        await pilot.press("s")

    with FindingStore(db) as store:
        assert "Remediation suggested" not in get_profile("openai_h1").missing(store.get(fid))


async def test_refresh_picks_up_externally_added_findings(tmp_path):
    db = tmp_path / "findings.db"
    _seed(db)
    async with WorkbenchApp(db_path=db).run_test() as pilot:
        assert pilot.app.query_one("#findings").row_count == 1
        _seed(db, title="Second finding", category=OwaspLLM.LLM02)
        await pilot.press("r")
        assert pilot.app.query_one("#findings").row_count == 2


async def test_checklist_pane_renders_readiness(tmp_path):
    """The readiness pane is a headline feature; nothing asserted it rendered at all."""
    db = tmp_path / "findings.db"
    _seed(db)
    async with WorkbenchApp(db_path=db).run_test() as pilot:
        source = pilot.app.query_one("#checklist").source
        assert "OpenAI (HackerOne)" in source
        assert "ready" in source
        assert "Remediation suggested" in source  # outstanding for a freshly seeded finding


async def test_unsaved_edit_survives_navigating_to_another_finding(tmp_path):
    """The workbench authors prose; moving the cursor must not destroy it."""
    db = tmp_path / "findings.db"
    _seed(db)
    _seed(db, title="Second finding", category=OwaspLLM.LLM02)

    async with WorkbenchApp(db_path=db).run_test() as pilot:
        await pilot.pause()
        pilot.app.query_one("#remediation").text = "half-written prose"
        table = pilot.app.query_one("#findings")
        table.move_cursor(row=1)
        await pilot.pause()
        assert pilot.app.query_one("#remediation").text == ""  # the other finding's editor
        table.move_cursor(row=0)
        await pilot.pause()
        assert pilot.app.query_one("#remediation").text == "half-written prose"


async def test_unsaved_edit_survives_a_reload(tmp_path):
    db = tmp_path / "findings.db"
    _seed(db)
    async with WorkbenchApp(db_path=db).run_test() as pilot:
        await pilot.pause()
        pilot.app.query_one("#remediation").text = "half-written prose"
        await pilot.press("r")
        assert pilot.app.query_one("#remediation").text == "half-written prose"
        assert "unsaved draft" in pilot.app.status_text


async def test_reload_keeps_the_operators_position(tmp_path):
    db = tmp_path / "findings.db"
    _seed(db)
    second = _seed(db, title="Second finding", category=OwaspLLM.LLM02)
    async with WorkbenchApp(db_path=db).run_test() as pilot:
        pilot.app.query_one("#findings").move_cursor(row=1)
        await pilot.pause()
        assert pilot.app._current.id == second
        await pilot.press("r")
        assert pilot.app._current.id == second


async def test_ctrl_s_saves_while_the_editor_has_focus(tmp_path):
    """Plain 's' is swallowed by TextArea — correctly, since prose contains the letter s."""
    db = tmp_path / "findings.db"
    fid = _seed(db)
    async with WorkbenchApp(db_path=db).run_test() as pilot:
        await pilot.pause()
        editor = pilot.app.query_one("#remediation")
        editor.focus()
        await pilot.pause()
        editor.text = "Strip instructions from retrieved content."
        await pilot.press("ctrl+s")

    with FindingStore(db) as store:
        assert store.get(fid).remediation == "Strip instructions from retrieved content."


# Modules that can put bytes on the wire toward a target, or that reach the probe pipeline.
# `promptstrike.llm` is listed as a PACKAGE, not by symbol: the scope check lives in
# TargetClient.send, so importing the lower-level `openai_chat_transport` directly would send
# UNSCOPED traffic. Naming symbols cannot express that; naming the package can.
_FORBIDDEN_PREFIXES = (
    "httpx",
    "requests",
    "urllib.request",
    "promptstrike.llm",
    "promptstrike.probes",
    "promptstrike.scope",
)


def _is_forbidden(module_name: str) -> bool:
    return any(
        module_name == p or module_name.startswith(p + ".") for p in _FORBIDDEN_PREFIXES
    )


async def test_workbench_package_does_not_import_traffic_capable_modules():
    """Division hard gate, checked transitively: importing the whole TUI package must not pull in
    anything able to reach a target. A subprocess is used so the assertion sees a pristine
    ``sys.modules`` rather than one already populated by the rest of the test session."""
    import subprocess
    import sys

    code = (
        "import importlib, pkgutil, sys, json\n"
        "import promptstrike.tui as pkg\n"
        "for m in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + '.'):\n"
        "    importlib.import_module(m.name)\n"
        "print(json.dumps(sorted(sys.modules)))\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr

    import json

    loaded = json.loads(proc.stdout)
    offenders = [name for name in loaded if _is_forbidden(name)]
    assert not offenders, f"workbench transitively imports traffic-capable modules: {offenders}"


async def test_no_workbench_module_declares_a_traffic_capable_import():
    """Second layer, covering what the runtime check cannot see.

    A deferred import inside a function body never executes at import time, so it would not appear
    in ``sys.modules`` above. This walks the AST of EVERY module in the package — including files
    that do not exist yet, such as the planned Run tab — so the gate cannot be silently disabled by
    adding a new file.
    """
    import ast
    from pathlib import Path

    package = Path("src/promptstrike/tui")
    modules = sorted(package.rglob("*.py"))
    assert modules, "expected to find TUI modules to check"

    offenders: list[str] = []
    for path in modules:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module] if node.module else []
            else:
                continue
            offenders += [f"{path.name}:{n}" for n in names if n and _is_forbidden(n)]

    assert not offenders, f"workbench declares traffic-capable imports: {offenders}"
