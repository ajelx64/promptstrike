"""Packaging guards.

These assert facts about distribution rather than behavior. They exist because every install in
this project's own docs is `pip install -e .`, and `pytest.ini` sets `pythonpath = src`, so the
source tree is always what gets read locally - which means a file missing from the wheel is
invisible until a stranger installs it.
"""

from __future__ import annotations

import pathlib
import tomllib

import promptstrike


def _package_root() -> pathlib.Path:
    """Directory of the installed/importable promptstrike package."""
    # __file__ points at package/__init__.py, so the parent is the package root.
    return pathlib.Path(promptstrike.__file__).parent


def _declared_package_data() -> list[str]:
    """The package-data globs declared in pyproject.toml."""
    # pyproject sits two levels above the package root in the source layout (src/promptstrike).
    pyproject = _package_root().parents[1] / "pyproject.toml"
    # Parse it with the stdlib TOML reader - no extra dependency for a packaging guard.
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    # Reach the promptstrike entry under [tool.setuptools.package-data].
    return data["tool"]["setuptools"]["package-data"]["promptstrike"]


def test_every_non_python_data_file_is_covered_by_a_package_data_glob() -> None:
    """Any data file the package needs at runtime must be matched by a declared glob.

    The failure this catches is silent: setuptools does not warn about a data file that no glob
    matches, so the wheel is simply missing it and the tool breaks only for people who installed
    it properly.
    """
    # Where the importable package lives.
    root = _package_root()
    # The globs pyproject promises to ship.
    globs = _declared_package_data()
    # Directories whose contents are runtime data rather than code or build noise.
    data_dirs = ["probes/pack", "report/templates", "knowledge/data"]
    # Collect every file under those directories that is not Python source.
    required: list[pathlib.Path] = []
    for relative_dir in data_dirs:
        # Skip a directory that does not exist in this layout rather than failing on it.
        directory = root / relative_dir
        if not directory.is_dir():
            continue
        # Walk it recursively.
        for candidate in directory.rglob("*"):
            # Only files matter; directories are not shipped on their own.
            if not candidate.is_file():
                continue
            # .py files ship as package modules, and caches are never shipped.
            if candidate.suffix == ".py" or "__pycache__" in candidate.parts:
                continue
            required.append(candidate)
    # Sanity: the fixture set must be non-empty, or this test would pass vacuously.
    assert required, "no data files found - this guard would pass for the wrong reason"
    # Every one of them must be matched by at least one declared glob.
    uncovered = []
    for data_file in required:
        # Express the path the way pyproject globs do: relative to the package root, forward slashes.
        relative = data_file.relative_to(root).as_posix()
        # PurePath.match handles the glob syntax setuptools uses here.
        if not any(pathlib.PurePosixPath(relative).match(pattern) for pattern in globs):
            uncovered.append(relative)
    # Name the offenders, since "packaging is wrong" alone is not actionable.
    assert not uncovered, f"data files not covered by any package-data glob: {uncovered}"


def test_the_markdown_report_template_ships() -> None:
    """Named explicitly because Markdown is the DEFAULT report format.

    Regression guard for a real defect: the glob once listed only *.html, so `render_markdown`
    raised TemplateNotFound in any installed wheel while every local editable install worked.
    """
    # The template the default --format path renders.
    template = _package_root() / "report" / "templates" / "report" / "finding.md.j2"
    # It must exist in the package tree...
    assert template.is_file()
    # ...and be covered by a declared glob, which is the part that was broken.
    relative = template.relative_to(_package_root()).as_posix()
    assert any(pathlib.PurePosixPath(relative).match(p) for p in _declared_package_data())
