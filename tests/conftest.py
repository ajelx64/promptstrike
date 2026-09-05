"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    """An isolated, writable data directory for storage-backed tests."""
    d = tmp_path / "data"
    d.mkdir()
    return d
